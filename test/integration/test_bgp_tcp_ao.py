"""
BNG Blaster BGP TCP-AO (RFC 5925) against GoBGP (Linux kernel TCP-AO)

The KeyIDs are asymmetric to verify the SendID/RecvID mapping: the
BNG Blaster sends KeyID 1 and expects RNextKeyID/RecvID 2 from GoBGP.

TCP-AO with TCP options excluded from the MAC (e.g. Junos default) is
tested between two BNG Blaster BGP sessions, where the MAC of a SYN is
verified against a reference implementation of RFC 5925 and RFC 5926.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import hashlib
import hmac
import struct

import pytest

from bgp_common import BgpSetup
from helpers import BngBlaster, wait_until

KEY = "BNGBlasterTCPAOKey0123456789abcd"
ALGORITHMS = ["hmac-sha-1-96", "aes-128-cmac-96", "hmac-sha-256-128"]



@pytest.fixture
def bgp(topology, processes, tmp_path, gobgp_bin, tcp_ao_kernel):
    return BgpSetup(topology, processes, tmp_path)


def gobgp_ao(algorithm, key=KEY, send_id=2, receive_id=1):
    return {"algorithm": algorithm, "key": key, "send_id": send_id, "receive_id": receive_id}


def bbl_ao(algorithm, key=KEY, key_id=1, rnext_key_id=2):
    return {
        "tcp-ao-algorithm": algorithm,
        "tcp-ao-key": key,
        "tcp-ao-key-id": key_id,
        "tcp-ao-rnext-key-id": rnext_key_id,
    }


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_tcp_ao(bgp, algorithm):
    bgp.start(gobgp={"ao": gobgp_ao(algorithm)}, bbl={"bgp": bbl_ao(algorithm)})
    bgp.wait_established()
    assert bgp.bbl_session()["tcp-auth"] == algorithm
    bgp.teardown()


@pytest.mark.parametrize("gobgp,bbl", [
    ({"ao": gobgp_ao("hmac-sha-1-96", key="WrongKey0123456789ab")}, {"bgp": bbl_ao("hmac-sha-1-96")}),
    ({"ao": gobgp_ao("hmac-sha-1-96", receive_id=3)}, {"bgp": bbl_ao("hmac-sha-1-96")}),
    ({"ao": gobgp_ao("hmac-sha-1-96", send_id=3)}, {"bgp": bbl_ao("hmac-sha-1-96")}),
    ({"ao": gobgp_ao("aes-128-cmac-96")}, {"bgp": bbl_ao("hmac-sha-1-96")}),
    ({"ao": gobgp_ao("hmac-sha-1-96")}, {}),
    ({}, {"bgp": bbl_ao("hmac-sha-1-96")}),
], ids=["wrong-key", "wrong-recv-id", "wrong-send-id", "wrong-algorithm", "gobgp-only", "bbl-only"])
def test_tcp_ao_mismatch(bgp, gobgp, bbl):
    bgp.start(gobgp=gobgp, bbl=bbl)
    bgp.assert_not_established()
    bgp.teardown()


def pcap_frames(path):
    """Frames of a pcapng file."""
    data = open(path, "rb").read()
    off = 0
    while off + 12 <= len(data):
        block_type, block_len = struct.unpack_from("<II", data, off)
        if block_len < 12:
            break
        if block_type == 6:  # enhanced packet block
            caplen, = struct.unpack_from("<I", data, off + 20)
            yield data[off + 28:off + 28 + caplen]
        off += block_len


def tcp_ao_mac_sha1(key, frame, exclude_options):
    """HMAC-SHA-1-96 MAC of an IPv4 SYN with TCP-AO (RFC 5925, RFC 5926)."""
    ip = frame[14:]
    ihl = (ip[0] & 0xf) * 4
    src, dst = ip[12:16], ip[16:20]
    tcp = bytearray(ip[ihl:struct.unpack("!H", ip[2:4])[0]])
    sport, dport, isn = struct.unpack_from("!HHI", tcp, 0)
    hdr_len = (tcp[12] >> 4) * 4
    o, ao = 20, None
    while o < hdr_len and tcp[o] != 0:
        if tcp[o] == 1:
            o += 1
            continue
        if tcp[o] == 29:
            ao = (o, tcp[o + 1])
        o += tcp[o + 1]
    off, length = ao
    received = bytes(tcp[off + 4:off + length])
    context = src + dst + struct.pack("!HHII", sport, dport, isn, 0)
    traffic_key = hmac.new(key, b"\x01TCP-AO" + context + struct.pack("!H", 160), hashlib.sha1).digest()
    tcp[16:18] = b"\x00\x00"
    tcp[off + 4:off + length] = bytes(length - 4)
    header = bytes(tcp[:20]) + bytes(tcp[off:off + length]) if exclude_options else bytes(tcp[:hdr_len])
    message = struct.pack("!I", 0) + src + dst + struct.pack("!BBH", 0, 6, len(tcp)) + header + bytes(tcp[hdr_len:])
    return received, hmac.new(traffic_key, message, hashlib.sha1).digest()[:12]


def tcp_ao_sessions(local_veth, exclude_a, exclude_b):
    def session(local, peer, exclude):
        config = {"local-ipv4-address": local, "peer-ipv4-address": peer, "local-as": 65000,
                  "peer-as": 65000, "id": local}
        config.update(bbl_ao("hmac-sha-1-96", key_id=1, rnext_key_id=1))
        if exclude:
            config["tcp-ao-exclude-options"] = True
        return config
    return {
        "interfaces": {"network": [
            {"interface": local_veth.if1, "address": "10.0.0.1/24", "gateway": "10.0.0.2"},
            {"interface": local_veth.if2, "address": "10.0.0.2/24", "gateway": "10.0.0.1"}]},
        "bgp": [session("10.0.0.1", "10.0.0.2", exclude_a), session("10.0.0.2", "10.0.0.1", exclude_b)]
    }


def test_tcp_ao_exclude_options(local_veth, processes, tmp_path):
    """TCP options other than TCP-AO are excluded from the MAC."""
    instance = BngBlaster(local_veth.ns, tmp_path).start(tcp_ao_sessions(local_veth, True, True),
                                                         logging=("info", "bgp", "tcp"))
    processes.append(instance)
    wait_until(lambda: all(s["state"] == "established" for s in instance.ctrl("bgp-sessions")["bgp-sessions"]),
               30, message="BGP sessions established")
    instance.terminate()
    syns = [f for f in pcap_frames(instance.path("pcap"))
            if f[12:14] == b"\x08\x00" and f[23] == 6 and f[14 + (f[14] & 0xf) * 4 + 13] == 0x02]
    assert syns, "no SYN captured"
    received, excluded = tcp_ao_mac_sha1(KEY.encode(), syns[0], True)
    _, included = tcp_ao_mac_sha1(KEY.encode(), syns[0], False)
    assert received == excluded
    assert received != included


@pytest.mark.parametrize("exclude_a,exclude_b", [(True, False), (False, True)])
def test_tcp_ao_exclude_options_mismatch(local_veth, processes, tmp_path, exclude_a, exclude_b):
    instance = BngBlaster(local_veth.ns, tmp_path).start(tcp_ao_sessions(local_veth, exclude_a, exclude_b),
                                                         logging=("info", "bgp", "tcp"))
    processes.append(instance)
    with pytest.raises(TimeoutError):
        wait_until(lambda: any(s["state"] == "established" for s in instance.ctrl("bgp-sessions")["bgp-sessions"]),
                   10, message="BGP session established")
