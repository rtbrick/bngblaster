"""
BNG Blaster ISIS against a scripted neighbor (isis_peer.py)

The neighbor sends PDUs in orders and with contents a real router would
not send, to verify the receive rules of ISO 10589, RFC 5303 (P2P
three-way handshake), RFC 5304 (HMAC-MD5) and the control commands.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import hashlib
import hmac
import struct
import time

import pytest

import isis_peer as ip
from helpers import BngBlaster, lspgen, wait_until

BBL_SYSTEM_ID = "1921.6800.1001"
BBL_SYSID = ip.system_id(BBL_SYSTEM_ID)
PEER_SYSTEM_ID = "1921.6800.2002"
AREA = "49.0001/24"
KEY = "secret123"


def bbl_config(ifname, level=2, p2p=True, isis=None, network=None):
    instance = {
        "instance-id": 1,
        "level": level,
        "area": [AREA],
        "system-id": BBL_SYSTEM_ID,
        "router-id": "10.10.0.1",
        "hostname": "BBL",
        "hello-interval": 1,
        "hold-time": 30,
    }
    instance.update(isis or {})
    interface = {
        "interface": ifname,
        "address": "10.0.0.1/24",
        "gateway": "10.0.0.2",
        "isis-instance-id": 1,
        "isis-level": level,
        "isis-p2p": p2p,
    }
    interface.update(network or {})
    return {"interfaces": {"network": interface}, "isis": [instance]}


@pytest.fixture
def setup(topology, processes, tmp_path):
    """Start the BNG Blaster with config(**kwargs) and return it with a
    scripted neighbor on the other end of the veth pair."""
    peers = []

    def start(mac="02:00:00:00:00:fe", **kwargs):
        bbl = BngBlaster(topology.a, tmp_path).start(bbl_config(topology.if_a, **kwargs),
                                                     logging=("info", "isis"))
        processes.append(bbl)
        peer = ip.IsisPeer(topology.b, topology.if_b, mac=mac, sysid=PEER_SYSTEM_ID)
        peers.append(peer)
        return bbl, peer
    yield start
    for peer in peers:
        peer.close()


def p2p_state(p):
    """(state, TLV length) of the three-way adjacency TLV of a P2P hello."""
    v = p.tlv(ip.TLV_P2P_ADJ)[0]
    return v[0], len(v)


def is_p2p_hello(p):
    return p.type == ip.P2P_HELLO


def p2p_up(peer, circuit_type=2, auth=None):
    """Bring the P2P adjacency up with the three-way handshake and return
    the extended local circuit ID of the BNG Blaster."""
    send = (lambda d: peer.send(sign(d, auth))) if auth else peer.send
    send(peer.p2p_hello(ip.P2P_DOWN, circuit_type=circuit_type, hold=600))
    hello = peer.wait(5, lambda p: is_p2p_hello(p) and p2p_state(p)[0] == ip.P2P_INIT)
    assert hello, "BNG Blaster did not change to init"
    circuit = struct.unpack("!I", hello.tlv(ip.TLV_P2P_ADJ)[0][1:5])[0]
    send(peer.p2p_hello(ip.P2P_INIT, circuit_type=circuit_type, neighbor=BBL_SYSID,
                        neighbor_circuit=circuit, hold=600))
    assert peer.wait(5, lambda p: is_p2p_hello(p) and p2p_state(p)[0] == ip.P2P_UP)
    send(peer.p2p_hello(ip.P2P_UP, circuit_type=circuit_type, neighbor=BBL_SYSID,
                        neighbor_circuit=circuit, hold=600))
    return circuit


def sign(data, key):
    """Insert an HMAC-MD5 authentication TLV as first TLV of a PDU."""
    hdr = data[1]
    data = bytearray(data[:hdr] + ip.tlv(ip.TLV_AUTH, b"\x36" + bytes(16)) + data[hdr:])
    length_offset = 17 if data[4] in (ip.L1_HELLO, ip.L2_HELLO, ip.P2P_HELLO) else 8
    data[length_offset:length_offset + 2] = struct.pack("!H", len(data))
    work = bytearray(data)
    if data[4] in (ip.L1_LSP, ip.L2_LSP):
        work[10:12] = b"\x00\x00"
        work[24:26] = b"\x00\x00"
    data[hdr + 3:hdr + 19] = hmac.new(key.encode(), bytes(work), hashlib.md5).digest()
    return bytes(data)


def database(bbl, level=2):
    return {e["id"]: e for e in bbl.ctrl("isis-database", instance=1, level=level)["isis-database"]}


def adjacency_up(bbl, level="L2"):
    for a in bbl.ctrl("isis-adjacencies")["isis-adjacencies"]:
        if a["level"] == level and a["adjacency-state"] == "Up":
            return True
    return False


def test_p2p_three_way(setup):
    """RFC 5303 section 3.2: a neighbor reporting up while the local state
    is down does not bring the adjacency up. The extended TLV with the
    neighbor system-id is sent once the neighbor is known (section 3.1),
    a neighbor reporting another system resets the adjacency (3.3)."""
    bbl, peer = setup()
    peer.send(peer.p2p_hello(ip.P2P_UP, hold=600))
    hellos = peer.recv(3, is_p2p_hello)
    assert hellos and all(p2p_state(p)[0] == ip.P2P_DOWN for p in hellos)
    assert not adjacency_up(bbl)

    peer.send(peer.p2p_hello(ip.P2P_DOWN, hold=600))
    hello = peer.wait(5, lambda p: is_p2p_hello(p) and p2p_state(p)[0] == ip.P2P_INIT)
    assert hello
    v = hello.tlv(ip.TLV_P2P_ADJ)[0]
    assert len(v) == 15 and v[5:11] == peer.sysid and v[11:15] == struct.pack("!I", 1)
    circuit = struct.unpack("!I", v[1:5])[0]

    peer.send(peer.p2p_hello(ip.P2P_INIT, neighbor=BBL_SYSID, neighbor_circuit=circuit, hold=600))
    assert peer.wait(5, lambda p: is_p2p_hello(p) and p2p_state(p)[0] == ip.P2P_UP)
    wait_until(lambda: adjacency_up(bbl), 5, message="adjacency up")

    peer.send(peer.p2p_hello(ip.P2P_UP, neighbor=ip.system_id("1921.6800.9999"),
                             neighbor_circuit=circuit, hold=600))
    assert peer.wait(5, lambda p: is_p2p_hello(p) and p2p_state(p)[0] == ip.P2P_INIT)
    wait_until(lambda: not adjacency_up(bbl), 5, message="adjacency down")


def test_p2p_two_way(setup):
    """RFC 5303 section 3.1: hellos without the three-way adjacency TLV
    are handled by the two-way handshake of ISO 10589, the adjacency is
    up with the first hello of the neighbor."""
    bbl, peer = setup()
    peer.send(peer.p2p_hello(hold=600))
    wait_until(lambda: adjacency_up(bbl), 5, message="adjacency up")
    assert peer.wait(5, lambda p: is_p2p_hello(p) and p2p_state(p)[0] == ip.P2P_UP)


def test_self_lsp_buffer_size(setup, topology, tmp_path):
    """With the minimum lsp-buffer-size of 512, a long hostname and a long
    authentication key, the TLVs which do not fit into fragment zero are
    moved to the next fragment (overflowed the LSP buffer). If even area
    addresses, protocols, hostname and authentication do not fit, the
    configuration is rejected."""
    isis = {"lsp-buffer-size": 512, "hostname": "h" * 250,
            "level2-auth-key": "k" * 200, "level2-auth-type": "simple"}
    bbl, _ = setup(isis=isis)
    lsps = sorted(e for e in database(bbl) if e.startswith(BBL_SYSTEM_ID))
    assert lsps == [BBL_SYSTEM_ID + ".00-00", BBL_SYSTEM_ID + ".00-01"], lsps
    assert bbl.alive()

    other = BngBlaster(topology.a, tmp_path, name="buffer")
    isis["level2-auth-key"] = "k" * 254
    isis["area"] = ["49.0001.0000.0000.0001/104", "49.0002.0000.0000.0001/104"]
    with pytest.raises(RuntimeError):
        other.start(bbl_config(topology.if_a, isis=isis))


def test_level_mismatch(setup, topology, tmp_path):
    """An interface with the default isis-level 3 on a level 2 instance
    has only a level 2 adjacency. Level 1 LSPs, also via control socket,
    are rejected without crash."""
    bbl, peer = setup(level=2, network={"isis-level": 3})
    p2p_up(peer, circuit_type=3)
    wait_until(lambda: adjacency_up(bbl, "L2"), 5, message="L2 adjacency up")
    assert [a["level"] for a in bbl.ctrl("isis-adjacencies")["isis-adjacencies"]] == ["L2"]

    l1 = ip.lsp(ip.L1_LSP, ip.lsp_id("0000.0000.0099"), 1, 1200)
    peer.send(l1, dst=ip.MAC_L1)
    time.sleep(1)
    assert bbl.alive()
    response = bbl.ctrl("isis-lsp-update", instance=1, pdu=[l1.hex()])
    assert response["status"] == "error"
    assert bbl.alive() and database(bbl)

    # An interface level not enabled in the instance is a config error.
    other = BngBlaster(topology.a, tmp_path, name="mismatch")
    with pytest.raises(RuntimeError):
        other.start(bbl_config(topology.if_a, level=2, network={"isis-level": 1}))


def test_lan_pdus_before_hello(setup):
    """LSPs and SNPs received before an adjacency is up are discarded
    (ISO 10589 7.3.15), which crashed on LAN without peer."""
    bbl, peer = setup(p2p=False)
    lid = ip.lsp_id("0000.0000.0099")
    peer.send(ip.lsp(ip.L2_LSP, lid, 1, 1200), dst=ip.MAC_L2)
    peer.send(peer.snp(ip.L2_CSNP, [(1200, ip.lsp_id("0000.0000.0098"), 1, 0x1234)]), dst=ip.MAC_L2)
    peer.send(peer.snp(ip.L2_PSNP, [(1200, ip.lsp_id("0000.0000.0097"), 1, 0x1234)]), dst=ip.MAC_L2)
    time.sleep(1)
    assert bbl.alive()
    db = database(bbl)
    assert not [i for i in db if i.startswith("0000.0000.00")]


def lan_dis(p):
    """LAN ID of a LAN hello."""
    return p.raw[20:27]


def test_lan_dis_tie(setup):
    """ISO 10589 8.4.5: with equal priority the highest MAC address wins,
    so the BNG Blaster stays DIS against a neighbor with a lower MAC."""
    bbl, peer = setup(p2p=False, mac="00:00:00:00:00:01")
    assert peer.wait(5, lambda p: p.type == ip.L2_HELLO)
    bbl_mac = peer.last_src
    for _ in range(5):
        # Same priority as the BNG Blaster (default 10), claims to be DIS.
        peer.send(peer.lan_hello(level=2, priority=10, dis=peer.sysid + b"\x01",
                                 neighbors=[bbl_mac], hold=10), dst=ip.MAC_L2)
        time.sleep(1)
    wait_until(lambda: adjacency_up(bbl), 5, message="adjacency up")
    hellos = peer.recv(3, lambda p: p.type == ip.L2_HELLO)
    assert hellos and all(lan_dis(p)[:6] == BBL_SYSID for p in hellos)


def test_hello_checks(setup):
    """Hellos with another area (level 1), a circuit type without the
    level or the own system-id do not create neighbors (ISO 10589 8.4)."""
    bbl, peer = setup(level=1, p2p=False)
    for _ in range(3):
        peer.send(peer.lan_hello(level=1, areas=("49.0002",)), dst=ip.MAC_L1)
        peer.send(peer.lan_hello(level=1, sysid=BBL_SYSID), dst=ip.MAC_L1)
        time.sleep(1)
    hellos = peer.recv(2, lambda p: p.type == ip.L1_HELLO)
    assert hellos and not any(h.tlv(ip.TLV_IS_NEIGHBOR) for h in hellos)
    assert not bbl.ctrl("isis-adjacencies")["isis-adjacencies"][0]["peers"]

    peer.send(peer.lan_hello(level=1, areas=("49.0002", "49.0001")), dst=ip.MAC_L1)
    hello = peer.wait(5, lambda p: p.type == ip.L1_HELLO and p.tlv(ip.TLV_IS_NEIGHBOR))
    assert hello and peer.mac in hello.tlv(ip.TLV_IS_NEIGHBOR)[0]


def test_hello_circuit_type(setup):
    bbl, peer = setup(level=2, p2p=False)
    for _ in range(3):
        peer.send(peer.lan_hello(level=2, circuit_type=1), dst=ip.MAC_L2)
        time.sleep(1)
    assert not bbl.ctrl("isis-adjacencies")["isis-adjacencies"][0]["peers"]


def test_lsp_receive_rules(setup):
    """Receive rules for LSPs and SNP entries on a P2P adjacency."""
    bbl, peer = setup()
    p2p_up(peer)
    wait_until(lambda: adjacency_up(bbl), 5, message="adjacency up")
    x = ip.lsp_id("0000.0000.0099")
    ext = ip.tlv(ip.TLV_EXT_IS_REACH, peer.sysid + b"\x00" + b"\x00\x00\x0a\x00")

    # ISO 10589 7.3.14.2: zero checksum of an LSP with lifetime is invalid.
    peer.send(ip.lsp(ip.L2_LSP, x, 5, 1200, ext, checksum=0), dst=ip.MAC_L2)
    time.sleep(1)
    assert "0000.0000.0099.00-00" not in database(bbl)

    # Bytes after the PDU length are ignored (e.g. Ethernet padding).
    peer.send(ip.lsp(ip.L2_LSP, x, 5, 1200, ext) + bytes(6), dst=ip.MAC_L2)
    wait_until(lambda: database(bbl).get("0000.0000.0099.00-00", {}).get("seq") == 5, 5,
               message="LSP with trailing bytes accepted")

    # Authentication TLVs are accepted without authentication.
    y = ip.lsp_id("0000.0000.0098")
    peer.send(ip.lsp(ip.L2_LSP, y, 1, 1200, ip.tlv(ip.TLV_AUTH, b"\x01abc") + ext), dst=ip.MAC_L2)
    wait_until(lambda: "0000.0000.0098.00-00" in database(bbl), 5, message="LSP with auth TLV")

    # An older LSP is answered with the newer one (ISO 10589 7.3.15.1).
    peer.send(ip.lsp(ip.L2_LSP, x, 3, 1200, ext), dst=ip.MAC_L2)
    assert peer.wait(5, lambda p: p.type == ip.L2_LSP and p.lsp_id == x and p.seq == 5)

    # A CSNP entry with the same sequence number and zero lifetime is
    # newer, the LSP is requested.
    peer.send(peer.snp(ip.L2_CSNP, [(0, x, 5, 0)]), dst=ip.MAC_L2)
    assert peer.wait(5, lambda p: p.type == ip.L2_PSNP and any(e[1] == x for e in p.entries()))

    # The checksum of a purge is not checked (RFC 3719 section 7).
    peer.send(ip.lsp(ip.L2_LSP, x, 6, 0, checksum=0x1234), dst=ip.MAC_L2)
    wait_until(lambda: database(bbl).get("0000.0000.0099.00-00", {}).get("seq") == 6, 5,
               message="purge accepted")
    assert database(bbl)["0000.0000.0099.00-00"]["lifetime-remaining"] == 0

    # LSP-ID zero is acknowledged.
    zero = bytes(8)
    peer.send(ip.lsp(ip.L2_LSP, zero, 1, 1200, ext), dst=ip.MAC_L2)
    assert peer.wait(5, lambda p: p.type == ip.L2_PSNP and any(e[1] == zero for e in p.entries()))

    # An own LSP not originated is purged with a higher sequence number.
    own = ip.lsp_id(BBL_SYSID, 0, 7)
    peer.send(ip.lsp(ip.L2_LSP, own, 100, 1200, ext), dst=ip.MAC_L2)
    p = peer.wait(5, lambda p: p.type == ip.L2_LSP and p.lsp_id == own)
    assert p and p.seq == 101 and p.lifetime == 0

    # The sequence number of own LSPs does not wrap (ISO 10589 7.3.16.1).
    frag0 = ip.lsp_id(BBL_SYSID)
    peer.send(ip.lsp(ip.L2_LSP, frag0, 0xffffffff, 1200, ext), dst=ip.MAC_L2)
    time.sleep(1)
    assert database(bbl)["%s.00-00" % BBL_SYSTEM_ID]["seq"] == 0xffffffff
    assert bbl.alive()


def test_csnp_ranges_md5(setup, tmp_path):
    """CSNPs of a large LSDB describe every LSP exactly once in contiguous
    ranges, and each one has a valid HMAC-MD5 (RFC 5304)."""
    topo = tmp_path / "isis"
    mrt = str(topo.with_suffix(".mrt"))
    # Node prefix 10.1.0.0 gives system-ids 0100.0100.xxxx, which do not
    # collide with the BNG Blaster system-id.
    lspgen(["-a", AREA, "-c", "300", "-V", "2", "-C", BBL_SYSTEM_ID, "-K", KEY, "-T", "md5",
            "-n", "10.1.0.0/32", "-m", mrt], cwd=str(tmp_path))
    bbl, peer = setup(isis={"level2-auth-key": KEY, "level2-auth-type": "md5", "csnp-interval": 4,
                            "external": {"mrt-file": mrt,
                                         "connections": [{"system-id": "0100.0100.0000.00", "l2-metric": 10}]}})
    p2p_up(peer, auth=KEY)
    # One complete round of the periodic CSNPs, starting with LSP-ID zero.
    csnps = peer.recv(9, lambda p: p.type == ip.L2_CSNP)
    first = next(i for i, c in enumerate(csnps) if c.raw[17:25] == bytes(8))
    csnps = csnps[first:]
    assert len(csnps) >= 4
    db = sorted(bytes.fromhex(i.replace(".", "").replace("-", "")) for i in database(bbl))
    listed = []
    for c in csnps:
        auth = [off for t, v, off in c.tlvs if t == ip.TLV_AUTH]
        assert auth and ip.hmac_ok(c.raw[:c.length], KEY, auth[0] + 1), "invalid HMAC"
        start, end = c.raw[17:25], c.raw[25:33]
        entries = [e[1] for e in c.entries()]
        assert all(start <= e <= end for e in entries)
        assert [i for i in db if start <= i <= end] == entries, "LSP missing in CSNP range"
        listed += entries
        if end == b"\xff" * 8:
            break
    assert sorted(listed) == db


def test_lsp_retry_interval(setup):
    """Unacknowledged LSPs are retransmitted after lsp-retry-interval, the
    retry job runs every second (it used to take 2-3 times the interval)."""
    bbl, peer = setup(isis={"lsp-retry-interval": 3})
    p2p_up(peer)
    own = ip.lsp_id(BBL_SYSID)
    sent = peer.recv(14, lambda p: p.type == ip.L2_LSP and p.lsp_id == own)
    assert len(sent) >= 3
    gaps = [b.time - a.time for a, b in zip(sent, sent[1:])]
    assert all(2.9 < g < 4.3 for g in gaps), gaps


def test_expired_lsp_purge(setup):
    """An external LSP reaching lifetime 0 is purged in the network with
    the header only (ISO 10589 7.3.16.4)."""
    bbl, peer = setup()
    p2p_up(peer)
    z = ip.lsp_id("0000.0000.0077")
    ext = ip.tlv(ip.TLV_EXT_IS_REACH, BBL_SYSID + b"\x00" + b"\x00\x00\x0a\x00")
    response = bbl.ctrl("isis-lsp-update", instance=1, pdu=[ip.lsp(ip.L2_LSP, z, 1, 20, ext).hex()])
    assert response["status"] == "ok", response
    assert peer.wait(5, lambda p: p.type == ip.L2_LSP and p.lsp_id == z and p.lifetime > 0)
    purge = peer.wait(35, lambda p: p.type == ip.L2_LSP and p.lsp_id == z and p.lifetime == 0)
    assert purge and purge.seq == 1 and not purge.tlv(ip.TLV_EXT_IS_REACH)


def test_ctrl_input(setup, tmp_path):
    """Invalid identifiers and hex strings are refused, own LSPs can not be
    updated externally and isis-load-mrt floods the loaded LSPs."""
    bbl, peer = setup()
    p2p_up(peer)
    assert bbl.ctrl("isis-lsp-purge", instance=1, level=2, id="1921.6800")["code"] == 400
    assert bbl.ctrl("isis-lsp-update", instance=1, pdu=["831b0"])["code"] == 400
    assert bbl.ctrl("isis-lsp-update", instance=1, pdu=["831bzz"])["code"] == 400
    own = ip.lsp(ip.L2_LSP, ip.lsp_id(BBL_SYSID), 1000, 1200)
    assert bbl.ctrl("isis-lsp-update", instance=1, pdu=[own.hex()])["status"] == "error"

    mrt = str(tmp_path / "load.mrt")
    lspgen(["-a", AREA, "-c", "5", "-V", "2", "-C", BBL_SYSTEM_ID, "-m", mrt], cwd=str(tmp_path))
    assert bbl.ctrl("isis-load-mrt", instance=1, file=mrt)["status"] == "ok"
    assert peer.wait(5, lambda p: p.type == ip.L2_LSP and p.lsp_id[:6] == ip.system_id("1921.6800.0000"))


def test_lsp_header_and_buffer_size(setup):
    """Level 1 LSPs have IS type 1 (ISO 10589 9.9) and self originated
    LSPs do not exceed the lsp-buffer-size."""
    connections = [{"system-id": "0000.0000.%04x.00" % i, "l1-metric": 10} for i in range(60)]
    bbl, peer = setup(level=1, isis={"lsp-buffer-size": 512, "external": {"connections": connections}})
    p2p_up(peer, circuit_type=1)
    # An empty CSNP of the whole range requests all LSPs.
    peer.send(peer.snp(ip.L1_CSNP, []), dst=ip.MAC_L1)
    lsps = peer.recv(3, lambda p: p.type == ip.L1_LSP and p.lsp_id[:6] == BBL_SYSID)
    assert len({p.lsp_id for p in lsps}) > 1
    assert all(p.length <= 512 and p.raw[26] & 0x03 == 1 for p in lsps)


def test_config_limits(topology, tmp_path):
    """More than 3 areas and LSP buffer sizes below 512 are refused."""
    for name, isis in (("areas", {"area": ["49.0001/24", "49.0002/24", "49.0003/24", "49.0004/24"]}),
                       ("buffer", {"lsp-buffer-size": 128})):
        bbl = BngBlaster(topology.a, tmp_path, name=name)
        with pytest.raises(RuntimeError):
            bbl.start(bbl_config(topology.if_a, isis=isis))


def test_pseudonode_lsp(setup):
    """The pseudonode LSP of many neighbors uses several fragments without
    adjacency SID (RFC 8667 section 2.2) and is purged when all
    neighbors are gone (ISO 10589 8.4.5)."""
    bbl, peer = setup(p2p=False, isis={"adjacency-sid-base": 1000})
    hello = peer.wait(5, lambda p: p.type == ip.L2_HELLO)
    assert hello
    bbl_mac = peer.last_src
    macs = [bytes([2, 0, 0, 1, i >> 8, i & 0xff]) for i in range(120)]
    for _ in range(6):
        for i, mac in enumerate(macs):
            sysid = bytes([0x19, 0x21, 0x68, 0x00, i >> 8, i & 0xff])
            peer.send(peer.lan_hello(level=2, priority=0, neighbors=[bbl_mac], hold=4, sysid=sysid,
                                     dis=BBL_SYSID + b"\x01"), dst=ip.MAC_L2, src=mac)
        time.sleep(1)
    db = database(bbl)
    pseudo = [i for i in db if i.startswith("%s.01-" % BBL_SYSTEM_ID)]
    assert len(pseudo) >= 2, db.keys()
    assert all(db[i]["lifetime-remaining"] > 0 for i in pseudo)
    assert bbl.alive()

    wait_until(lambda: not adjacency_up(bbl), 15, message="adjacency down")
    db = database(bbl)
    assert all(db[i]["lifetime-remaining"] == 0 for i in pseudo if i in db)


@pytest.mark.slow
def test_snp_request_expiry(setup):
    """An LSP requested by a CSNP entry but never received is removed:
    60 seconds request lifetime, 60 seconds purge timer and up to 30
    seconds until the garbage collection (it was kept forever)."""
    bbl, peer = setup()
    p2p_up(peer)
    w = ip.lsp_id("0000.0000.0066")
    peer.send(peer.snp(ip.L2_CSNP, [(1200, w, 5, 0x1234)]), dst=ip.MAC_L2)
    assert peer.wait(5, lambda p: p.type == ip.L2_PSNP and any(e[1] == w for e in p.entries()))
    assert database(bbl)["0000.0000.0066.00-00"]["seq"] == 0
    wait_until(lambda: "0000.0000.0066.00-00" not in database(bbl), 170, 5,
               message="requested LSP removed")
    assert bbl.alive()


@pytest.mark.slow
def test_flap_hmac(setup):
    """An external LSP flapped for longer than it is kept as purge (60
    seconds purge timer plus garbage collection) is re-created with a
    valid HMAC-MD5 for its new sequence number, also without external
    auto-refresh (it kept the HMAC of the old sequence number)."""
    bbl, peer = setup(isis={"level2-auth-key": KEY, "level2-auth-type": "md5"})
    p2p_up(peer, auth=KEY)
    z = ip.lsp_id("0000.0000.0055")
    ext = ip.tlv(ip.TLV_EXT_IS_REACH, BBL_SYSID + b"\x00" + b"\x00\x00\x0a\x00")
    data = bytearray(sign(ip.lsp(ip.L2_LSP, z, 1, 1200, ext), KEY))
    data[24:26] = ip.fletcher(data[12:], 12)
    assert bbl.ctrl("isis-lsp-update", instance=1, pdu=[bytes(data).hex()])["status"] == "ok"
    assert peer.wait(5, lambda p: p.type == ip.L2_LSP and p.lsp_id == z and p.lifetime > 0)

    assert bbl.ctrl("isis-lsp-flap", instance=1, level=2, id="0000.0000.0055.00-00", timer=100)["status"] == "ok"
    purge = peer.wait(5, lambda p: p.type == ip.L2_LSP and p.lsp_id == z and p.lifetime == 0)
    assert purge
    # The acknowledged purge is removed from the LSDB before the flap ends.
    peer.send(sign(peer.snp(ip.L2_PSNP, [(0, z, purge.seq, 0)]), KEY), dst=ip.MAC_L2)
    wait_until(lambda: "0000.0000.0055.00-00" not in database(bbl), 95, 5,
               message="purged LSP removed")
    lsp = peer.wait(115, lambda p: p.type == ip.L2_LSP and p.lsp_id == z and p.lifetime > 0)
    assert lsp and lsp.seq > 2
    auth = [off for t, v, off in lsp.tlvs if t == ip.TLV_AUTH]
    assert auth and ip.hmac_ok(lsp.raw[:lsp.length], KEY, auth[0] + 1), "invalid HMAC"
    assert ip.fletcher_ok(lsp.raw[12:lsp.length])

