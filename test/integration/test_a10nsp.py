"""
BNG Blaster A10NSP switch emulation

A10NSP over a network interface: namespace A runs the BNG Blaster with
PPPoE sessions on an access interface and A10NSP on a network interface
with VLAN, namespace B the access node pseudowire (a10nsp_relay.py)
between both, which forwards network frames only with the VLAN.

A10NSP interface: a single BNG Blaster instance runs IPoE sessions and
the A10NSP interface on both ends of a veth pair.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import itertools
import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import helpers
from helpers import BngBlaster, Netns, wait_until

EXIT_TIMEOUT = 30
SESSIONS = 2
VLAN = 10
RELAY = str(Path(__file__).parent / "a10nsp_relay.py")
_ids = itertools.count(1)


def counters(bbl):
    return bbl.ctrl("session-counters")["session-counters"]


@pytest.fixture
def pseudowire():
    """Namespace A with access (acc) and network (net) interface, both
    connected to namespace B."""
    n = next(_ids)
    topo = type("Topology", (), {})()
    topo.a, topo.b = Netns("a10nsp%d-a" % n), Netns("a10nsp%d-b" % n)
    topo.acc_a, topo.acc_b = "a10acc%da" % n, "a10acc%db" % n
    topo.net_a, topo.net_b = "a10net%da" % n, "a10net%db" % n
    helpers.veth_pair(topo.a, topo.acc_a, topo.b, topo.acc_b)
    helpers.veth_pair(topo.a, topo.net_a, topo.b, topo.net_b)
    yield topo
    topo.a.delete()
    topo.b.delete()


@pytest.mark.parametrize("rx_threads", [0, 1])
def test_network_interface_vlan(pseudowire, processes, tmp_path, rx_threads):
    """PPPoE sessions over A10NSP on a network interface with VLAN are
    established and session traffic is verified in both directions, as
    replies and downstream traffic carry the network interface VLAN. With
    RX threads, A10NSP stream traffic is received as in the main thread."""
    peer_mac = helpers.run(pseudowire.a.cmd(["cat", "/sys/class/net/%s/address" % pseudowire.net_a])).strip()
    relay = subprocess.Popen(pseudowire.b.cmd([sys.executable, RELAY, pseudowire.acc_b, pseudowire.net_b,
                                               "--vlan", str(VLAN), "--peer-mac", peer_mac]),
                             stdout=subprocess.PIPE, text=True)
    processes.append(type("Proc", (), {"stop": relay.kill})())
    config = {
        "interfaces": {
            "network": [{"interface": pseudowire.net_a, "address": "10.0.0.1/24", "gateway": "10.0.0.2",
                         "vlan": VLAN, "a10nsp": True, "gateway-resolve-wait": False}],
            "access": [{"interface": pseudowire.acc_a, "type": "pppoe", "outer-vlan-min": 100,
                        "outer-vlan-max": 200, "inner-vlan": 7}]
        },
        "sessions": {"count": SESSIONS},
        "session-traffic": {"ipv4-pps": 1},
        "dhcpv6": {"enable": False},
        "ppp": {"ip6cp": {"enable": False}}
    }
    if rx_threads:
        config["interfaces"]["links"] = [{"interface": pseudowire.net_a, "rx-threads": rx_threads}]
    instance = BngBlaster(pseudowire.a, tmp_path, "bbl").start(config)
    processes.append(instance)
    wait_until(lambda: counters(instance)["sessions-established"] == SESSIONS, 30,
               message="sessions established")
    wait_until(lambda: counters(instance)["session-traffic-flows-verified"] == 2 * SESSIONS, 15,
               message="session traffic verified")
    info = instance.ctrl("session-info", **{"session-id": 1})["session-info"]
    assert info["a10nsp"]["interface"] == "%s:%d" % (pseudowire.net_a, VLAN)
    # Upstream received over MPLS carries the RX timestamp (was 0).
    streams = instance.ctrl("session-streams", **{"session-id": 1})["session-streams"]["streams"]
    upstream = [s for s in streams if s["direction"] == "upstream"]
    assert upstream and all(s["rx-first-epoch"] > 0 for s in upstream), upstream
    assert instance.terminate(EXIT_TIMEOUT) == 0
    relay.send_signal(signal.SIGTERM)
    stats = json.loads(relay.communicate(timeout=10)[0])
    assert stats["untagged"] == 0, stats


PADI_INJECT = r"""
import socket, struct, sys, time
ifname, host_uniq_len = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((ifname, 0))
tags = struct.pack("!HH", 0x0101, 0) + struct.pack("!HH", 0x0103, host_uniq_len) + b"h" * host_uniq_len
frame = (b"\xff" * 6 + bytes.fromhex("020000000001") + struct.pack("!HHHH", 0x8100, 100, 0x8100, 7) +
         struct.pack("!HBBHH", 0x8863, 0x11, 0x09, 0, len(tags)) + tags)
s.send(frame)
largest, end = 0, time.monotonic() + 2
s.settimeout(0.2)
while time.monotonic() < end:
    try:
        data = s.recv(65535)
    except socket.timeout:
        continue
    # The kernel strips the outer VLAN tag of received frames.
    for offset in (12, 16, 20):
        if data[offset:offset + 2] == b"\x88\x63" and data[offset + 3] == 0x07:
            largest = max(largest, len(data))
print(len(frame), largest)
"""


def test_pado_reply_slot_limit(local_veth, processes, tmp_path):
    """A PADI close to the TXQ slot size is not answered, as the PADO with
    AC-Cookie, AC-Name and Service-Name would not fit into the slot (was
    encoded beyond the slot). Small PADIs are answered."""
    for ifname in (local_veth.if1, local_veth.if2):
        local_veth.ns.exec(["ip", "link", "set", ifname, "mtu", "9000"])
    config = {
        "interfaces": {
            "links": [{"interface": local_veth.if1, "io-mode": "raw"}],
            "a10nsp": [{"interface": local_veth.if1}],
            "access": [{"interface": local_veth.if2, "type": "pppoe", "outer-vlan": 100, "inner-vlan": 7}]
        },
        "sessions": {"count": 1},
        "dhcpv6": {"enable": False},
        "ppp": {"ip6cp": {"enable": False}}
    }
    instance = BngBlaster(local_veth.ns, tmp_path, "bbl").start(config)
    processes.append(instance)
    wait_until(lambda: counters(instance)["sessions-established"] == 1, 15, message="session established")

    def inject(host_uniq_len):
        out = helpers.run(local_veth.ns.cmd([sys.executable, "-c", PADI_INJECT, local_veth.if2,
                                             str(host_uniq_len)]))
        return [int(v) for v in out.split()]

    padi, pado = inject(16)
    assert pado and pado < 200, (padi, pado)
    padi, pado = inject(4026)
    assert padi == 4062 and pado == 0, (padi, pado)
    assert instance.alive()
    assert instance.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.full
def test_dhcpv6_renew(local_veth, processes, tmp_path):
    """The A10NSP answers DHCPv6 Renew of IPoE sessions at T1 (300 seconds)
    with Reply, the lease is not restarted with Solicit."""
    config = {
        "interfaces": {
            "a10nsp": [{"interface": local_veth.if1}],
            "access": [{"interface": local_veth.if2, "type": "ipoe", "outer-vlan": 100, "inner-vlan": 7,
                        "ipv4": False}]
        },
        "sessions": {"count": 1},
        "dhcpv6": {"enable": True}
    }
    instance = BngBlaster(local_veth.ns, tmp_path, "bbl").start(config, logging=("info", "dhcp"))
    processes.append(instance)

    def info():
        return instance.ctrl("session-info", **{"session-id": 1})["session-info"]

    wait_until(lambda: info()["dhcpv6-state"] == "Bound", 30, message="DHCPv6 bound")
    replies = info()["dhcpv6-rx-reply"]
    wait_until(lambda: info()["dhcpv6-tx-renew"] >= 1, 330, interval=5, message="DHCPv6 renew")
    wait_until(lambda: info()["dhcpv6-rx-reply"] > replies, 10, message="DHCPv6 renew reply")
    session = info()
    assert session["dhcpv6-state"] == "Bound", session
    assert session["dhcpv6-tx-solicit"] == 1, session
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_dhcpv6_reply_client_id(local_veth, processes, tmp_path):
    """The A10NSP DHCPv6 replies carry the Client Identifier of the request
    (RFC 8415 section 18.3)."""
    from scapy.utils import rdpcap
    from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply, DHCP6OptClientId
    config = {
        "interfaces": {
            "a10nsp": [{"interface": local_veth.if1}],
            "access": [{"interface": local_veth.if2, "type": "ipoe", "outer-vlan": 100, "inner-vlan": 7,
                        "ipv4": False}]
        },
        "sessions": {"count": 1},
        "dhcpv6": {"enable": True}
    }
    instance = BngBlaster(local_veth.ns, tmp_path, "bbl").start(config)
    processes.append(instance)
    wait_until(lambda: instance.ctrl("session-info", **{"session-id": 1})["session-info"]["dhcpv6-state"]
               == "Bound", 30, message="DHCPv6 bound")
    assert instance.terminate(EXIT_TIMEOUT) == 0
    replies = [p for p in rdpcap(instance.path("pcap")) if DHCP6_Advertise in p or DHCP6_Reply in p]
    assert replies
    assert all(DHCP6OptClientId in p for p in replies), [p.summary() for p in replies]

