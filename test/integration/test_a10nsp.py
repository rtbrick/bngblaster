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


def test_network_interface_vlan(pseudowire, processes, tmp_path):
    """PPPoE sessions over A10NSP on a network interface with VLAN are
    established and session traffic is verified in both directions, as
    replies and downstream traffic carry the network interface VLAN."""
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
    instance = BngBlaster(pseudowire.a, tmp_path, "bbl").start(config)
    processes.append(instance)
    wait_until(lambda: counters(instance)["sessions-established"] == SESSIONS, 30,
               message="sessions established")
    wait_until(lambda: counters(instance)["session-traffic-flows-verified"] == 2 * SESSIONS, 15,
               message="session traffic verified")
    info = instance.ctrl("session-info", **{"session-id": 1})["session-info"]
    assert info["a10nsp"]["interface"] == "%s:%d" % (pseudowire.net_a, VLAN)
    assert instance.terminate(EXIT_TIMEOUT) == 0
    relay.send_signal(signal.SIGTERM)
    stats = json.loads(relay.communicate(timeout=10)[0])
    assert stats["untagged"] == 0, stats


@pytest.mark.slow
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
