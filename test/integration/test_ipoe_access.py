"""
BNG Blaster IPoE access sessions: IGMP, DHCPv4 and DHCPv6

Namespace A runs the BNG Blaster with IPoE sessions on VLAN 100 (N:1),
namespace B the scripted peer ipoe_peer.py (DHCP and DHCPv6 server,
router advertisements, IGMP querier) on a VLAN device, where the kernel
answers ARP and ND for the gateway. Tests with DHCP sessions against the
A10NSP mock run on both ends of a veth pair (local_veth).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import helpers
from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30
VLAN = 100
GATEWAY = "10.0.0.1"
PEER = str(Path(__file__).parent / "ipoe_peer.py")


class Setup:

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.log = str(tmp_path / "peer.log")
        self.bbl = None
        self.vlan_if = "%sv%d" % (topology.if_b, VLAN)
        topology.b.exec(["ip", "link", "add", "link", topology.if_b, "name", self.vlan_if,
                         "type", "vlan", "id", str(VLAN)])
        topology.b.exec(["ip", "link", "set", self.vlan_if, "up"])
        helpers.kernel_address(topology.b, self.vlan_if, GATEWAY + "/24", "fe80::1/64")

    def peer(self, scenario, *args):
        proc = subprocess.Popen(self.topology.b.cmd([sys.executable, PEER, self.vlan_if, self.log,
                                                     "--scenario", scenario] + list(args)))
        self.processes.append(type("Proc", (), {"stop": proc.kill})())
        time.sleep(1)

    def entries(self, **match):
        if not os.path.exists(self.log):
            return []
        entries = [json.loads(line) for line in open(self.log)]
        return [e for e in entries if all(e.get(k) == v for k, v in match.items())]

    def start(self, access=None, sessions=1, logging=("info",), **config):
        conf = {
            "interfaces": {
                "access": [dict({"interface": self.topology.if_a, "type": "ipoe", "vlan-mode": "N:1",
                                 "outer-vlan": VLAN, "ipv6": False, "address": "10.0.0.10",
                                 "address-iter": "0.0.0.1", "gateway": GATEWAY}, **(access or {}))]
            },
            "sessions": {"count": sessions, "reconnect": True},
            "dhcp": {"enable": False},
            "dhcpv6": {"enable": False},
            "igmp": {"autostart": False}
        }
        access_conf = conf["interfaces"]["access"][0]
        for key in [k for k, v in access_conf.items() if v is None]:
            del access_conf[key]
        conf.update(config)
        self.bbl = BngBlaster(self.topology.a, self.tmp_path, "bbl").start(conf, logging=logging)
        self.processes.append(self.bbl)
        return self.bbl

    def established(self, count):
        wait_until(lambda: self.bbl.ctrl("session-counters")["session-counters"]["sessions-established"]
                   == count, 20, message="sessions established")

    def info(self, session_id=1):
        return self.bbl.ctrl("session-info", **{"session-id": session_id})["session-info"]


@pytest.fixture
def ipoe(topology, processes, tmp_path):
    return Setup(topology, processes, tmp_path)


def groups(entries):
    found = []
    for e in entries:
        found += [r["group"] for r in e.get("records", [])]
        if "group" in e:
            found.append(e["group"])
    return found


def test_igmp_join_iter(ipoe):
    """igmp-join-iter sends the reports right away (RFC 3376 section 5.1)."""
    ipoe.peer("igmp")
    ipoe.start(sessions=2)
    ipoe.established(2)
    assert ipoe.bbl.ctrl("igmp-join-iter", group="239.1.1.1", **{"group-count": 2})["code"] == 200
    wait_until(lambda: {"239.1.1.1", "239.1.1.2"} <= set(groups(ipoe.entries(proto="igmp"))), 3,
               message="IGMP reports")


def test_igmpv2_leave(ipoe):
    """IGMPv2 Leave Group is sent to all routers (RFC 2236 section 3)."""
    ipoe.peer("igmp")
    ipoe.start(access={"igmp-version": 2})
    ipoe.established(1)
    assert ipoe.bbl.ctrl("igmp-join", group="239.1.1.1", **{"session-id": 1})["code"] == 200
    wait_until(lambda: ipoe.entries(proto="igmp", type=0x16), 3, message="IGMPv2 report")
    assert ipoe.bbl.ctrl("igmp-leave", group="239.1.1.1", **{"session-id": 1})["code"] == 200
    wait_until(lambda: ipoe.entries(proto="igmp", type=0x17), 3, message="IGMPv2 leave")
    assert all(e["dst"] == "224.0.0.2" for e in ipoe.entries(proto="igmp", type=0x17))


def test_igmp_autostart_interface(ipoe):
    """The access interface igmp-autostart overrides the global setting."""
    ipoe.peer("igmp")
    ipoe.start(access={"igmp-autostart": True},
               igmp={"autostart": False, "start-delay": 1, "group": "239.2.0.1"})
    ipoe.established(1)
    wait_until(lambda: "239.2.0.1" in groups(ipoe.entries(proto="igmp")), 5, message="initial join")


def test_igmp_initial_join_with_join(ipoe):
    """A join within start-delay does not cancel the initial join."""
    ipoe.peer("igmp")
    ipoe.start(igmp={"autostart": True, "start-delay": 3, "group": "239.2.0.1"})
    ipoe.established(1)
    assert ipoe.bbl.ctrl("igmp-join", group="239.3.0.1", **{"session-id": 1})["code"] == 200
    wait_until(lambda: "239.2.0.1" in groups(ipoe.entries(proto="igmp")), 6, message="initial join")


def test_igmp_rejoin_after_reconnect(ipoe):
    """Groups joined via control socket are joined again after a session
    reconnect, instead of staying active without a report."""
    ipoe.peer("igmp")
    ipoe.start()
    ipoe.established(1)
    assert ipoe.bbl.ctrl("igmp-join", group="239.1.1.1", **{"session-id": 1})["code"] == 200
    wait_until(lambda: ipoe.entries(proto="igmp"), 3, message="IGMP report")
    reports = len(ipoe.entries(proto="igmp"))
    assert ipoe.bbl.ctrl("session-restart", **{"session-id": 1})["code"] == 200
    wait_until(lambda: ipoe.info()["flapped"] == 1, 10, message="session flapped")
    ipoe.established(1)
    wait_until(lambda: len(ipoe.entries(proto="igmp")) > reports, 5, message="IGMP report after reconnect")

    def state():
        info = ipoe.bbl.ctrl("igmp-info", **{"session-id": 1})["igmp-groups"]
        return [g["state"] for g in info if g["group"] == "239.1.1.1"]

    wait_until(lambda: state() == ["active"], 5, message="group active")


def test_igmpv3_records_and_querier(ipoe):
    """IGMPv3 joins use CHANGE_TO_EXCLUDE, query responses MODE_IS_EXCLUDE
    after a delay within the max response time (RFC 3376 sections 5.1
    and 5.2), and an IGMPv2 querier switches the reports to IGMPv2
    (RFC 3376 section 7.2.1)."""
    ipoe.start()
    ipoe.established(1)
    assert ipoe.bbl.ctrl("igmp-join", group="239.1.1.1", **{"session-id": 1})["code"] == 200
    ipoe.peer("igmp-query", "--query-delay", "2")
    wait_until(lambda: ipoe.entries(proto="query", version=2), 10, message="IGMP queries")
    time.sleep(3)
    reports = ipoe.entries(proto="igmp")
    query3 = ipoe.entries(proto="query", version=3)[0]["time"]
    query2 = ipoe.entries(proto="query", version=2)[0]["time"]
    responses3 = [r for r in reports if query3 <= r["time"] < query2]
    assert responses3 and responses3[0]["type"] == 0x22, reports
    assert responses3[0]["records"][0]["type"] == 2, reports
    assert responses3[0]["time"] - query3 <= 2.5, reports
    responses2 = [r for r in reports if r["time"] >= query2]
    assert responses2 and all(r["type"] == 0x16 for r in responses2), reports


def test_igmpv3_join_record(ipoe):
    """IGMPv3 joins use the state change record CHANGE_TO_EXCLUDE."""
    ipoe.peer("igmp")
    ipoe.start()
    ipoe.established(1)
    assert ipoe.bbl.ctrl("igmp-join", group="239.1.1.1", **{"session-id": 1})["code"] == 200
    wait_until(lambda: ipoe.entries(proto="igmp", type=0x22), 3, message="IGMPv3 report")
    assert ipoe.entries(proto="igmp", type=0x22)[0]["records"][0]["type"] == 4


def test_zapping_stop_not_received(ipoe):
    """multicast-not-received does not grow after zapping-stop."""
    ipoe.peer("igmp")
    ipoe.start(igmp={"autostart": True, "start-delay": 1, "group": "239.2.0.1", "group-count": 4,
                     "zapping-interval": 1, "zapping-wait": False})
    ipoe.established(1)
    time.sleep(4)
    assert ipoe.bbl.ctrl("zapping-stop")["code"] == 200
    time.sleep(2)
    count = ipoe.bbl.ctrl("zapping-stats")["zapping-stats"]["multicast-not-received"]
    time.sleep(3)
    assert ipoe.bbl.ctrl("zapping-stats")["zapping-stats"]["multicast-not-received"] == count


def test_ra_n1_sessions(ipoe):
    """A multicast RA is processed by all IPoE sessions of an N:1 VLAN."""
    ipoe.peer("ra", "--ra-delay", "3")
    ipoe.start(sessions=3, access={"ipv4": False, "ipv6": True})
    ipoe.established(3)


def test_dhcp_rebind_and_names(ipoe):
    """An unanswered renew is followed by a broadcast rebind at T2 which
    keeps the address (RFC 2131 section 4.4.5), host and domain name of
    the DHCP-ACK are stored."""
    ipoe.peer("dhcp-rebind")
    ipoe.start(access={"address": None, "gateway": None}, dhcp={"enable": True}, logging=("info", "dhcp"))
    ipoe.established(1)
    address = ipoe.info()["ipv4-address"]
    wait_until(lambda: [e for e in ipoe.entries(proto="dhcp", type=3) if e["dst"] == "255.255.255.255"
                        and e["ciaddr"] != "0.0.0.0"], 12, message="DHCP rebind")
    time.sleep(1)
    info = ipoe.info()
    assert info["dhcp-state"] == "Bound", info
    assert info["ipv4-address"] == address
    assert info["dhcp-tx-discover"] == 1, info
    assert info["dhcp-host-name"] == "bbl-host" and info["dhcp-domain-name"] == "bbl.test", info


def test_dhcpv6_long_duid_new_xid(ipoe):
    """A 100 byte server DUID is sent in the Request, which has a new
    transaction ID (RFC 8415 sections 16.1 and 18.2.2)."""
    ipoe.peer("dhcpv6-long-duid")
    ipoe.start(access={"ipv4": False, "ipv6": True}, dhcpv6={"enable": True}, logging=("info", "dhcp"))
    ipoe.established(1)
    solicit = ipoe.entries(proto="dhcpv6", type=1)[0]
    request = ipoe.entries(proto="dhcpv6", type=3)[0]
    assert request["server_id_ok"], request
    assert request["xid"] != solicit["xid"]


def test_dhcpv6_release_ra(ipoe):
    """A session which is stopped during the DHCPv6 release does not become
    established again by the first RA."""
    ipoe.peer("dhcpv6-release-ra", "--ra-delay", "2")
    ipoe.start(access={"ipv4": False, "ipv6": True}, dhcpv6={"enable": True, "timeout": 1, "retry": 3},
               logging=("info", "dhcp"))
    wait_until(lambda: ipoe.entries(proto="dhcpv6", type=3), 10, message="DHCPv6 request")
    time.sleep(0.5)
    assert ipoe.bbl.ctrl("session-stop", **{"session-id": 1})["code"] == 200
    wait_until(lambda: ipoe.entries(proto="ra"), 5, message="RA")
    time.sleep(0.5)
    assert ipoe.info()["session-state"] != "Established"
    wait_until(lambda: ipoe.info()["session-state"] == "Terminated", 15, message="session terminated")


def a10nsp_config(veth, access, **config):
    conf = {
        "interfaces": {
            "a10nsp": [{"interface": veth.if1}],
            "access": [dict({"interface": veth.if2, "type": "ipoe", "outer-vlan-min": 100, "outer-vlan-max": 110,
                             "inner-vlan": 7}, **access)]
        },
        "sessions": {"count": 2, "reconnect": False}
    }
    conf.update(config)
    return conf


def test_dhcp_start_terminated(local_veth, processes, tmp_path):
    """dhcp-start does not act on terminated sessions."""
    instance = BngBlaster(local_veth.ns, tmp_path, "bbl").start(
        a10nsp_config(local_veth, {"ipv6": False}, dhcp={"enable": True}), logging=("info", "dhcp"))
    processes.append(instance)
    wait_until(lambda: instance.ctrl("session-counters")["session-counters"]["sessions-established"] == 2,
               20, message="sessions established")
    assert instance.ctrl("session-stop", **{"session-id": 1})["code"] == 200
    wait_until(lambda: instance.ctrl("session-info", **{"session-id": 1})["session-info"]["session-state"]
               == "Terminated", 15, message="session terminated")
    assert instance.ctrl("dhcp-start", **{"session-id": 1})["code"] == 405
    assert instance.ctrl("dhcp-start")["code"] == 200
    time.sleep(2)
    assert instance.ctrl("session-info", **{"session-id": 1})["session-info"]["session-state"] == "Terminated"
    counters = instance.ctrl("session-counters")["session-counters"]
    assert counters["sessions-terminated"] == 1 and counters["sessions-established"] == 1, counters
    assert instance.alive()
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_dhcpv6_ia_separate(local_veth, processes, tmp_path):
    """With ia-separate the IA_PD Solicit follows the IA_NA Reply without
    waiting for a retransmission timeout."""
    instance = BngBlaster(local_veth.ns, tmp_path, "bbl").start(
        a10nsp_config(local_veth, {"ipv4": False}, dhcpv6={"enable": True, "ia-separate": True}),
        logging=("info", "dhcp"))
    processes.append(instance)
    wait_until(lambda: instance.ctrl("session-counters")["session-counters"]["sessions-established"] == 2,
               4, message="sessions established")
    stats = instance.ctrl("access-protocol-stats")["access-protocol-stats"][0]
    assert stats["dhcpv6-timeout"] == 0, stats
    assert instance.terminate(EXIT_TIMEOUT) == 0
