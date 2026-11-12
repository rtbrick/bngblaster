"""
BNG Blaster LDP against FRR (ldpd)

Namespace A runs the BNG Blaster (10.0.0.1, fd00::1), namespace B runs
FRR on the kernel interface (10.0.0.2, fd00::2). The LDP sessions use
the interface addresses as transport addresses. FRR advertises the
connected prefix (implicit null) and a static route with a label.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import time

import pytest

import helpers
from helpers import BngBlaster, Frr, wait_until

BBL_LSR_ID, FRR_LSR_ID = "10.10.0.1", "10.10.0.2"
BBL_ADDRESS, FRR_ADDRESS = "10.0.0.1", "10.0.0.2"
BBL_ADDRESS6, FRR_ADDRESS6 = "fd00::1", "fd00::2"
FRR_STATIC = "10.98.0.0/24"
HOLD_TIME = 6

pytestmark = pytest.mark.usefixtures("frr_bin")


class LdpSetup:

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.frr = None
        self.bbl = None
        helpers.kernel_address(topology.b, topology.if_b, FRR_ADDRESS + "/24", FRR_ADDRESS6 + "/64")

    def frr_config(self, ipv4=True, ipv6=False, hold_time=HOLD_TIME):
        lines = ["ip route %s %s" % (FRR_STATIC, BBL_ADDRESS), "mpls ldp", " router-id %s" % FRR_LSR_ID]
        for af, enabled, transport in (("ipv4", ipv4, FRR_ADDRESS), ("ipv6", ipv6, FRR_ADDRESS6)):
            if enabled:
                lines += [" address-family %s" % af,
                          "  discovery hello holdtime %d" % hold_time,
                          "  discovery hello interval 2",
                          "  discovery transport-address %s" % transport,
                          "  interface %s" % self.topology.if_b,
                          "  exit",
                          " exit-address-family"]
        lines.append("exit")
        return "\n".join(lines) + "\n"

    def start_frr(self, **frr):
        self.frr = Frr(self.topology.b, self.tmp_path, ("ldpd", "staticd")).start(self.frr_config(**frr))
        self.processes.append(self.frr)

    def start_bbl(self, ipv6=False, ipv4_interface=True, streams=None):
        network = {"interface": self.topology.if_a, "gateway": FRR_ADDRESS, "ldp-instance-id": 1,
                   "address-ipv6": BBL_ADDRESS6 + "/64", "gateway-ipv6": FRR_ADDRESS6}
        if ipv4_interface:
            network["address"] = BBL_ADDRESS + "/24"
        ldp = {"instance-id": 1, "lsr-id": BBL_LSR_ID, "hold-time": 15}
        if ipv4_interface:
            ldp["ipv4-transport-address"] = BBL_ADDRESS
        else:
            ldp["no-ipv4-transport"] = True
        if ipv6:
            ldp["ipv6-transport-address"] = BBL_ADDRESS6
        config = {"interfaces": {"network": network}, "ldp": [ldp]}
        if streams:
            config["streams"] = streams
        self.bbl = BngBlaster(self.topology.a, self.tmp_path).start(config, logging=("info", "ldp"))
        self.processes.append(self.bbl)

    def bbl_sessions(self):
        return self.bbl.ctrl("ldp-sessions")["ldp-sessions"]

    def bbl_state(self):
        return [s["state"] for s in self.bbl_sessions()]

    def bbl_database(self):
        return {e["prefix"]: e for e in self.bbl.ctrl("ldp-database", **{"ldp-instance-id": 1})["ldp-database"]
                if e["active"]}

    def bbl_adjacency(self):
        return self.bbl.ctrl("ldp-adjacencies")["ldp-adjacencies"][0]

    def frr_neighbors(self):
        return self.frr.vtysh("show mpls ldp neighbor").get("neighbors", [])

    def frr_operational(self):
        return [n for n in self.frr_neighbors() if n["neighborId"] == BBL_LSR_ID and n["state"] == "OPERATIONAL"]

    def frr_remote_bindings(self):
        """Return {prefix: label} learned by FRR from the BNG Blaster."""
        return {b["prefix"]: b["remoteLabel"] for b in self.frr.vtysh("show mpls ldp binding").get("bindings", [])
                if b["neighborId"] == BBL_LSR_ID and b["remoteLabel"] != "-"}

    def frr_adjacencies(self):
        return [a for a in self.frr.vtysh("show mpls ldp discovery").get("adjacencies", [])
                if a["neighborId"] == BBL_LSR_ID]

    def wait_operational(self, timeout=30):
        wait_until(lambda: self.bbl_state() == ["operational"] and self.frr_operational(), timeout,
                   message="LDP session operational")


@pytest.fixture
def ldp(topology, processes, tmp_path):
    return LdpSetup(topology, processes, tmp_path)


def test_session_bindings(ldp):
    """Label bindings are exchanged in both directions. The BNG Blaster
    advertises its LSR-ID and interface prefix with implicit null."""
    ldp.start_frr()
    ldp.start_bbl()
    ldp.wait_operational()
    wait_until(lambda: {"10.0.0.0/24", FRR_STATIC} <= set(ldp.bbl_database()), 10,
               message="FRR bindings in BNG Blaster database")
    db = ldp.bbl_database()
    assert db["10.0.0.0/24"]["label"] == 3
    assert 16 <= db[FRR_STATIC]["label"] <= 0xFFFFF
    assert db[FRR_STATIC]["source-identifier"] == FRR_LSR_ID + ":0"
    wait_until(lambda: ldp.frr_remote_bindings() == {BBL_LSR_ID + "/32": "imp-null", "10.0.0.0/24": "imp-null"},
               10, message="BNG Blaster bindings in FRR")
    assert ldp.bbl.terminate(30) == 0


def test_ipv6(ldp):
    """Dual-stack BNG Blaster and FRR establish the session with IPv6
    transport (RFC 7552) and exchange IPv4 and IPv6 bindings. The BNG
    Blaster advertises its IPv6 addresses and prefixes."""
    ldp.start_frr(ipv6=True)
    ldp.start_bbl(ipv6=True)
    ldp.wait_operational()
    assert ldp.frr_operational()[0]["transportAddress"] == BBL_ADDRESS6
    assert ldp.bbl_sessions()[0]["local-address"] == BBL_ADDRESS6
    wait_until(lambda: ldp.frr_remote_bindings() == {
        BBL_LSR_ID + "/32": "imp-null", "10.0.0.0/24": "imp-null",
        BBL_ADDRESS6 + "/128": "imp-null", "fd00::/64": "imp-null"}, 10, message="IPv4 and IPv6 bindings in FRR")
    wait_until(lambda: {"10.0.0.0/24", FRR_STATIC, "fd00::/64"} <= set(ldp.bbl_database()), 10,
               message="FRR IPv4 and IPv6 bindings in BNG Blaster database")
    assert ldp.bbl.terminate(30) == 0


def test_ipv6_only_interface(ldp):
    """An interface without IPv4 address is not advertised as IPv4
    prefix 0.0.0.0/0 (IPv6 only BNG Blaster)."""
    ldp.start_frr(ipv4=False, ipv6=True)
    ldp.start_bbl(ipv6=True, ipv4_interface=False)
    ldp.wait_operational()
    wait_until(lambda: "fd00::/64" in ldp.frr_remote_bindings(), 10, message="IPv6 bindings in FRR")
    assert "0.0.0.0/0" not in ldp.frr_remote_bindings()
    assert ldp.bbl.terminate(30) == 0


def test_dual_stack_peer(ldp):
    """FRR is dual-stack and prefers IPv6, the IPv4 only BNG Blaster ignores
    the dual-stack capability (RFC 7552 section 6.1) and the session is
    established with IPv4 transport."""
    ldp.start_frr(ipv6=True)
    ldp.start_bbl()
    ldp.wait_operational()
    assert ldp.bbl_sessions()[0]["peer-address"] == FRR_ADDRESS
    assert ldp.bbl.terminate(30) == 0


def test_hold_time(ldp):
    """The link hello hold time is the minimum of the local (15) and the
    currently received hold time, also if the peer raises it."""
    ldp.start_frr()
    ldp.start_bbl()
    ldp.wait_operational()
    wait_until(lambda: ldp.bbl_adjacency()["hold-time"] == HOLD_TIME, 10, message="hold time %d" % HOLD_TIME)
    ldp.frr.vtysh_exec("configure terminal", "mpls ldp", "address-family ipv4", "discovery hello holdtime 10")
    wait_until(lambda: ldp.bbl_adjacency()["hold-time"] == 10, 10, message="hold time 10")
    assert ldp.bbl_adjacency()["state-transitions"] == 1
    assert ldp.bbl.terminate(30) == 0


@pytest.mark.full
def test_hello_adjacency_loss(ldp):
    """FRR hellos are dropped while the TCP connection stays up. The BNG
    Blaster terminates the session when its hello adjacency is lost
    (RFC 5036 section 2.5.5) and establishes it again with the next hello."""
    ldp.start_frr()
    ldp.start_bbl()
    ldp.wait_operational()
    wait_until(lambda: FRR_STATIC in ldp.bbl_database(), 10, message="FRR bindings")
    rule = ["OUTPUT", "-p", "udp", "--dport", "646", "-j", "DROP"]
    ldp.topology.b.exec(["iptables", "-A"] + rule)
    wait_until(lambda: ldp.bbl_state() == ["closed"], HOLD_TIME + 5, message="session closed after hold time")
    assert not ldp.bbl_database()
    # No reconnect without hello.
    time.sleep(6)
    assert ldp.bbl_state() == ["closed"]
    ldp.topology.b.exec(["iptables", "-D"] + rule)
    ldp.wait_operational(20)
    wait_until(lambda: FRR_STATIC in ldp.bbl_database(), 10, message="FRR bindings again")
    assert "hello adjacency lost" in open(ldp.bbl.path("log")).read()
    assert ldp.bbl.terminate(30) == 0


@pytest.mark.full
def test_teardown(ldp):
    """With ldp-teardown, the session is closed and the BNG Blaster stops
    sending hellos, so FRR removes the adjacency after the hold time and
    no new session is established."""
    ldp.start_frr()
    ldp.start_bbl()
    ldp.wait_operational()
    ldp.bbl.ctrl("ldp-teardown")
    wait_until(lambda: not ldp.frr_operational(), 10, message="FRR session down")
    wait_until(lambda: not ldp.frr_adjacencies(), HOLD_TIME + 5, message="FRR adjacency removed")
    tx = ldp.bbl_adjacency()["tx-discovery"]
    time.sleep(3)
    assert ldp.bbl_adjacency()["tx-discovery"] == tx
    assert ldp.bbl_state() == ["closed"] and not ldp.frr_operational()
    assert ldp.bbl.terminate(30) == 0


def test_stream_label(ldp):
    """A stream with LDP lookup of the FRR static route is sent with
    the label advertised by FRR (captured in the FRR namespace)."""
    ldp.start_frr()
    ldp.start_bbl(streams=[{"name": "S1", "type": "ipv4", "direction": "downstream", "pps": 100,
                            "network-interface": ldp.topology.if_a,
                            "destination-ipv4-address": "10.98.0.1",
                            "ldp-ipv4-lookup-address": "10.98.0.0"}])
    ldp.wait_operational()
    wait_until(lambda: FRR_STATIC in ldp.bbl_database(), 10, message="FRR bindings")
    label = ldp.bbl_database()[FRR_STATIC]["label"]
    ldp.bbl.ctrl("traffic-start")
    capture = ldp.topology.b.exec(["timeout", "10", "tcpdump", "-nn", "-c", "3", "-i", ldp.topology.if_b, "mpls"])
    assert capture.count("MPLS (label %d," % label) == 3, capture
    assert ldp.bbl.terminate(30) == 0
