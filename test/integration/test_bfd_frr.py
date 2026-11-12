"""
BNG Blaster BFD against FRR bfdd (static single-hop and multi-hop
sessions, timer negotiation, poll sequence, AdminDown, detection
timeout and the BFD clients OSPFv2, OSPFv3, IS-IS and BGP)

Namespace A runs the BNG Blaster (10.0.0.1, fd00::1, loopback
10.10.0.1), namespace B runs FRR (10.0.0.2, fd00::2, loopback
10.10.0.2). FRR bfdd has no BFD authentication, which is tested
against BIRD and between BNG Blaster instances.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import re
import time

import pytest

import helpers
from helpers import BngBlaster, Frr, Netns, wait_until
from igp_common import (BBL_ADDRESS, BBL_ADDRESS6, BBL_ROUTER_ID, BBL_SYSTEM_ID, FRR_ADDRESS, FRR_ADDRESS6,
                        FRR_ROUTER_ID, FRR_SYSTEM_ID, ISIS_AREA, IgpSetup, IsisSetup, Ospf6Setup, OspfSetup)

pytestmark = pytest.mark.usefixtures("frr_bin")

BBL_LOOPBACK6 = "fd00:10::1"
FRR_LOOPBACK6 = "fd00:10::2"
BGP_AS = 65000

# BNG Blaster profile, deliberately different from the FRR timers
# to verify the negotiation in both directions.
BBL_TX, BBL_RX, BBL_MULT = 100, 150, 3
FRR_TX, FRR_RX, FRR_MULT = 200, 300, 4
BBL_PROFILE = {"bfd-profile-id": 1, "tx-interval": BBL_TX, "rx-interval": BBL_RX,
               "multiplier": BBL_MULT}
# Expected negotiated values in ms (RFC 5880 6.8.2 - 6.8.4).
BBL_TX_INTERVAL = max(BBL_TX, FRR_RX)
BBL_DETECTION_TIME = FRR_MULT * max(BBL_RX, FRR_TX)
FRR_DETECTION_TIME = BBL_MULT * max(FRR_RX, BBL_TX)

# Margin for the detection timeout measured by polling the control socket.
DETECTION_MARGIN = 0.4


def frr_bfd_timers(indent, tx=FRR_TX, rx=FRR_RX, mult=FRR_MULT):
    return ["%sreceive-interval %d" % (indent, rx),
            "%stransmit-interval %d" % (indent, tx),
            "%sdetect-multiplier %d" % (indent, mult)]


def frr_bfd_profile():
    """FRR BFD profile bbl used by the routing protocols."""
    return "\n".join(["bfd", " profile bbl"] + frr_bfd_timers("  ") + [" exit", "exit"]) + "\n"


def frr_drop_bfd(ns, drop=True):
    """Drop (or accept again) all BFD packets sent by FRR in namespace B,
    a real BFD failure in contrast to AdminDown."""
    if drop:
        ns.exec(["nft", "add table inet bbl_bfd"])
        ns.exec(["nft", "add chain inet bbl_bfd out { type filter hook output priority 0 ; }"])
        ns.exec(["nft", "add rule inet bbl_bfd out udp dport { 3784, 4784 } drop"])
    else:
        ns.exec(["nft", "delete table inet bbl_bfd"])


def link_local(ns, ifname):
    """Kernel IPv6 link-local address of an interface (after DAD)."""
    for entry in json.loads(ns.exec(["ip", "-j", "-6", "addr", "show", "dev", ifname, "scope", "link"])):
        for addr in entry.get("addr_info", []):
            if addr.get("local") and not addr.get("tentative"):
                return addr["local"]
    return None


def bbl_link_local(ns, ifname):
    """Link-local address of the BNG Blaster network interface, derived from
    the MAC address without inverting the U/L bit (bbl_network.c)."""
    mac = json.loads(ns.exec(["ip", "-j", "link", "show", "dev", ifname]))[0]["address"]
    b = [int(x, 16) for x in mac.split(":")]
    return "fe80::%x:%x:%x:%x" % (b[0] << 8 | b[1], b[2] << 8 | 0xff, 0xfe << 8 | b[3], b[4] << 8 | b[5])


def bbl_sessions(bbl, **filters):
    return bbl.ctrl("bfd-sessions", **filters)["bfd-sessions"]


def bbl_session(bbl, **filters):
    sessions = bbl_sessions(bbl, **filters)
    assert len(sessions) == 1, sessions
    return sessions[0]


def frr_peers(frr):
    return frr.vtysh("show bfd peers")


def frr_peer(frr, peer, multihop=False):
    for entry in frr_peers(frr):
        if entry.get("peer") == peer and entry.get("multihop", False) == multihop:
            return entry
    return None


def frr_peer_status(frr, peer, multihop=False):
    entry = frr_peer(frr, peer, multihop)
    return entry and entry.get("status")


def bbl_state(bbl, peer):
    sessions = bbl_sessions(bbl, **{"peer-address": peer})
    return sessions[0]["state"] if sessions else None


def wait_bfd_up(bbl, frr, bbl_peer, frr_peer_address, multihop=False, timeout=15):
    try:
        wait_until(lambda: bbl_state(bbl, bbl_peer) == "Up" and
                   frr_peer_status(frr, frr_peer_address, multihop) == "up",
                   timeout, 0.2, message="BFD session up (%s)" % bbl_peer)
    except TimeoutError as e:
        raise TimeoutError("%s, BNG Blaster: %s, FRR: %s" % (
            e, bbl_sessions(bbl), frr_peers(frr))) from None


def wait_bbl_down(bbl, peer, timeout):
    """Poll the session until Down and return the elapsed time."""
    start = time.monotonic()
    wait_until(lambda: bbl_state(bbl, peer) == "Down", timeout, 0.02,
               message="BNG Blaster BFD session down (%s)" % peer)
    return time.monotonic() - start


def bbl_log(bbl):
    with open(bbl.path("log")) as f:
        return f.read()


class StaticSetup(IgpSetup):
    """Static BFD sessions configured on both sides."""

    logging = ("info", "bfd")

    def __init__(self, topology, processes, tmp_path):
        super().__init__(topology, processes, tmp_path)
        ns = topology.b
        ns.exec(["ip", "addr", "add", FRR_ROUTER_ID + "/32", "dev", "lo"])
        ns.exec(["ip", "-6", "addr", "add", FRR_LOOPBACK6 + "/128", "dev", "lo"])
        ns.exec(["ip", "route", "add", BBL_ROUTER_ID + "/32", "via", BBL_ADDRESS])
        ns.exec(["ip", "-6", "route", "add", BBL_LOOPBACK6 + "/128", "via", BBL_ADDRESS6])

    def start_frr(self, frr=None):
        self.frr = Frr(self.topology.b, self.tmp_path, ("bfdd",)).start(frr)
        self.processes.append(self.frr)
        return self

    def bbl_config(self, sessions=(), profile=None):
        return {
            "interfaces": {"network": {
                "interface": self.topology.if_a,
                "address": BBL_ADDRESS + "/24",
                "gateway": FRR_ADDRESS,
                "address-ipv6": BBL_ADDRESS6 + "/64",
                "gateway-ipv6": FRR_ADDRESS6,
            }},
            "bfd": [profile or BBL_PROFILE],
            "bfd-sessions": [dict(s, **{"network-interface": self.topology.if_a, "bfd-profile-id": 1})
                             for s in sessions],
        }

    def frr_peer_config(self, peer, local=None, multihop=False, extra=()):
        """FRR peer config. FRR sends from the global address to a link-local
        peer unless the local address is set, which the BNG Blaster discards
        as it does not match the session (RFC 5880 6.3)."""
        line = " peer %s" % peer
        if multihop:
            line += " local-address %s multihop" % local
        elif local:
            line += " local-address %s interface %s" % (local, self.topology.if_b)
        else:
            line += " interface %s" % self.topology.if_b
        return "\n".join(["bfd", line] + frr_bfd_timers("  ") + ["  " + e for e in extra] +
                         [" exit", "exit"]) + "\n"

    def frr_peer_exec(self, peer, local, multihop, *commands):
        line = "peer %s" % peer
        line += " local-address %s multihop" % local if multihop else " interface %s" % self.topology.if_b
        self.frr.vtysh_exec("configure terminal", "bfd", line, *commands)


@pytest.fixture
def static(topology, processes, tmp_path):
    return StaticSetup(topology, processes, tmp_path)


# (BNG Blaster session config, FRR peer, FRR local address, multi-hop)
STATIC_SESSIONS = {
    "ipv4": ({"peer-ipv4-address": FRR_ADDRESS}, BBL_ADDRESS, None, False),
    "ipv6": ({"peer-ipv6-address": FRR_ADDRESS6}, BBL_ADDRESS6, None, False),
    "ipv4-multihop": ({"local-ipv4-address": BBL_ROUTER_ID, "peer-ipv4-address": FRR_ROUTER_ID,
                       "multihop": True}, BBL_ROUTER_ID, FRR_ROUTER_ID, True),
    "ipv6-multihop": ({"local-ipv6-address": BBL_LOOPBACK6, "peer-ipv6-address": FRR_LOOPBACK6,
                       "multihop": True}, BBL_LOOPBACK6, FRR_LOOPBACK6, True),
}


def start_static(static, variant, extra=()):
    session, frr_peer_address, frr_local, multihop = STATIC_SESSIONS[variant]
    static.start(frr=static.frr_peer_config(frr_peer_address, frr_local, multihop, extra),
                 bbl={"sessions": [dict(session, name="S1")]})
    bbl_peer = session.get("peer-ipv4-address") or session.get("peer-ipv6-address")
    wait_bfd_up(static.bbl, static.frr, bbl_peer, frr_peer_address, multihop)
    return bbl_peer, frr_peer_address, frr_local, multihop


def test_static_ipv4(static):
    """Basic single-hop IPv4 session, control command filters and AdminDown
    sent on teardown."""
    bbl_peer, frr_address, _, _ = start_static(static, "ipv4")
    s = bbl_session(static.bbl)
    assert s["name"] == "S1"
    assert not s["multihop"] and s["min-ttl"] == 255
    assert s["clients"] == ["static"]
    assert s["peer-address"] == bbl_peer
    assert len(bbl_sessions(static.bbl, **{"bfd-session-id": s["bfd-session-id"]})) == 1
    assert len(bbl_sessions(static.bbl, **{"network-interface": static.topology.if_a})) == 1
    assert not bbl_sessions(static.bbl, **{"bfd-session-id": s["bfd-session-id"] + 1})
    assert not bbl_sessions(static.bbl, state="Down")
    static.teardown()
    # AdminDown on teardown (FRR keeps the configured peer).
    wait_until(lambda: frr_peer_status(static.frr, frr_address) == "down", 5,
               message="FRR peer down after teardown")
    assert frr_peer(static.frr, frr_address)["remote-diagnostic"] == "administratively down"


@pytest.mark.full
@pytest.mark.parametrize("variant", list(STATIC_SESSIONS))
def test_static_timers(static, variant):
    """Single-hop and multi-hop sessions with different intervals per side.
    The TX interval is the maximum of the own desired min TX and the remote
    required min RX, the detection time the remote multiplier times the
    maximum of the own required min RX and the remote desired min TX."""
    bbl_peer, frr_address, _, multihop = start_static(static, variant)
    # The BNG Blaster starts a poll sequence after slow start.
    wait_until(lambda: not bbl_session(static.bbl)["poll"], 5, message="poll sequence completed")
    s = bbl_session(static.bbl)
    assert s["multihop"] == multihop
    assert s["min-ttl"] == (254 if multihop else 255)
    assert s["local-address"] == STATIC_SESSIONS[variant][1]
    assert s["peer-address"] == bbl_peer
    assert s["remote-state"] == "Up"
    assert s["desired-min-tx-interval-us"] == BBL_TX * 1000
    assert s["required-min-rx-interval-us"] == BBL_RX * 1000
    assert s["remote-desired-min-tx-interval-us"] == FRR_TX * 1000
    assert s["remote-required-min-rx-interval-us"] == FRR_RX * 1000
    assert s["remote-multiplier"] == FRR_MULT
    assert s["tx-interval-us"] == BBL_TX_INTERVAL * 1000
    assert s["detection-time-us"] == BBL_DETECTION_TIME * 1000
    assert s["stats"]["rx-errors"] == 0 and s["stats"]["tx-errors"] == 0
    assert s["stats"]["up"] == 1 and s["stats"]["down"] == 0
    assert s["stats"]["poll-sequences"] == 1
    assert s["remote-discriminator"] == frr_peer(static.frr, frr_address, multihop)["id"]
    p = frr_peer(static.frr, frr_address, multihop)
    assert p["remote-id"] == s["local-discriminator"]
    assert p["remote-transmit-interval"] == BBL_TX
    assert p["remote-receive-interval"] == BBL_RX
    assert p["remote-detect-multiplier"] == BBL_MULT
    assert p["detection-timeout"] == FRR_DETECTION_TIME
    # Stable without flaps.
    time.sleep(3)
    s = bbl_session(static.bbl)
    assert s["state"] == "Up" and s["stats"]["down"] == 0
    # About one packet per TX interval (with jitter of up to 25 %).
    assert s["stats"]["rx-packets"] >= 3000 / FRR_TX
    static.teardown()
    report = static.bbl.report()["report"]["bfd"]
    assert report["sessions"] == 1 and report["sessions-up"] == 0, report
    assert report["up"] == 1 and report["timeout"] == 0, report
    assert report["rx-errors"] == 0 and report["rx-no-session"] == 0, report
    assert report["bfd-sessions"][0]["state"] == "AdminDown", report


@pytest.mark.full
def test_static_ipv6_link_local(static):
    """Single-hop session between the IPv6 link-local addresses."""
    wait_until(lambda: link_local(static.topology.b, static.topology.if_b), 5,
               message="FRR link-local address")
    frr_ll = link_local(static.topology.b, static.topology.if_b)
    bbl_ll = bbl_link_local(static.topology.a, static.topology.if_a)
    static.start(frr=static.frr_peer_config(bbl_ll, frr_ll),
                 bbl={"sessions": [{"peer-ipv6-address": frr_ll}]})
    wait_bfd_up(static.bbl, static.frr, frr_ll, bbl_ll)
    s = bbl_session(static.bbl)
    assert s["local-address"] == bbl_ll
    assert s["tx-interval-us"] == BBL_TX_INTERVAL * 1000
    static.teardown()


@pytest.mark.full
@pytest.mark.parametrize("variant", ["ipv4", "ipv6-multihop"])
def test_poll_sequence(static, variant):
    """bfd-session-update while Up starts a poll sequence (RFC 5880 6.8.3)
    and FRR applies the new remote intervals and multiplier. A timer change
    of FRR is answered with final and applied by the BNG Blaster."""
    bbl_peer, frr_address, frr_local, multihop = start_static(static, variant)
    wait_until(lambda: not bbl_session(static.bbl)["poll"], 5, message="initial poll sequence completed")
    polls = bbl_session(static.bbl)["stats"]["poll-sequences"]

    result = static.bbl.ctrl("bfd-session-update", **{"peer-address": bbl_peer, "tx-interval": 300,
                                                      "rx-interval": 400, "multiplier": 5})
    assert result["code"] == 200, result
    wait_until(lambda: (lambda p: p["remote-transmit-interval"] == 300 and
                        p["remote-receive-interval"] == 400 and
                        p["remote-detect-multiplier"] == 5)(frr_peer(static.frr, frr_address, multihop)),
               5, 0.2, message="FRR remote intervals updated")
    wait_until(lambda: not bbl_session(static.bbl)["poll"], 5, message="poll sequence completed")
    s = bbl_session(static.bbl)
    assert s["stats"]["poll-sequences"] == polls + 1
    assert s["desired-min-tx-interval-us"] == 300000
    assert s["required-min-rx-interval-us"] == 400000
    assert s["multiplier"] == 5
    assert s["tx-interval-us"] == max(300, FRR_RX) * 1000
    assert s["detection-time-us"] == FRR_MULT * max(400, FRR_TX) * 1000
    wait_until(lambda: frr_peer(static.frr, frr_address, multihop)["detection-timeout"] == 5 * max(FRR_RX, 300),
               5, 0.2, message="FRR detection timeout updated")
    assert s["state"] == "Up" and s["stats"]["down"] == 0

    # Poll sequence started by FRR.
    rx = s["stats"]["rx-packets"]
    static.frr_peer_exec(frr_address, frr_local, multihop, "transmit-interval 500", "receive-interval 600")
    wait_until(lambda: bbl_session(static.bbl)["remote-desired-min-tx-interval-us"] == 500000, 5, 0.2,
               message="BNG Blaster remote desired min TX updated")
    wait_until(lambda: bbl_session(static.bbl)["detection-time-us"] == FRR_MULT * 500 * 1000, 5, 0.2,
               message="BNG Blaster detection time updated")
    s = bbl_session(static.bbl)
    assert s["remote-required-min-rx-interval-us"] == 600000
    assert s["tx-interval-us"] == 600000
    assert s["stats"]["rx-packets"] > rx
    time.sleep(3)
    s = bbl_session(static.bbl)
    assert s["state"] == "Up" and s["stats"]["down"] == 0, s
    assert frr_peer_status(static.frr, frr_address, multihop) == "up"
    static.teardown()


@pytest.mark.full
@pytest.mark.parametrize("variant", ["ipv4", "ipv6", "ipv4-multihop"])
def test_admin_down(static, variant):
    """AdminDown in both directions: bfd-session-disable is signaled to
    FRR, FRR shutdown is signaled to the BNG Blaster (diagnostic neighbor
    signaled session down), both sessions come up again after enable."""
    bbl_peer, frr_address, frr_local, multihop = start_static(static, variant)
    bbl, frr = static.bbl, static.frr

    assert bbl.ctrl("bfd-session-disable", **{"peer-address": bbl_peer})["code"] == 200
    s = bbl_session(bbl)
    assert s["state"] == "AdminDown" and s["admin-state"] == "disabled"
    assert s["local-diagnostic"] == "administratively-down"
    wait_until(lambda: frr_peer_status(frr, frr_address, multihop) == "down", 3, 0.1,
               message="FRR peer down")
    assert frr_peer(frr, frr_address, multihop)["remote-diagnostic"] == "administratively down"
    time.sleep(BBL_DETECTION_TIME * 2 / 1000)
    # No detection timeout while AdminDown.
    s = bbl_session(bbl)
    assert s["state"] == "AdminDown" and s["stats"]["timeout"] == 0
    assert bbl.ctrl("bfd-session-enable", **{"peer-address": bbl_peer})["code"] == 200
    wait_bfd_up(bbl, frr, bbl_peer, frr_address, multihop)
    assert bbl_session(bbl)["admin-state"] == "enabled"

    static.frr_peer_exec(frr_address, frr_local, multihop, "shutdown")
    wait_until(lambda: bbl_state(bbl, bbl_peer) == "Down", 3, 0.1, message="BNG Blaster session down")
    s = bbl_session(bbl)
    assert s["remote-state"] == "AdminDown"
    assert s["local-diagnostic"] == "neighbor-signaled-session-down"
    assert s["remote-diagnostic"] == "administratively-down"
    # The session stays Down (no Init) and does not time out.
    time.sleep(BBL_DETECTION_TIME * 2 / 1000 + 1)
    s = bbl_session(bbl)
    assert s["state"] == "Down" and s["stats"]["timeout"] == 0, s
    static.frr_peer_exec(frr_address, frr_local, multihop, "no shutdown")
    wait_bfd_up(bbl, frr, bbl_peer, frr_address, multihop)
    s = bbl_session(bbl)
    # Local AdminDown (disable) is not counted as down, the peer AdminDown is.
    assert s["stats"]["up"] == 3 and s["stats"]["down"] == 1, s
    static.teardown()


@pytest.mark.full
def test_admin_down_all(static):
    """bfd-session-disable and -enable without filter apply to all sessions."""
    sessions = [STATIC_SESSIONS[v][0] for v in ("ipv4", "ipv6", "ipv4-multihop")]
    frr = "".join(static.frr_peer_config(STATIC_SESSIONS[v][1], STATIC_SESSIONS[v][2], STATIC_SESSIONS[v][3])
                  for v in ("ipv4", "ipv6", "ipv4-multihop"))
    static.start(frr=frr, bbl={"sessions": sessions})
    wait_until(lambda: [s["state"] for s in bbl_sessions(static.bbl)] == ["Up"] * 3, 15, 0.2,
               message="all sessions up")
    static.bbl.ctrl("bfd-session-disable")
    assert {s["state"] for s in bbl_sessions(static.bbl)} == {"AdminDown"}
    assert bbl_sessions(static.bbl, state="AdminDown") and not bbl_sessions(static.bbl, state="Up")
    wait_until(lambda: {p["status"] for p in frr_peers(static.frr)} == {"down"}, 3, 0.1,
               message="all FRR peers down")
    static.bbl.ctrl("bfd-session-enable")
    wait_until(lambda: {p["status"] for p in frr_peers(static.frr)} == {"up"} and
               {s["state"] for s in bbl_sessions(static.bbl)} == {"Up"}, 15, 0.2,
               message="all sessions up again")
    static.teardown()


@pytest.mark.full
@pytest.mark.parametrize("variant", ["ipv4", "ipv6", "ipv4-multihop"])
def test_detection_timeout(static, variant):
    """FRR stops sending: the BNG Blaster session goes down within the
    detection time with diagnostic control detection time expired and
    signals this to FRR, which goes down with neighbor signaled session down."""
    bbl_peer, frr_address, _, multihop = start_static(static, variant)
    bbl, frr = static.bbl, static.frr
    wait_until(lambda: not bbl_session(bbl)["poll"], 5, message="poll sequence completed")
    detection_time = bbl_session(bbl)["detection-time-us"] / 1e6
    assert detection_time == BBL_DETECTION_TIME / 1000

    frr_drop_bfd(static.topology.b)
    elapsed = wait_bbl_down(bbl, bbl_peer, 5)
    assert elapsed <= detection_time + DETECTION_MARGIN, (elapsed, detection_time)
    s = bbl_session(bbl)
    assert s["local-diagnostic"] == "control-detection-time-expired"
    assert s["stats"]["timeout"] == 1 and s["stats"]["down"] == 1
    assert s["remote-discriminator"] == 0
    # FRR ignores packets with your discriminator zero while it knows the
    # remote discriminator ("'remote discriminator' is zero, not overridden"),
    # so it does not see the Down state (diagnostic neighbor signaled session
    # down) but detects the failure by its own detection timeout.
    wait_until(lambda: frr_peer(frr, frr_address, multihop)["diagnostic"] in
               ("neighbor signaled session down", "control detection time expired"),
               FRR_DETECTION_TIME / 1000 + 1, 0.1, message="FRR peer down")
    assert frr_peer_status(frr, frr_address, multihop) != "up"
    # Down while the peer is silent, no further timeouts.
    time.sleep(3)
    s = bbl_session(bbl)
    assert s["state"] == "Down" and s["stats"]["timeout"] == 1, s

    frr_drop_bfd(static.topology.b, drop=False)
    wait_bfd_up(bbl, frr, bbl_peer, frr_address, multihop)
    static.teardown()


@pytest.mark.full
def test_detection_timeout_bfdd_killed(static):
    """bfdd killed (no AdminDown sent): detection timeout."""
    bbl_peer, _, _, _ = start_static(static, "ipv4")
    wait_until(lambda: not bbl_session(static.bbl)["poll"], 5, message="poll sequence completed")
    bfdd = static.frr.procs[static.frr.daemons.index("bfdd")]
    bfdd.kill()
    bfdd.wait(5)
    elapsed = wait_bbl_down(static.bbl, bbl_peer, 5)
    assert elapsed <= BBL_DETECTION_TIME / 1000 + DETECTION_MARGIN, elapsed
    assert bbl_session(static.bbl)["local-diagnostic"] == "control-detection-time-expired"
    static.teardown()


# Protocol bindings

class BfdClientMixin:
    """BFD profile 1 on the BNG Blaster network interface and FRR BFD
    profile bbl for the protocol (added to the FRR config by frr_bfd())."""

    bbl_bfd_key = None
    client = None

    def start_frr(self, frr=None):
        config = frr_bfd_profile() + self.frr_config(**(frr or {})) + self.frr_bfd()
        self.frr = Frr(self.topology.b, self.tmp_path, (self.daemon, "bfdd")).start(config)
        self.processes.append(self.frr)
        return self

    def bbl_config(self, **kwargs):
        config = super().bbl_config(**kwargs)
        config["bfd"] = [BBL_PROFILE]
        config["interfaces"]["network"][self.bbl_bfd_key] = 1
        return config

    def frr_bfd_profile_exec(self, *commands):
        self.frr.vtysh_exec("configure terminal", "bfd", "profile bbl", *commands)

    def bbl_peer(self):
        """Peer address of the BFD session on the BNG Blaster."""
        return FRR_ADDRESS

    def frr_peer_address(self):
        return BBL_ADDRESS

    def protocol_down_log(self):
        """Log pattern of the protocol brought down by BFD."""
        raise NotImplementedError


class BfdOspfSetup(BfdClientMixin, OspfSetup):
    logging = ("info", "ospf", "bfd")
    bbl_bfd_key = "ospfv2-bfd-profile-id"
    client = "ospfv2"

    def frr_bfd(self):
        return "interface %s\n ip ospf bfd\n ip ospf bfd profile bbl\nexit\n" % self.topology.if_b

    def protocol_up(self):
        return self.established()

    def protocol_down_log(self):
        return r"OSPFv2 neighbor %s state \S+ -> Down" % FRR_ROUTER_ID

    def bbl_teardown_protocol(self):
        self.bbl.ctrl("ospf-teardown")


class BfdOspf6Setup(BfdClientMixin, Ospf6Setup):
    logging = ("info", "ospf", "bfd")
    bbl_bfd_key = "ospfv3-bfd-profile-id"
    client = "ospfv3"

    def frr_bfd(self):
        return "interface %s\n ipv6 ospf6 bfd\n ipv6 ospf6 bfd profile bbl\nexit\n" % self.topology.if_b

    def bbl_peer(self):
        return link_local(self.topology.b, self.topology.if_b)

    def frr_peer_address(self):
        return bbl_link_local(self.topology.a, self.topology.if_a)

    def protocol_up(self):
        return self.established()

    def protocol_down_log(self):
        return r"OSPFv3 neighbor %s state \S+ -> Down" % FRR_ROUTER_ID

    def bbl_teardown_protocol(self):
        self.bbl.ctrl("ospf-teardown")


class BfdIsisSetup(BfdClientMixin, IsisSetup):
    """IS-IS for IPv4 only on FRR (BFD to the IPv4 interface address of
    TLV 132) or IPv6 only (BFD to the IPv6 link-local address of TLV 232).
    With both, FRR uses IPv6 only for BFD (see test_isis_dual_stack)."""

    logging = ("info", "isis", "bfd")
    bbl_bfd_key = "isis-bfd-profile-id"
    client = "isis"
    af = "ipv4"

    def frr_config(self, **kwargs):
        skip = {"ipv4": " ipv6 router isis bbl", "ipv6": " ip router isis bbl", None: None}[self.af]
        return "\n".join(l for l in super().frr_config(**kwargs).split("\n") if l != skip)

    def bbl_peer(self):
        return FRR_ADDRESS if self.af == "ipv4" else link_local(self.topology.b, self.topology.if_b)

    def frr_peer_address(self):
        return BBL_ADDRESS if self.af == "ipv4" else bbl_link_local(self.topology.a, self.topology.if_a)

    def frr_bfd(self):
        return "interface %s\n isis bfd\n isis bfd profile bbl\nexit\n" % self.topology.if_b

    def protocol_up(self):
        return self.established(1)

    def protocol_down_log(self):
        return r"ISIS L1 adjacency DOWN .*\(BFD down\)"

    def bbl_teardown_protocol(self):
        self.bbl.ctrl("isis-teardown")


class BfdIsis6Setup(BfdIsisSetup):
    af = "ipv6"


class BfdIsisDualSetup(BfdIsisSetup):
    af = None


class BfdBgpSetup(BfdClientMixin, IgpSetup):
    """iBGP over the link (single-hop BFD) or between the loopbacks
    (multi-hop BFD, BNG Blaster default for peers not connected)."""

    daemon = "bgpd"
    logging = ("info", "bgp", "bfd")
    client = "bgp"
    loopback = False

    def __init__(self, topology, processes, tmp_path):
        super().__init__(topology, processes, tmp_path)
        if self.loopback:
            ns = topology.b
            ns.exec(["ip", "addr", "add", FRR_ROUTER_ID + "/32", "dev", "lo"])
            ns.exec(["ip", "route", "add", BBL_ROUTER_ID + "/32", "via", BBL_ADDRESS])

    def bbl_peer(self):
        return FRR_ROUTER_ID if self.loopback else FRR_ADDRESS

    def frr_peer_address(self):
        return BBL_ROUTER_ID if self.loopback else BBL_ADDRESS

    def frr_config(self):
        peer = self.frr_peer_address()
        lines = [
            "router bgp %d" % BGP_AS,
            " bgp router-id %s" % FRR_ROUTER_ID,
            " no bgp ebgp-requires-policy",
            " timers bgp 3 9",
            " neighbor %s remote-as %d" % (peer, BGP_AS),
            " neighbor %s timers connect 1" % peer,
        ]
        if self.loopback:
            lines.append(" neighbor %s update-source %s" % (peer, FRR_ROUTER_ID))
        return "\n".join(lines + ["exit"]) + "\n"

    def frr_bfd(self):
        peer = self.frr_peer_address()
        return "router bgp %d\n neighbor %s bfd\n neighbor %s bfd profile bbl\nexit\n" % (BGP_AS, peer, peer)

    def bbl_config(self):
        return {
            "interfaces": {"network": {
                "interface": self.topology.if_a,
                "address": BBL_ADDRESS + "/24",
                "gateway": FRR_ADDRESS,
            }},
            "bfd": [BBL_PROFILE],
            "bgp": [{
                "network-interface": self.topology.if_a,
                "local-ipv4-address": self.frr_peer_address(),
                "peer-ipv4-address": self.bbl_peer(),
                "local-as": BGP_AS,
                "peer-as": BGP_AS,
                "hold-time": 9,
                "reconnect": True,
                "bfd-profile-id": 1,
            }],
        }

    def bbl_bgp(self):
        return self.bbl.ctrl("bgp-sessions")["bgp-sessions"]

    def frr_bgp_neighbor(self):
        peer = self.frr_peer_address()
        return self.frr.vtysh("show bgp neighbors %s" % peer).get(peer, {})

    def protocol_up(self):
        sessions = self.bbl_bgp()
        return (len(sessions) == 1 and sessions[0]["state"] == "established" and
                self.frr_bgp_neighbor().get("bgpState") == "Established")

    def protocol_down_log(self):
        return r"BGP \(.*\) state changed from established -> closing"

    def bbl_teardown_protocol(self):
        self.bbl.ctrl("bgp-teardown")


class BfdBgpLoopbackSetup(BfdBgpSetup):
    loopback = True


PROTOCOLS = {
    "ospfv2": BfdOspfSetup,
    "ospfv3": BfdOspf6Setup,
    "isis-ipv4": BfdIsisSetup,
    "isis-ipv6": BfdIsis6Setup,
    "bgp": BfdBgpSetup,
    "bgp-multihop": BfdBgpLoopbackSetup,
}


@pytest.fixture(params=list(PROTOCOLS))
def client(request, topology, processes, tmp_path):
    return PROTOCOLS[request.param](topology, processes, tmp_path)


def start_client(client):
    client.start()
    if client.client == "ospfv3" or isinstance(client, BfdIsis6Setup):
        wait_until(lambda: link_local(client.topology.b, client.topology.if_b), 5,
                   message="FRR link-local address")
    wait_until(client.protocol_up, 30, message="%s up" % client.client)
    wait_bfd_up(client.bbl, client.frr, client.bbl_peer(), client.frr_peer_address(),
                multihop=client.client == "bgp" and client.loopback)
    s = bbl_session(client.bbl)
    assert s["clients"] == [client.client]
    assert s["multihop"] == (client.client == "bgp" and client.loopback)
    assert s["peer-address"] == client.bbl_peer()
    return s


def protocol_down_count(client):
    return len(re.findall(client.protocol_down_log(), bbl_log(client.bbl)))


@pytest.mark.full
def test_client_bfd_failure(client):
    """The session is created when the protocol comes up, a real BFD
    failure (detection timeout) brings the protocol down immediately."""
    start_client(client)
    bbl = client.bbl
    assert protocol_down_count(client) == 0

    frr_drop_bfd(client.topology.b)
    wait_until(lambda: protocol_down_count(client) > 0, BBL_DETECTION_TIME / 1000 + 1, 0.05,
               message="%s down by BFD" % client.client)
    assert re.search(r"BFD \(.*\) detection time expired", bbl_log(bbl))
    if client.client == "bgp":
        # Cease with subcode BFD Down (RFC 9384).
        wait_until(lambda: "Cease" in client.frr_bgp_neighbor().get("lastNotificationReason", ""),
                   5, message="FRR received Cease")
        neighbor = client.frr_bgp_neighbor()
        assert neighbor["lastNotificationReason"] == "Cease/BFD Down", neighbor
    # The protocol comes up again without BFD (FRR does not wait for BFD).
    frr_drop_bfd(client.topology.b, drop=False)
    wait_until(client.protocol_up, 30, message="%s up again" % client.client)
    wait_bfd_up(bbl, client.frr, client.bbl_peer(), client.frr_peer_address(),
                multihop=client.client == "bgp" and client.loopback)
    client.teardown()


@pytest.mark.full
def test_client_peer_admin_down(client):
    """FRR shutdown of the BFD session (AdminDown) must not bring the
    protocol down (RFC 5882 3.2)."""
    start_client(client)
    bbl = client.bbl
    client.frr_bfd_profile_exec("shutdown")
    wait_until(lambda: bbl_state(bbl, client.bbl_peer()) == "Down", 3, 0.1,
               message="BNG Blaster BFD session down")
    s = bbl_session(bbl)
    assert s["remote-state"] == "AdminDown"
    assert s["local-diagnostic"] == "neighbor-signaled-session-down"
    # Longer than the BFD detection time.
    time.sleep(3)
    assert client.protocol_up()
    assert protocol_down_count(client) == 0
    client.frr_bfd_profile_exec("no shutdown")
    wait_bfd_up(bbl, client.frr, client.bbl_peer(), client.frr_peer_address(),
                multihop=client.client == "bgp" and client.loopback)
    assert client.protocol_up()
    assert protocol_down_count(client) == 0
    client.teardown()


@pytest.mark.full
def test_client_protocol_down(client):
    """The session is deleted when the protocol goes down normally
    (teardown by control command), signaled with AdminDown to FRR."""
    start_client(client)
    client.bbl_teardown_protocol()
    wait_until(lambda: not bbl_sessions(client.bbl), 15, 0.2, message="BFD session deleted")
    assert re.search(r"BFD \(.*\) delete session", bbl_log(client.bbl))
    assert "detection time expired" not in bbl_log(client.bbl)
    client.teardown()


@pytest.mark.full
def test_isis_dual_stack(topology, processes, tmp_path):
    """IS-IS for IPv4 and IPv6: the BNG Blaster starts one BFD session per
    address family (RFC 6213), FRR isisd uses the IPv6 link-local address
    only, which comes up while the IPv4 session stays down."""
    client = BfdIsisDualSetup(topology, processes, tmp_path)
    client.start()
    wait_until(client.protocol_up, 30, message="isis up")

    def ipv6_up():
        sessions = bbl_sessions(client.bbl)
        return [s for s in sessions if s["peer-address"].startswith("fe80:") and
                s["state"] == "Up" and "isis" in s["clients"]]
    wait_until(lambda: len(bbl_sessions(client.bbl)) == 2, 10, 0.2, message="two BFD sessions")
    wait_until(ipv6_up, 10, 0.2, message="IPv6 link-local BFD session up")


FRR2_SYSTEM_ID = "1921.6800.1003"


def frr_isis_lan_config(ifname, system_id, priority):
    return frr_bfd_profile() + "\n".join([
        "router isis bbl",
        " net %s.%s.00" % (ISIS_AREA, system_id),
        " is-type level-2-only",
        " metric-style wide",
        " no hostname dynamic",
        "exit",
        "interface %s" % ifname,
        " ip router isis bbl",
        " isis circuit-type level-2-only",
        " isis hello-interval 1",
        " isis hello-multiplier 10",
        " isis priority %d level-2" % priority,
        " isis bfd",
        " isis bfd profile bbl",
        "exit",
    ]) + "\n"


@pytest.mark.full
def test_isis_lan_bfd_per_neighbor(topology, processes, tmp_path):
    """IS-IS on a LAN with two FRR neighbors: the BNG Blaster runs one BFD
    session per neighbor, and the BFD failure of one neighbor brings down
    only this neighbor, not the other one."""
    n = topology.if_a[3:-1]
    ns_b = topology.b
    ns_b.exec(["ip", "link", "add", "br0", "type", "bridge", "stp_state", "0", "mcast_snooping", "0"])
    ns_b.exec(["ip", "link", "set", "br0", "up"])
    ns_b.exec(["ip", "link", "set", topology.if_b, "master", "br0"])
    namespaces, frrs, addresses = [], [], []
    try:
        for i, (tag, system_id, priority) in enumerate((("c", FRR_SYSTEM_ID, 64), ("d", FRR2_SYSTEM_ID, 50))):
            ns = Netns("%s-%s" % (n, tag))
            namespaces.append(ns)
            ifname = "bbl%s%s" % (n, tag)
            helpers.veth_pair(ns, ifname, ns_b, ifname + "b")
            ns_b.exec(["ip", "link", "set", ifname + "b", "master", "br0"])
            addresses.append("10.0.0.%d" % (i + 2))
            helpers.kernel_address(ns, ifname, addresses[-1] + "/24")
            workdir = tmp_path / ("frr%d" % (i + 1))
            workdir.mkdir()
            frr = Frr(ns, workdir, ("isisd", "bfdd"))
            processes.append(frr)
            frrs.append(frr.start(frr_isis_lan_config(ifname, system_id, priority)))

        bbl = BngBlaster(topology.a, tmp_path).start({
            "interfaces": {"network": {
                "interface": topology.if_a, "address": BBL_ADDRESS + "/24",
                "gateway": addresses[0], "isis-instance-id": 1, "isis-level": 2,
                "isis-p2p": False, "isis-l2-priority": 100, "isis-bfd-profile-id": 1}},
            "bfd": [BBL_PROFILE],
            "isis": [{"instance-id": 1, "level": 2, "area": ["%s/24" % ISIS_AREA],
                      "system-id": BBL_SYSTEM_ID, "router-id": BBL_ROUTER_ID,
                      "hostname": "BBL", "hello-interval": 1, "hold-time": 10}]},
            logging=("info", "isis", "bfd"))
        processes.append(bbl)

        def up_peers():
            return sorted(s["peer-address"] for s in bbl_sessions(bbl)
                          if s["state"] == "Up" and "isis" in s["clients"])
        wait_until(lambda: up_peers() == addresses, 40, 0.5, message="BFD up to both LAN neighbors")

        def session(address):
            return [s for s in bbl_sessions(bbl) if s["peer-address"] == address][0]
        frr2_session_id = session(addresses[1])["bfd-session-id"]

        # bfdd of FRR1 fails while its IS-IS adjacency (isisd) stays.
        bfdd = frrs[0].procs[frrs[0].daemons.index("bfdd")]
        bfdd.kill()
        bfdd.wait(5)
        wait_until(lambda: session(addresses[0])["state"] != "Up", 5, 0.1, message="BFD to FRR1 down")
        time.sleep(2)
        # The session of FRR2 was never deleted (FRR2 not brought down).
        s = session(addresses[1])
        assert (s["bfd-session-id"], s["state"], s["stats"]["down"]) == (frr2_session_id, "Up", 0), s
        assert bbl.terminate() == 0
        log = bbl_log(bbl)
        assert "ISIS L2 BFD down to %s" % FRR_SYSTEM_ID in log
        assert "BFD down to %s" % FRR2_SYSTEM_ID not in log
    finally:
        for ns in namespaces:
            ns.delete()
