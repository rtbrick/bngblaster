"""
BNG Blaster BFD against BIRD (single-hop IPv4/IPv6, multi-hop,
authentication, timer negotiation, poll sequence, AdminDown,
detection timeout and OSPFv2 as BFD client)

Namespace A runs the BNG Blaster (10.0.0.1, fd00::1, loopback
10.10.0.1 for multi-hop), namespace B runs BIRD on the kernel
interface (10.0.0.2, fd00::2, loopback 10.10.0.2 with a route
to 10.10.0.1 via the BNG Blaster).

BIRD quirks covered here:
* Multi-hop packets are sent with the default TTL 64 instead of 255,
  so the BNG Blaster needs a lower min-ttl than the default 254.
* BIRD never signals AdminDown: disable of the protocol or removal
  of a neighbor silently stops the session (detection timeout on
  the BNG Blaster).
* BIRD sends the poll bit also in state Down after the remote
  system went AdminDown (slow TX interval change), which the
  BNG Blaster discards in AdminDown (RFC 5880 6.8.6).
* BIRD uses kernel ephemeral source ports (32768-60999, e.g. 33110),
  RFC 5881/5883 require 49152-65535, the BNG Blaster doesn't check.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import re
import time

import pytest

import helpers
from helpers import BngBlaster, Bird, wait_until

BBL_ADDRESS = "10.0.0.1"
BBL_ADDRESS6 = "fd00::1"
BBL_LOOPBACK = "10.10.0.1"
BIRD_ADDRESS = "10.0.0.2"
BIRD_ADDRESS6 = "fd00::2"
BIRD_LOOPBACK = "10.10.0.2"
BBL_ROUTER_ID = BBL_LOOPBACK
BIRD_ROUTER_ID = BIRD_LOOPBACK

# Session name -> (BNG Blaster peer address, BIRD neighbor address).
SESSIONS = {
    "ipv4": (BIRD_ADDRESS, BBL_ADDRESS),
    "ipv6": (BIRD_ADDRESS6, BBL_ADDRESS6),
    "multihop": (BIRD_LOOPBACK, BBL_LOOPBACK),
}
# BIRD sends multi-hop packets with TTL 64.
MULTIHOP_MIN_TTL = 64

AUTH_KEY = "BFD-secret-key"
# BNG Blaster authentication type -> BIRD authentication.
BIRD_AUTH = {
    "simple": "simple",
    "keyed-md5": "keyed md5",
    "meticulous-keyed-md5": "meticulous keyed md5",
    "keyed-sha1": "keyed sha1",
    "meticulous-keyed-sha1": "meticulous keyed sha1",
}
AUTH_TYPES = list(BIRD_AUTH)

pytestmark = pytest.mark.usefixtures("bird_bin")


def bird_seconds(value):
    """Return microseconds of a BIRD time value (e.g. 0.300)."""
    return int(round(float(value) * 1000000))


class BfdSetup:
    """BIRD protocol bfd in namespace B and the BNG Blaster with static
    BFD sessions (or OSPFv2 with BFD) in namespace A."""

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.bird = None
        self.bbl = None
        self.bird_args = {}
        self.bird_details = None  # 'show bfd sessions all' (BIRD >= 2.15)
        helpers.kernel_address(topology.b, topology.if_b,
                               BIRD_ADDRESS + "/24", BIRD_ADDRESS6 + "/64")
        topology.b.exec(["ip", "addr", "add", BIRD_LOOPBACK + "/32", "dev", "lo"])
        topology.b.exec(["ip", "route", "add", BBL_LOOPBACK + "/32", "via", BBL_ADDRESS])

    # BIRD

    def start_bird(self, **args):
        """Start BIRD, see bird_config for args."""
        self.bird_args = args
        self.bird = Bird(self.topology.b, self.tmp_path).start(self.bird_config())
        self.processes.append(self.bird)
        return self

    @staticmethod
    def bird_options(opts):
        """BIRD interface/multihop options: tx, rx (ms), multiplier,
        passive and auth tuple (type, key, key ID)."""
        lines = []
        if "tx" in opts:
            lines.append("min tx interval %d ms;" % opts["tx"])
        if "rx" in opts:
            lines.append("min rx interval %d ms;" % opts["rx"])
        if "multiplier" in opts:
            lines.append("multiplier %d;" % opts["multiplier"])
        if opts.get("passive"):
            lines.append("passive yes;")
        auth = opts.get("auth")
        if auth:
            auth_type, key, key_id = auth
            lines.append("authentication %s;" % BIRD_AUTH[auth_type])
            lines.append("password \"%s\" { id %d; };" % (key, key_id))
        return lines

    def bird_config(self):
        """Return BIRD config with static neighbors (names of SESSIONS)
        and optionally OSPFv2 with BFD."""
        args = self.bird_args
        options = self.bird_options(args)
        lines = [
            "router id %s;" % BIRD_ROUTER_ID,
            "log stderr all;",
            "protocol device { scan time 1; }",
            "protocol bfd bfd1 {",
            "  debug all;",
            "  interface \"%s\" {" % self.topology.if_b,
        ]
        lines += ["    " + l for l in options]
        lines += ["  };", "  multihop {"]
        lines += ["    " + l for l in options]
        lines.append("  };")
        for name in args.get("neighbors", ("ipv4",)):
            # Single-hop neighbor given as (local, peer) or name of SESSIONS.
            local, peer = name if isinstance(name, tuple) else SESSIONS[name]
            if name == "multihop":
                lines.append("  neighbor %s local %s multihop yes;" % (peer, local))
            else:
                lines.append("  neighbor %s dev \"%s\" local %s;" % (peer, self.topology.if_b, local))
        lines.append("}")
        if args.get("ospf"):
            lines += [
                "protocol ospf v2 ospf1 {",
                "  ipv4 { import all; export none; };",
                "  area 0 {",
                "    interface \"%s\" {" % self.topology.if_b,
                "      type ptp;",
                "      hello 1; dead 10; wait 4;",
                "      bfd yes;",
                "    };",
                "  };",
                "}",
            ]
        return "\n".join(lines) + "\n"

    def bird_reconfigure(self, **args):
        self.bird_args.update(args)
        (self.tmp_path / "bird.conf").write_text(self.bird_config())
        out = self.bird.birdc("configure")
        assert any("Reconfigured" in l for l in out), out

    def bird_sessions(self):
        """Return BIRD BFD sessions by address from 'show bfd sessions all'
        (session table only before BIRD 2.15, see bird_details),
        keys as shown by BIRD, prefixed with local/remote for the local
        and remote parameters (e.g. 'remote min tx interval')."""
        if self.bird_details is not False:
            try:
                lines = self.bird.birdc("show bfd sessions all")
                self.bird_details = True
            except RuntimeError:
                if self.bird_details:
                    raise
                self.bird_details = False
        if not self.bird_details:
            return self.bird_sessions_table()
        sessions, session, prefix = {}, None, ""
        for line in lines:
            if ":" not in line:
                continue
            key, value = (s.strip() for s in line.split(":", 1))
            key = key.lower()
            if key == "address":
                session, prefix = {}, ""
                sessions[value] = session
            elif session is None:
                continue
            elif key in ("local parameters", "remote parameters"):
                prefix = key.split()[0] + " "
            else:
                session[prefix + key] = value
        return sessions

    def bird_sessions_table(self):
        """BIRD before 2.15 has only the session table (address, interface,
        state, since, interval, timeout), the interval and timeout are
        returned in the format of the detailed output (e.g. '- / 0.300')."""
        sessions = {}
        for line in self.bird.birdc("show bfd sessions"):
            fields = line.split()
            if len(fields) < 5 or fields[0] == "IP" or fields[0].endswith(":"):
                continue
            sessions[fields[0]] = {"session state": fields[2],
                                   "transmit timer": "- / " + fields[-2],
                                   "detect timer": "- / " + fields[-1]}
        return sessions

    def bird_session(self, address):
        return self.bird_sessions().get(address)

    def bird_state(self, address):
        session = self.bird_session(address)
        return session["session state"] if session else None

    def bird_log(self):
        return (self.tmp_path / "bird.log").read_text()

    def bird_drop_bfd(self, drop=True):
        """Drop (or accept again) BFD packets sent by BIRD."""
        ns = self.topology.b
        if drop:
            ns.exec(["nft", "add", "table", "inet", "bbl"])
            ns.exec(["nft", "add", "chain", "inet", "bbl", "out",
                     "{ type filter hook output priority 0 ; }"])
            ns.exec(["nft", "add", "rule", "inet", "bbl", "out",
                     "udp", "dport", "{ 3784, 4784 }", "drop"])
        else:
            ns.exec(["nft", "delete", "table", "inet", "bbl"])

    # BNG Blaster

    def start_bbl(self, profile=None, sessions=("ipv4",), ospf=False):
        """Start the BNG Blaster with BFD profile 1 (dict merged into
        the defaults) and static sessions (names of SESSIONS)."""
        bbl_profile = {"bfd-profile-id": 1, "tx-interval": 300, "rx-interval": 300, "multiplier": 3}
        bbl_profile.update(profile or {})
        network = {
            "interface": self.topology.if_a,
            "address": BBL_ADDRESS + "/24",
            "gateway": BIRD_ADDRESS,
            "address-ipv6": BBL_ADDRESS6 + "/64",
            "gateway-ipv6": BIRD_ADDRESS6,
        }
        config = {"interfaces": {"network": network}, "bfd": [bbl_profile]}
        bfd_sessions = []
        for name in sessions:
            if isinstance(name, dict):
                bfd_sessions.append(name)
                continue
            local, peer = SESSIONS[name][1], SESSIONS[name][0]
            af = "ipv6" if ":" in local else "ipv4"
            bfd_sessions.append({
                "network-interface": self.topology.if_a,
                "local-%s-address" % af: local,
                "peer-%s-address" % af: peer,
                "multihop": name == "multihop",
                "bfd-profile-id": 1,
                "name": name,
            })
        if bfd_sessions:
            config["bfd-sessions"] = bfd_sessions
        logging = ("info", "bfd")
        if ospf:
            network.update({
                "ospfv2-instance-id": 1,
                "ospfv2-type": "p2p",
                "ospfv2-bfd-profile-id": 1,
            })
            config["ospf"] = [{
                "instance-id": 1,
                "version": 2,
                "router-id": BBL_ROUTER_ID,
                "hostname": "BBL",
                "hello-interval": 1,
                "dead-interval": 10,
            }]
            logging += ("ospf",)
        self.bbl = BngBlaster(self.topology.a, self.tmp_path).start(config, logging=logging)
        self.processes.append(self.bbl)
        return self

    def bbl_sessions(self, **filters):
        response = self.bbl.ctrl("bfd-sessions", **filters)
        assert response["status"] == "ok", response
        return response["bfd-sessions"]

    def bbl_session(self, name):
        for session in self.bbl_sessions():
            if session["name"] == name:
                return session
        return None

    def bbl_state(self, name):
        session = self.bbl_session(name)
        return session["state"] if session else None

    def bbl_ctrl(self, command, name, **arguments):
        """Run session command for the named session."""
        arguments["bfd-session-id"] = self.bbl_session(name)["bfd-session-id"]
        response = self.bbl.ctrl(command, **arguments)
        assert response["status"] == "ok", response
        return response

    def bbl_log(self):
        with open(self.bbl.path("log")) as f:
            return f.read()

    def up(self, names):
        return all(self.bbl_state(name) == "Up" and self.bird_state(SESSIONS[name][1]) == "Up"
                   for name in names)

    def wait_up(self, names=("ipv4",), timeout=15):
        """Wait until all sessions are Up on both sides."""
        try:
            wait_until(lambda: self.up(names), timeout, message="BFD sessions up")
        except TimeoutError as e:
            raise TimeoutError("%s, BNG Blaster: %s, BIRD: %s" % (
                e, self.bbl_sessions(), self.bird_sessions())) from None

    def assert_not_up(self, names=("ipv4",), duration=5):
        """Assert that the sessions do not come up on any side."""
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            for name in names:
                assert self.bbl_state(name) != "Up", self.bbl_session(name)
                assert self.bird_state(SESSIONS[name][1]) != "Up", self.bird_sessions()
            time.sleep(0.5)


@pytest.fixture
def bfd(topology, processes, tmp_path):
    return BfdSetup(topology, processes, tmp_path)


@pytest.mark.parametrize("name", [
    "ipv4",
    pytest.param("ipv6", marks=pytest.mark.full),
    pytest.param("multihop", marks=pytest.mark.full),
])
def test_session(bfd, name):
    """Static session single-hop (RFC 5881) and multi-hop (RFC 5883)
    between loopback addresses. The teardown signals AdminDown."""
    bfd.start_bird(tx=300, rx=300, multiplier=3, neighbors=(name,))
    bfd.start_bbl(profile={"min-ttl": MULTIHOP_MIN_TTL}, sessions=(name,))
    bfd.wait_up((name,))
    peer, local = SESSIONS[name]
    session = bfd.bbl_session(name)
    assert session["peer-address"] == peer
    assert session["local-address"] == local
    assert session["multihop"] == (name == "multihop")
    assert session["min-ttl"] == (MULTIHOP_MIN_TTL if name == "multihop" else 255)
    assert session["clients"] == ["static"]
    assert session["remote-state"] == "Up"
    assert session["tx-interval-us"] == 300000
    assert session["detection-time-us"] == 900000
    assert session["stats"]["rx-errors"] == 0
    bird = bfd.bird_session(local)
    if bfd.bird_details:
        assert bird["session type"] == ("Multihop" if name == "multihop" else "Direct")
        assert bird["remote discriminator"] == str(session["local-discriminator"])
        assert bird["local discriminator"] == str(session["remote-discriminator"])

    assert bfd.bbl.terminate(30) == 0
    report = bfd.bbl.report()["report"]["bfd"]
    assert report, report
    wait_until(lambda: bfd.bird_state(local) == "Down", 5, message="BIRD session down")
    bird = bfd.bird_session(local)
    if bfd.bird_details:
        assert bird["remote state"] == "AdminDown", bird
        assert bird["local diagnostic"] == "Neighbor down", bird


@pytest.mark.full
def test_session_all(bfd):
    """IPv4, IPv6 and multi-hop sessions at the same time with 100 ms
    stable for several detection times."""
    names = tuple(SESSIONS)
    bfd.start_bird(tx=100, rx=100, multiplier=3, neighbors=names)
    bfd.start_bbl(profile={"tx-interval": 100, "rx-interval": 100, "min-ttl": MULTIHOP_MIN_TTL},
                  sessions=names)
    bfd.wait_up(names)
    time.sleep(3)
    for name in names:
        session = bfd.bbl_session(name)
        assert session["state"] == "Up"
        assert session["stats"]["up"] == 1, session
        assert session["stats"]["down"] == 0, session
        assert session["tx-interval-us"] == 100000
    assert len(bfd.bbl_sessions(**{"state": "Up"})) == 3
    assert len(bfd.bbl_sessions(**{"peer-address": BIRD_ADDRESS6})) == 1
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
def test_multihop_min_ttl(bfd):
    """Multi-hop packets of BIRD (TTL 64) are discarded with the default
    min-ttl 254 of the BNG Blaster."""
    bfd.start_bird(neighbors=("multihop",))
    bfd.start_bbl(sessions=("multihop",))
    bfd.assert_not_up(("multihop",), 4)
    session = bfd.bbl_session("multihop")
    assert session["min-ttl"] == 254
    assert session["stats"]["rx-packets"] == 0
    assert session["stats"]["rx-errors"] > 0
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
@pytest.mark.parametrize("auth_type", AUTH_TYPES)
def test_authentication(bfd, auth_type):
    """All authentication types (RFC 5880 section 6.7) with key ID 7.
    The meticulous types increment the sequence number with every
    packet, so the session must stay up for several detection times."""
    bfd.start_bird(tx=100, rx=100, auth=(auth_type, AUTH_KEY, 7))
    bfd.start_bbl(profile={"tx-interval": 100, "rx-interval": 100,
                           "authentication-type": auth_type,
                           "authentication-key": AUTH_KEY,
                           "authentication-key-id": 7})
    bfd.wait_up()
    time.sleep(2)
    session = bfd.bbl_session("ipv4")
    assert session["state"] == "Up"
    assert session["authentication-type"] == auth_type
    assert session["stats"]["down"] == 0, session
    assert session["stats"]["rx-auth-errors"] == 0, session
    assert "Bad packet" not in bfd.bird_log()
    assert bfd.bbl.terminate(30) == 0
    if bfd.bird_details:
        wait_until(lambda: bfd.bird_session(BBL_ADDRESS)["remote state"] == "AdminDown", 5,
                   message="authenticated AdminDown accepted by BIRD")
    else:
        wait_until(lambda: bfd.bird_state(BBL_ADDRESS) == "Down", 5,
                   message="authenticated AdminDown accepted by BIRD")
    assert "Bad packet" not in bfd.bird_log()


@pytest.mark.full
@pytest.mark.parametrize("auth_type", ["keyed-md5", "meticulous-keyed-sha1"])
def test_authentication_restart(bfd, auth_type):
    """BIRD restarted within the detection time of the BNG Blaster with
    a new (random) sequence number: the packets are out of the sequence
    number window of the old session and discarded (RFC 5880 6.7.3,
    6.7.4) until the session times out and the sequence number is no
    longer known. The session comes up again."""
    bfd.start_bird(tx=100, rx=100, auth=(auth_type, AUTH_KEY, 1))
    bfd.start_bbl(profile={"tx-interval": 100, "rx-interval": 1000, "multiplier": 3,
                           "authentication-type": auth_type,
                           "authentication-key": AUTH_KEY})
    bfd.wait_up()
    bfd.bird.stop()
    (bfd.tmp_path / "bird.ctl").unlink(missing_ok=True)
    bfd.bird.start(bfd.bird_config())
    bfd.wait_up(timeout=15)
    session = bfd.bbl_session("ipv4")
    assert session["stats"]["up"] == 2, session
    assert session["stats"]["timeout"] == 1, session
    assert session["stats"]["rx-auth-errors"] > 0, session
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
@pytest.mark.parametrize("auth_type,bird_auth", [
    ("simple", ("simple", "wrong", 1)),
    ("keyed-md5", ("keyed-md5", "wrong", 1)),
    ("meticulous-keyed-md5", ("meticulous-keyed-md5", AUTH_KEY, 2)),
    ("keyed-sha1", ("keyed-sha1", "wrong", 1)),
    ("meticulous-keyed-sha1", ("meticulous-keyed-sha1", AUTH_KEY, 2)),
    ("keyed-sha1", ("keyed-md5", AUTH_KEY, 1)),
    ("keyed-sha1", None),
], ids=["simple-key", "keyed-md5-key", "meticulous-keyed-md5-key-id", "keyed-sha1-key",
        "meticulous-keyed-sha1-key-id", "type", "none"])
def test_authentication_mismatch(bfd, auth_type, bird_auth):
    """Wrong key, key ID or authentication type: the session stays
    down and the packets are counted as authentication errors."""
    bfd.start_bird(auth=bird_auth)
    bfd.start_bbl(profile={"authentication-type": auth_type,
                           "authentication-key": AUTH_KEY})
    bfd.assert_not_up(duration=3)
    first = bfd.bbl_session("ipv4")["stats"]["rx-auth-errors"]
    assert first > 0
    wait_until(lambda: bfd.bbl_session("ipv4")["stats"]["rx-auth-errors"] > first, 5,
               message="rx-auth-errors increasing")
    session = bfd.bbl_session("ipv4")
    assert session["state"] == "Down"
    assert session["stats"]["rx-packets"] == 0
    assert session["stats"]["up"] == 0
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
def test_timer_negotiation(bfd):
    """Different intervals and multipliers per side (RFC 5880 6.8.2,
    6.8.4): TX interval max(local desired min TX, remote required min
    RX) and detection time remote multiplier x max(local required min
    RX, remote desired min TX)."""
    bfd.start_bird(tx=300, rx=150, multiplier=5)
    bfd.start_bbl(profile={"tx-interval": 200, "rx-interval": 500, "multiplier": 4})
    bfd.wait_up()

    def negotiated():
        session = bfd.bbl_session("ipv4")
        return not session["poll"] and session["tx-interval-us"] == 200000 and \
            session["detection-time-us"] == 2500000 and session
    session = wait_until(negotiated, 5, message="negotiated BNG Blaster timers")
    assert session["desired-min-tx-interval-us"] == 200000
    assert session["required-min-rx-interval-us"] == 500000
    assert session["remote-desired-min-tx-interval-us"] == 300000
    assert session["remote-required-min-rx-interval-us"] == 150000
    assert session["remote-multiplier"] == 5

    def bird_negotiated():
        bird = bfd.bird_session(BBL_ADDRESS)
        return bird["transmit timer"].endswith("/ 0.500") and \
            bird["detect timer"].endswith("/ 0.800") and bird
    bird = wait_until(bird_negotiated, 5, message="negotiated BIRD timers")
    if bfd.bird_details:
        assert bird_seconds(bird["remote min tx interval"]) == 200000
        assert bird_seconds(bird["remote min rx interval"]) == 500000
        assert bird["remote multiplier"] == "4"
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
def test_poll_sequence(bfd):
    """bfd-session-update while Up starts a poll sequence and the new
    values are used after the final (RFC 5880 6.8.3). A BIRD timer
    change is answered with final. The session stays up."""
    bfd.start_bird(tx=100, rx=100, multiplier=3)
    bfd.start_bbl(profile={"tx-interval": 300, "rx-interval": 300, "multiplier": 3})
    bfd.wait_up()
    session = wait_until(lambda: (lambda s: not s["poll"] and s)(bfd.bbl_session("ipv4")), 5,
                         message="slow start poll sequence finished")
    polls = session["stats"]["poll-sequences"]
    assert session["tx-interval-us"] == 300000

    bfd.bbl_ctrl("bfd-session-update", "ipv4",
                 **{"tx-interval": 100, "rx-interval": 100, "multiplier": 5})

    def updated():
        s = bfd.bbl_session("ipv4")
        return not s["poll"] and s["stats"]["poll-sequences"] == polls + 1 and s
    session = wait_until(updated, 5, message="poll sequence finished")
    assert session["desired-min-tx-interval-us"] == 100000
    assert session["required-min-rx-interval-us"] == 100000
    assert session["multiplier"] == 5
    assert session["tx-interval-us"] == 100000
    assert session["detection-time-us"] == 300000

    def bird_updated():
        bird = bfd.bird_session(BBL_ADDRESS)
        return bird["transmit timer"].endswith("/ 0.100") and \
            bird["detect timer"].endswith("/ 0.500") and bird
    bird = wait_until(bird_updated, 5, message="BIRD timers updated")
    if bfd.bird_details:
        assert bird["remote multiplier"] == "5"

    # Timer change by BIRD (poll sequence started by BIRD).
    bfd.bird_reconfigure(tx=200, rx=400, multiplier=3)

    def remote_updated():
        s = bfd.bbl_session("ipv4")
        return s["remote-desired-min-tx-interval-us"] == 200000 and \
            s["remote-required-min-rx-interval-us"] == 400000 and \
            s["tx-interval-us"] == 400000 and s["detection-time-us"] == 600000 and s
    wait_until(remote_updated, 5, message="BNG Blaster timers updated by BIRD")
    wait_until(lambda: bfd.bird_session(BBL_ADDRESS)["transmit timer"].endswith("/ 0.200"), 5,
               message="BIRD poll sequence finished")
    time.sleep(1)
    session = bfd.bbl_session("ipv4")
    assert session["state"] == "Up"
    assert session["stats"]["up"] == 1, session
    assert session["stats"]["down"] == 0, session
    assert "changed state from Up" not in bfd.bird_log()
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
def test_admin_down_bbl(bfd):
    """bfd-session-disable signals AdminDown, BIRD goes down with
    diagnostic neighbor down (RFC 5880 6.8.16), and up again after
    bfd-session-enable."""
    bfd.start_bird(tx=100, rx=100)
    bfd.start_bbl(profile={"tx-interval": 100, "rx-interval": 100})
    bfd.wait_up()
    bfd.bbl_ctrl("bfd-session-disable", "ipv4")
    session = bfd.bbl_session("ipv4")
    assert session["state"] == "AdminDown"
    assert session["admin-state"] == "disabled"
    assert session["local-diagnostic"] == "administratively-down"
    wait_until(lambda: bfd.bird_state(BBL_ADDRESS) == "Down", 3, message="BIRD session down")
    bird = bfd.bird_session(BBL_ADDRESS)
    if bfd.bird_details:
        assert bird["remote state"] == "AdminDown"
        assert bird["local diagnostic"] == "Neighbor down"
        assert bird["remote diagnostic"] == "Admin down"
    # Stays AdminDown, also with packets of BIRD.
    time.sleep(3)
    assert bfd.bbl_state("ipv4") == "AdminDown"
    assert bfd.bird_state(BBL_ADDRESS) == "Down"

    bfd.bbl_ctrl("bfd-session-enable", "ipv4")
    bfd.wait_up(timeout=10)
    session = bfd.bbl_session("ipv4")
    assert session["admin-state"] == "enabled"
    assert session["stats"]["up"] == 2
    assert session["stats"]["timeout"] == 0
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
def test_admin_down_bird(bfd):
    """BIRD does not signal AdminDown when the protocol is disabled or
    the neighbor removed, it stops sending, so the BNG Blaster detects
    the failure by timeout. The session comes up again after enable."""
    bfd.start_bird(tx=100, rx=100)
    bfd.start_bbl(profile={"tx-interval": 100, "rx-interval": 100})
    bfd.wait_up()
    bfd.bird.birdc("disable bfd1")
    wait_until(lambda: bfd.bbl_state("ipv4") == "Down", 3, message="BNG Blaster session down")
    session = bfd.bbl_session("ipv4")
    assert session["local-diagnostic"] == "control-detection-time-expired"
    assert session["stats"]["timeout"] == 1
    bfd.bird.birdc("enable bfd1")
    bfd.wait_up(timeout=10)

    bfd.bird_reconfigure(neighbors=())
    wait_until(lambda: bfd.bbl_state("ipv4") == "Down", 3, message="BNG Blaster session down")
    assert bfd.bbl_session("ipv4")["stats"]["timeout"] == 2
    bfd.bird_reconfigure(neighbors=("ipv4",))
    bfd.wait_up(timeout=10)
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
@pytest.mark.parametrize("name", ["ipv4", "ipv6", "multihop"])
def test_detection_timeout(bfd, name):
    """BIRD packets dropped: the BNG Blaster goes down after the
    detection time with diagnostic control detection time expired and
    signals this to BIRD (RFC 5880 6.8.4). Up again without drop."""
    bfd.start_bird(tx=100, rx=100, multiplier=3, neighbors=(name,))
    bfd.start_bbl(profile={"tx-interval": 100, "rx-interval": 100, "multiplier": 3,
                           "min-ttl": MULTIHOP_MIN_TTL}, sessions=(name,))
    bfd.wait_up((name,))
    local = SESSIONS[name][1]
    bfd.bird_drop_bfd()
    start = time.monotonic()
    wait_until(lambda: bfd.bbl_state(name) == "Down", 3, 0.05, message="BNG Blaster session down")
    elapsed = time.monotonic() - start
    # Detection time 300 ms, ctrl and timer granularity.
    assert elapsed < 1.5, elapsed
    session = bfd.bbl_session(name)
    assert session["local-diagnostic"] == "control-detection-time-expired"
    assert session["stats"]["timeout"] == 1
    assert session["stats"]["down"] == 1
    # BIRD goes down (neighbor signaled) and then to Init, as the
    # BNG Blaster packets with state Down are still received.
    wait_until(lambda: "Session to %s changed state from Up to Down" % local in bfd.bird_log(), 3,
               message="BIRD session down")
    bird = bfd.bird_session(local)
    assert bird["session state"] in ("Down", "Init"), bird
    if bfd.bird_details:
        assert bird["remote state"] == "Down", bird
        assert bird["remote diagnostic"] == "Time expired", bird

    bfd.bird_drop_bfd(False)
    bfd.wait_up((name,), timeout=10)
    assert bfd.bbl_session(name)["stats"]["up"] == 2
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
def test_ospf(bfd):
    """OSPFv2 with BFD on both sides: the session is created for the
    neighbor (client ospfv2) and a BFD failure brings the neighbor down
    long before the dead interval (10 s)."""
    bfd.start_bird(tx=100, rx=100, multiplier=3, neighbors=(), ospf=True)
    bfd.start_bbl(profile={"tx-interval": 100, "rx-interval": 100, "multiplier": 3},
                  sessions=(), ospf=True)

    def ospf_full():
        neighbors = bfd.bbl.ctrl("ospf-neighbors", instance=1)["ospf-neighbors"]
        return len(neighbors) == 1 and neighbors[0]["state"] == "Full"

    def bfd_up():
        sessions = bfd.bbl_sessions()
        return len(sessions) == 1 and sessions[0]["state"] == "Up" and \
            bfd.bird_state(BBL_ADDRESS) == "Up" and sessions[0]

    wait_until(ospf_full, 30, message="OSPF neighbor full")
    session = wait_until(bfd_up, 15, message="BFD session up")
    assert session["clients"] == ["ospfv2"]
    assert session["peer-address"] == BIRD_ADDRESS
    assert session["multihop"] is False

    bfd.bird_drop_bfd()
    start = time.monotonic()
    pattern = re.compile(r"OSPFv2 neighbor %s BFD down" % re.escape(BIRD_ROUTER_ID))
    wait_until(lambda: pattern.search(bfd.bbl_log()), 5, 0.1,
               message="OSPF neighbor down by BFD")
    assert time.monotonic() - start < 3
    bfd.bird_drop_bfd(False)
    wait_until(ospf_full, 30, message="OSPF neighbor full again")
    wait_until(bfd_up, 15, message="BFD session up again")
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
def test_ipv6_link_local(bfd):
    """IPv6 single-hop between link-local addresses, the BNG Blaster
    uses its link-local address if no local address is configured for
    a link-local peer."""
    out = bfd.topology.b.exec(["ip", "-6", "-o", "addr", "show", "dev", bfd.topology.if_b,
                               "scope", "link"])
    bird_ll = re.search(r"inet6 (fe80::[0-9a-f:]+)/", out).group(1)
    bfd.start_bbl(profile={"tx-interval": 100, "rx-interval": 100},
                  sessions=({"network-interface": bfd.topology.if_a,
                             "peer-ipv6-address": bird_ll, "bfd-profile-id": 1, "name": "ll"},))
    bbl_ll = bfd.bbl_session("ll")["local-address"]
    assert bbl_ll.startswith("fe80::"), bbl_ll
    bfd.start_bird(tx=100, rx=100, neighbors=((bird_ll, bbl_ll),))

    def up():
        return bfd.bbl_state("ll") == "Up" and bfd.bird_state(bbl_ll) == "Up"
    wait_until(up, 15, message="link-local session up")
    session = bfd.bbl_session("ll")
    assert session["peer-address"] == bird_ll
    assert session["tx-interval-us"] == 100000
    assert bfd.bbl.terminate(30) == 0


@pytest.mark.full
def test_passive(bfd):
    """A passive BNG Blaster does not send before it receives a packet
    from BIRD (RFC 5880 6.1), BIRD passive and BNG Blaster active."""
    bfd.start_bbl(profile={"passive": True})
    time.sleep(2)
    session = bfd.bbl_session("ipv4")
    assert session["passive"] is True
    assert session["stats"]["tx-packets"] == 0, session
    bfd.start_bird()
    bfd.wait_up()
    assert bfd.bbl.terminate(30) == 0
    bfd.bird.stop()
    (bfd.tmp_path / "bird.ctl").unlink(missing_ok=True)

    # Both passive: no session.
    bfd.start_bbl(profile={"passive": True})
    bfd.start_bird(passive=True)
    bfd.assert_not_up(duration=3)
    assert bfd.bbl_session("ipv4")["stats"]["tx-packets"] == 0

    # BIRD passive and BNG Blaster active.
    assert bfd.bbl.terminate(30) == 0
    bfd.start_bbl()
    bfd.wait_up()
    assert bfd.bbl.terminate(30) == 0
