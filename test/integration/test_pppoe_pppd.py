"""
BNG Blaster PPPoE client against pppd (rp-pppoe pppoe-server)

Namespace A runs the BNG Blaster PPPoE client, namespace B runs
pppoe-server in kernel mode with pppd as PPP server. The pppd options
are written per test and placed at /etc/ppp with an overlay mount in a
private mount namespace, so nothing is installed on the host.

The ppp and pppoe packages are used from the system or from an extracted
root directory given by PPP_ROOT (dpkg-deb -x ppp_*.deb pppoe_*.deb), the
tests are skipped if not found unless BBL_REQUIRE_PPPD is set.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import os
import re
import subprocess
import time

import pytest

import helpers
from helpers import BngBlaster, wait_until

PPP_ROOT = os.environ.get("PPP_ROOT", "")
PPPOE_SERVER = os.path.join(PPP_ROOT or "/", "usr/sbin/pppoe-server")
PPPD = os.path.join(PPP_ROOT or "/", "usr/sbin/pppd")
USERNAME, PASSWORD = "user", "secret"


@pytest.fixture
def pppd_bin():
    if not (os.path.exists(PPPOE_SERVER) and os.path.exists(PPPD)):
        if os.environ.get("BBL_REQUIRE_PPPD"):
            pytest.fail("pppoe-server/pppd not found (set PPP_ROOT)")
        pytest.skip("pppoe-server/pppd not found (set PPP_ROOT)")
    if os.stat(PPPD).st_mode & 0o4000 and os.stat(PPPD).st_uid != 0:
        pytest.fail("%s is setuid to a user other than root (chmod u-s)" % PPPD)


class Setup:

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.pppd_log = str(tmp_path / "pppd.log")
        self.bbl = None

    def start_pppd(self, *options):
        etc = self.tmp_path / "etc" / "ppp"
        etc.mkdir(parents=True)
        (etc / "options").write_text("")
        (etc / "pppoe-server-options").write_text("\n".join(
            ["debug", "logfile " + self.pppd_log, "noipdefault", "nodefaultroute", "+ipv6",
             "lcp-echo-interval 0"] + list(options)) + "\n")
        for secrets in ("pap-secrets", "chap-secrets"):
            (etc / secrets).write_text('"%s" * "%s" *\n' % (USERNAME, PASSWORD))
            (etc / secrets).chmod(0o600)
        script = ["mount -t overlay overlay -o lowerdir=%s:/etc /etc" % (self.tmp_path / "etc")]
        if PPP_ROOT:
            script.append("mount -t overlay overlay -o lowerdir=%s/usr:/usr /usr" % PPP_ROOT)
        script.append("exec /usr/sbin/pppoe-server -F -k -I %s -L 10.0.0.1 -R 10.0.0.100 -N 4 -C pppd"
                      % self.topology.if_b)
        with open(str(self.tmp_path / "pppoe-server.out"), "w") as out:
            proc = subprocess.Popen(self.topology.b.cmd(["unshare", "-m", "sh", "-c", "; ".join(script)]),
                                    stdout=out, stderr=subprocess.STDOUT)
        # pppd children are killed with the network namespace processes.
        self.processes.append(type("Proc", (), {"stop": lambda s: self.stop_pppd(proc)})())
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError("pppoe-server exited, see pppoe-server.out")

    def stop_pppd(self, proc):
        proc.kill()
        self.topology.b.exec(["sh", "-c", "pkill -x pppd; true"], check=False)

    def start_bbl(self, access=None, **config):
        interface = {"interface": self.topology.if_a, "type": "pppoe", "outer-vlan": 0, "inner-vlan": 0,
                     "vlan-mode": "N:1", "username": USERNAME, "password": PASSWORD}
        interface.update(access or {})
        conf = {"interfaces": {"access": [interface]}, "sessions": {"count": 1, "reconnect": False},
                "dhcpv6": {"enable": False}}
        conf.update(config)
        self.bbl = BngBlaster(self.topology.a, self.tmp_path).start(conf, logging=("info", "pppoe"))
        self.processes.append(self.bbl)

    def session(self):
        return self.bbl.ctrl("session-info", **{"session-id": 1})["session-info"]

    def wait_state(self, state, timeout=30):
        wait_until(lambda: self.session()["session-state"] == state, timeout, message="session %s" % state)

    def log(self):
        return open(self.pppd_log).read() if os.path.exists(self.pppd_log) else ""


@pytest.fixture
def pppd(pppd_bin, topology, processes, tmp_path):
    return Setup(topology, processes, tmp_path)


def test_session(pppd):
    """PAP, IPCP and IP6CP against pppd, the address of the pppoe-server
    pool is assigned with configure-nak."""
    pppd.start_pppd("require-pap")
    pppd.start_bbl()
    pppd.wait_state("Established")
    session = pppd.session()
    assert (session["lcp-state"], session["ipcp-state"], session["ip6cp-state"]) == ("Opened",) * 3
    assert session["ipv4-address"] == "10.0.0.100"
    assert "remote IP address 10.0.0.100" in pppd.log()


def test_lcp_options_rejected(pppd):
    """pppd rejects the Magic-Number and MRU options (nomagic, -mru), the
    client requests LCP without them (RFC 1661 section 5.4)."""
    pppd.start_pppd("require-pap", "nomagic", "-mru")
    pppd.start_bbl()
    pppd.wait_state("Established", 20)
    log = pppd.log()
    assert re.search(r"sent \[LCP ConfRej id=0x\w+ <mru 1492> <magic", log), log
    assert "rcvd [LCP CodeRej" not in log


def test_chap_rechallenge(pppd):
    """pppd sends a CHAP challenge every 3 seconds (chap-interval), the
    client answers each challenge (RFC 1994 section 2)."""
    pppd.start_pppd("require-chap", "chap-interval 3")
    pppd.start_bbl(access={"authentication-protocol": "CHAP"})
    pppd.wait_state("Established")
    wait_until(lambda: pppd.log().count("rcvd [CHAP Response") >= 3, 15, message="CHAP responses")
    assert pppd.session()["session-state"] == "Established"
    assert "Peer %s failed CHAP" % USERNAME not in pppd.log()


def test_ipcp_rejected_dual_stack(pppd):
    """pppd without IPv4 (noip) rejects IPCP with LCP protocol-reject,
    the dual stack session is established with IPv6 only."""
    pppd.start_pppd("require-pap", "noip")
    pppd.start_bbl()
    pppd.wait_state("Established")
    session = pppd.session()
    assert (session["ipcp-state"], session["ip6cp-state"]) == ("Rejected", "Opened")


def test_ipcp_rejected_ipv4_only(pppd):
    """pppd without IPv4 (noip) rejects IPCP of an IPv4 only session:
    no NCP can be opened and the session is terminated."""
    pppd.start_pppd("require-pap", "noip")
    pppd.start_bbl(access={"ipv6": False})
    pppd.wait_state("Terminated")


@pytest.mark.parametrize("stop_verified", [False, True], ids=["default", "stop-verified"])
def test_session_traffic_ipcp_reopen(pppd, stop_verified):
    """Session traffic is routed by pppd between the session and a network
    interface (VLAN 100) on the same link. ipcp-close and ipcp-open reset the IPv4
    session traffic, the flows are verified again without counting them
    twice, so the session is not pending afterwards (IP6CP keeps the link).
    With stop-verified, the stopped flows start again to be verified."""
    topology = pppd.topology
    vlan = topology.if_b + ".100"
    topology.b.exec(["ip", "link", "add", "link", topology.if_b, "name", vlan, "type", "vlan", "id", "100"])
    topology.b.exec(["ip", "link", "set", vlan, "up"])
    helpers.kernel_address(topology.b, vlan, "192.168.1.2/24")
    topology.b.exec(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    pppd.start_pppd("require-pap")
    pppd.start_bbl(interfaces={
        "network": {"interface": topology.if_a, "vlan": 100, "address": "192.168.1.1/24",
                    "gateway": "192.168.1.2"},
        "access": [{"interface": topology.if_a, "type": "pppoe", "outer-vlan": 0, "inner-vlan": 0,
                    "vlan-mode": "N:1", "username": USERNAME, "password": PASSWORD}]},
        traffic={"stop-verified": stop_verified},
        **{"session-traffic": {"autostart": True, "ipv4-pps": 10}})
    pppd.wait_state("Established")

    def verified():
        counters = pppd.bbl.ctrl("session-counters")["session-counters"]
        return counters["session-traffic-flows"], counters["session-traffic-flows-verified"]

    wait_until(lambda: verified() == (2, 2), 15, message="session traffic verified")
    pppd.bbl.ctrl("ipcp-close", **{"session-id": 1})
    wait_until(lambda: pppd.session()["ipcp-state"] == "Closed", 10, message="IPCP closed")
    pppd.bbl.ctrl("ipcp-open", **{"session-id": 1})
    wait_until(lambda: pppd.session()["ipcp-state"] == "Opened", 10, message="IPCP opened")
    wait_until(lambda: not pppd.bbl.ctrl("sessions-pending")["sessions-pending"], 15,
               message="session traffic verified again")
    assert verified() == (2, 2)
