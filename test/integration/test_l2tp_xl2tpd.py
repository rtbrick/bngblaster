"""
BNG Blaster L2TP LAC against xl2tpd (LNS) with pppd

Namespace A runs the BNG Blaster LAC with PPPoL2TP sessions, namespace B
runs xl2tpd as LNS in userspace mode (no kernel L2TP), which starts pppd
for each session. The xl2tpd and pppd configuration is placed at /etc
with an overlay mount in a private mount namespace.

xl2tpd and pppd are used from the system or from an extracted root
directory given by PPP_ROOT (dpkg-deb -x of the ppp and xl2tpd packages),
the tests are skipped if not found unless BBL_REQUIRE_XL2TPD is set.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import os
import subprocess
import time

import pytest

import helpers
from helpers import BngBlaster, wait_until

PPP_ROOT = os.environ.get("PPP_ROOT", "")
XL2TPD = os.path.join(PPP_ROOT or "/", "usr/sbin/xl2tpd")
PPPD = os.path.join(PPP_ROOT or "/", "usr/sbin/pppd")
LAC_ADDRESS, LNS_ADDRESS = "10.0.0.1", "10.0.0.2"
LNS_PPP_ADDRESS = "10.100.0.1"
SESSIONS = 2
EXIT_TIMEOUT = 30


@pytest.fixture
def xl2tpd_bin():
    if not (os.path.exists(XL2TPD) and os.path.exists(PPPD)):
        if os.environ.get("BBL_REQUIRE_XL2TPD"):
            pytest.fail("xl2tpd/pppd not found (set PPP_ROOT)")
        pytest.skip("xl2tpd/pppd not found (set PPP_ROOT)")


class Setup:

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.pppd_log = str(tmp_path / "pppd.log")
        self.xl2tpd_log = str(tmp_path / "xl2tpd.out")
        self.lac = None
        helpers.kernel_address(topology.b, topology.if_b, LNS_ADDRESS + "/24")

    def start_lns(self, ppp_options=()):
        etc = self.tmp_path / "etc"
        (etc / "ppp").mkdir(parents=True)
        (etc / "xl2tpd").mkdir()
        (etc / "ppp" / "options").write_text("")
        (etc / "ppp" / "options.xl2tpd").write_text("\n".join([
            "require-pap", "debug", "logfile " + self.pppd_log, "lcp-echo-interval 0",
            "noipdefault", "nodefaultroute"] + list(ppp_options)) + "\n")
        (etc / "ppp" / "pap-secrets").write_text('* * "test" *\n')
        (etc / "ppp" / "pap-secrets").chmod(0o600)
        (etc / "xl2tpd" / "xl2tpd.conf").write_text("\n".join([
            "[global]", "listen-addr = %s" % LNS_ADDRESS, "port = 1701", "force userspace = yes",
            "access control = no", "debug tunnel = yes",
            "[lns default]", "ip range = 10.100.0.10-10.100.0.20", "local ip = %s" % LNS_PPP_ADDRESS,
            "require authentication = yes", "require pap = yes", "refuse chap = yes",
            "name = xl2tpd-lns", "length bit = yes", "pppoptfile = /etc/ppp/options.xl2tpd"]) + "\n")
        script = ["mount -t overlay overlay -o lowerdir=%s:/etc /etc" % etc]
        if PPP_ROOT:
            script.append("mount -t overlay overlay -o lowerdir=%s/usr:/usr /usr" % PPP_ROOT)
        script += ["mount -t tmpfs tmpfs /var/run", "mkdir -p /var/run/xl2tpd",
                   "exec /usr/sbin/xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf -p /var/run/xl2tpd.pid "
                   "-C /var/run/xl2tpd/l2tp-control"]
        with open(self.xl2tpd_log, "w") as out:
            proc = subprocess.Popen(self.topology.b.cmd(["unshare", "-m", "sh", "-c", "; ".join(script)]),
                                    stdout=out, stderr=subprocess.STDOUT)
        self.processes.append(type("Proc", (), {"stop": lambda s: self.stop_lns(proc)})())
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError("xl2tpd exited, see xl2tpd.out")

    def stop_lns(self, proc):
        proc.kill()
        self.topology.b.exec(["sh", "-c", "pkill -x pppd; true"], check=False)

    def start_lac(self, access=None, **config):
        conf = {
            "interfaces": {
                "network": {"interface": self.topology.if_a, "address": LAC_ADDRESS + "/24",
                            "gateway": LNS_ADDRESS},
                "access": [{"interface": self.topology.if_a, "type": "pppol2tp", "l2tp-client-group-id": 1,
                            "outer-vlan-min": 1, "outer-vlan-max": 100, "authentication-protocol": "PAP"}]
            },
            "sessions": {"count": SESSIONS, "reconnect": False},
            "ppp": {"authentication": {"username": "user{session-global}", "password": "test"},
                    "ip6cp": {"enable": False}},
            "l2tp-client": [{"group-id": 1, "name": "LAC1", "network-interface": self.topology.if_a,
                             "server-address": LNS_ADDRESS}]
        }
        conf["interfaces"]["access"][0].update(access or {})
        conf.update(config)
        self.lac = BngBlaster(self.topology.a, self.tmp_path, "lac").start(conf, logging=("info", "l2tp"))
        self.processes.append(self.lac)
        wait_until(lambda: self.lac.ctrl("session-counters")["session-counters"]["sessions-established"]
                   == SESSIONS, 30, message="LAC sessions established")

    def pppd(self):
        return open(self.pppd_log).read() if os.path.exists(self.pppd_log) else ""


@pytest.fixture
def xl2tpd(xl2tpd_bin, topology, processes, tmp_path):
    return Setup(topology, processes, tmp_path)


@pytest.mark.full
def test_sessions(xl2tpd):
    """PPPoL2TP sessions are established with addresses of the xl2tpd pool,
    CCP of pppd is answered with LCP protocol-reject and the LAC exits
    cleanly (CDN and StopCCN)."""
    xl2tpd.start_lns()
    xl2tpd.start_lac()
    addresses = {xl2tpd.lac.ctrl("session-info", **{"session-id": i})["session-info"]["ipv4-address"]
                 for i in range(1, SESSIONS + 1)}
    assert addresses == {"10.100.0.10", "10.100.0.11"}, addresses
    wait_until(lambda: "rcvd [LCP ProtRej" in xl2tpd.pppd() and "80 fd" in xl2tpd.pppd(), 10,
               message="CCP protocol-reject")
    assert xl2tpd.lac.terminate(EXIT_TIMEOUT) == 0
    # CDN for each call and StopCCN for the tunnel.
    wait_until(lambda: open(xl2tpd.xl2tpd_log).read().count("Connection closed to %s, serial" % LAC_ADDRESS)
               == SESSIONS and "closing down tunnel" in open(xl2tpd.xl2tpd_log).read(), 10,
               message="xl2tpd calls and tunnel closed")


@pytest.mark.full
def test_icmp_client(xl2tpd):
    """The ICMP client of PPPoL2TP sessions pings the pppd address of the
    LNS through the tunnel and receives the replies."""
    xl2tpd.start_lns()
    xl2tpd.start_lac(access={"icmp-client-group-id": 1},
                     **{"icmp-client": [{"icmp-client-group-id": 1, "destination-address": LNS_PPP_ADDRESS,
                                         "interval": 0.2}]})

    def received():
        clients = xl2tpd.lac.ctrl("icmp-clients", **{"session-id": 1}).get("icmp-clients", [])
        return clients and clients[0]["received"]

    wait_until(lambda: (received() or 0) >= 3, 15, message="ICMP replies")
    assert xl2tpd.lac.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.full
def test_reassemble_downstream_fragments(xl2tpd):
    """Downstream stream traffic of PPPoL2TP sessions is fragmented by the
    LNS (pppd MTU 1000) and reassembled by the LAC, the stream is verified
    with the session (crashed with a missing ethernet header)."""
    xl2tpd.topology.b.exec(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    xl2tpd.start_lns(ppp_options=["mtu 1000"])
    xl2tpd.start_lac(access={"stream-group-id": 1},
                     traffic={"reassemble-fragments": True, "autostart": True},
                     streams=[{"name": "down", "stream-group-id": 1, "type": "ipv4",
                               "direction": "downstream", "pps": 20, "length": 1400,
                               "ipv4-df": False}])

    def stream():
        streams = xl2tpd.lac.ctrl("session-streams", **{"session-id": 1})["session-streams"]["streams"]
        return [s for s in streams if s["direction"] == "downstream"][0]

    wait_until(lambda: stream()["rx-packets"] >= 10, 15, message="reassembled downstream packets")
    assert stream()["rx-fragments"] == 2
    assert xl2tpd.lac.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.full
def test_session_restart(xl2tpd):
    """session-restart restarts a PPPoL2TP session against xl2tpd."""
    xl2tpd.start_lns()
    xl2tpd.start_lac()
    assert xl2tpd.lac.ctrl("session-restart", **{"session-id": 1})["code"] == 200
    wait_until(lambda: xl2tpd.lac.ctrl("session-info", **{"session-id": 1})["session-info"]["flapped"] == 1,
               10, message="session flapped")
    wait_until(lambda: xl2tpd.lac.ctrl("session-counters")["session-counters"]["sessions-established"]
               == SESSIONS, 30, message="session established again")
    assert xl2tpd.lac.terminate(EXIT_TIMEOUT) == 0
