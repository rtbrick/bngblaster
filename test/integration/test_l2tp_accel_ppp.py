"""
BNG Blaster L2TP LAC against accel-ppp (LNS)

Namespace A runs the BNG Blaster LAC with PPPoL2TP sessions, namespace B
runs accel-pppd as LNS with kernel L2TP (l2tp_ppp module). accel-ppp
decrypts hidden AVPs and logs the received AVPs, but ignores proxy LCP
and proxy authentication and always starts its own LCP negotiation,
which verifies the LCP renegotiation of the LAC with proxy LCP.

accel-pppd is used from the system or from a build directory given by
ACCEL_PPP_BUILD (cmake build tree, modules are linked into the test
directory and the L2TP dictionary is used from the source tree), the tests are skipped if not found unless
BBL_REQUIRE_ACCEL_PPP is set. The kernel modules l2tp_ppp and
ppp_generic must be available.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import glob
import os
import shutil
import subprocess
import time

import pytest

import helpers
from helpers import BngBlaster, wait_until

ACCEL_PPP_BUILD = os.environ.get("ACCEL_PPP_BUILD", "")
if ACCEL_PPP_BUILD:
    ACCEL_PPPD = os.path.join(ACCEL_PPP_BUILD, "accel-pppd", "accel-pppd")
else:
    ACCEL_PPPD = shutil.which("accel-pppd") or "/usr/sbin/accel-pppd"
LAC_ADDRESS, LNS_ADDRESS = "10.0.0.1", "10.0.0.2"
LNS_PPP_ADDRESS = "10.100.0.1"
SESSIONS = 2
SECRET = "test"
EXIT_TIMEOUT = 30


@pytest.fixture
def accel_ppp_bin():
    if not os.path.exists(ACCEL_PPPD):
        if os.environ.get("BBL_REQUIRE_ACCEL_PPP"):
            pytest.fail("accel-pppd not found (set ACCEL_PPP_BUILD)")
        pytest.skip("accel-pppd not found (set ACCEL_PPP_BUILD)")
    if subprocess.run(["modprobe", "-a", "l2tp_ppp", "ppp_generic"],
                      capture_output=True).returncode != 0:
        pytest.skip("kernel modules l2tp_ppp/ppp_generic not available")


class Setup:

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.log = str(tmp_path / "accel-ppp.log")
        self.lac = None
        helpers.kernel_address(topology.b, topology.if_b, LNS_ADDRESS + "/24")

    def modules(self):
        """Module path option for a build tree (all modules in one directory)."""
        if not ACCEL_PPP_BUILD:
            return []
        path = self.tmp_path / "modules"
        path.mkdir()
        for module in glob.glob(os.path.join(ACCEL_PPP_BUILD, "accel-pppd", "**", "*.so"), recursive=True):
            os.symlink(module, path / os.path.basename(module))
        return ["path=%s" % path]

    def dictionary(self):
        """L2TP dictionary option for a build tree (not installed)."""
        if not ACCEL_PPP_BUILD:
            return []
        with open(os.path.join(ACCEL_PPP_BUILD, "CMakeCache.txt")) as f:
            for line in f:
                if line.startswith("CMAKE_HOME_DIRECTORY:"):
                    source = line.split("=", 1)[1].strip()
                    return ["dictionary=%s" % os.path.join(source, "accel-pppd", "ctrl", "l2tp", "dict", "dictionary")]
        return []

    def start_lns(self, hide_avps=False):
        secrets = self.tmp_path / "chap-secrets"
        secrets.write_text("".join("user%d@test * test 10.100.0.%d\n" % (i, 9 + i)
                                   for i in range(1, SESSIONS + 1)))
        secrets.chmod(0o600)
        config = self.tmp_path / "accel-ppp.conf"
        config.write_text("\n".join(
            ["[modules]"] + self.modules() +
            ["log_file", "l2tp", "auth_pap", "auth_chap_md5", "chap-secrets",
             "[core]", "log-error=%s" % (self.tmp_path / "accel-core.log"), "thread-count=2",
             "[log]", "log-file=%s" % self.log, "log-emerg=%s" % (self.tmp_path / "accel-emerg.log"),
             "level=5", "copy=1",
             "[ppp]", "verbose=1", "mtu=1400", "mru=1400", "ipv4=require", "ipv6=deny",
             "lcp-echo-interval=0",
             "[l2tp]", "verbose=1", "bind=%s" % LNS_ADDRESS, "secret=%s" % SECRET,
             "host-name=accel-lns", "hide-avps=%d" % hide_avps, "ppp-max-mtu=1420"] + self.dictionary() + [
             "[client-ip-range]", "disable",
             "[chap-secrets]", "chap-secrets=%s" % secrets, "gw-ip-address=%s" % LNS_PPP_ADDRESS]) + "\n")
        cmd = [ACCEL_PPPD, "-c", str(config), "-p", str(self.tmp_path / "accel-ppp.pid")]
        if ACCEL_PPP_BUILD:
            # libtriton of the build tree
            cmd = ["env", "LD_LIBRARY_PATH=%s" % os.path.join(ACCEL_PPP_BUILD, "accel-pppd", "triton")] + cmd
        with open(self.tmp_path / "accel-ppp.out", "w") as out:
            proc = subprocess.Popen(self.topology.b.cmd(cmd), stdout=out, stderr=subprocess.STDOUT)
        self.processes.append(type("Proc", (), {"stop": lambda s: self.stop_lns(proc)})())
        time.sleep(1)
        if proc.poll() is not None:
            raise RuntimeError("accel-pppd exited, see accel-ppp.out")

    def stop_lns(self, proc):
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()

    def start_lac(self, auth="PAP", access=None, access_line_profiles=None, **client):
        conf = {
            "interfaces": {
                "network": {"interface": self.topology.if_a, "address": LAC_ADDRESS + "/24",
                            "gateway": LNS_ADDRESS},
                "access": [{"interface": self.topology.if_a, "type": "pppol2tp", "l2tp-client-group-id": 1,
                            "outer-vlan-min": 1, "outer-vlan-max": 100, "authentication-protocol": auth}]
            },
            "sessions": {"count": SESSIONS, "start-rate": 10, "reconnect": False},
            "ppp": {"authentication": {"username": "user{session-global}@test", "password": "test"},
                    "ip6cp": {"enable": False}},
            "l2tp-client": [{"group-id": 1, "name": "LAC1", "network-interface": self.topology.if_a,
                             "server-address": LNS_ADDRESS, "secret": SECRET, **client}]
        }
        conf["interfaces"]["access"][0].update(access or {})
        if access_line_profiles:
            conf["access-line-profiles"] = access_line_profiles
        self.lac = BngBlaster(self.topology.a, self.tmp_path, "lac").start(conf, logging=("info", "l2tp", "pppoe"))
        self.processes.append(self.lac)
        wait_until(lambda: self.lac.ctrl("session-counters")["session-counters"]["sessions-established"]
                   == SESSIONS, 30, message="LAC sessions established")

    def addresses(self):
        return {self.lac.ctrl("session-info", **{"session-id": i})["session-info"]["ipv4-address"]
                for i in range(1, SESSIONS + 1)}

    def accel_log(self):
        return open(self.log).read() if os.path.exists(self.log) else ""

    def lac_log(self):
        return open(self.lac.path("log")).read()

    def terminate(self):
        assert self.lac.terminate(EXIT_TIMEOUT) == 0
        wait_until(lambda: self.accel_log().count("<Message-Type Call-Disconnect-Notify>") >= SESSIONS, 10,
                   message="accel-ppp CDN received")


@pytest.fixture
def accel_ppp(accel_ppp_bin, topology, processes, tmp_path):
    return Setup(topology, processes, tmp_path)


EXPECTED_ADDRESSES = {"10.100.0.10", "10.100.0.11"}


@pytest.mark.full
@pytest.mark.parametrize("auth", ["PAP", "CHAP"])
def test_sessions(accel_ppp, auth):
    """PPPoL2TP sessions without proxy LCP are established with the
    addresses of the chap-secrets file."""
    accel_ppp.start_lns()
    accel_ppp.start_lac(auth)
    assert accel_ppp.addresses() == EXPECTED_ADDRESSES
    assert "Proxy-Authen" not in accel_ppp.accel_log()
    accel_ppp.terminate()


@pytest.mark.full
@pytest.mark.parametrize("hidden", [False, True])
@pytest.mark.parametrize("auth", ["PAP", "CHAP"])
def test_proxy_lcp_renegotiation(accel_ppp, auth, hidden):
    """accel-ppp decodes (and decrypts) the proxy LCP and authentication
    AVPs but starts its own LCP negotiation, which restarts LCP in the
    PPPoL2TP sessions followed by a new authentication."""
    accel_ppp.start_lns()
    accel_ppp.start_lac(auth, **{"proxy-lcp": True, "proxy-auth": True, "proxy-auth-hidden": hidden})
    assert accel_ppp.addresses() == EXPECTED_ADDRESSES
    log = accel_ppp.accel_log()
    for i in range(1, SESSIONS + 1):
        assert "<Proxy-Authen-Name user%d@test>" % i in log, log
    assert "<Proxy-Authen-Type %d>" % (3 if auth == "PAP" else 2) in log
    assert "<Init-Recv-LCP>" in log and "<Last-Sent-LCP>" in log and "<Last-Recv-LCP>" in log
    assert ("<Random-Vector" in log) == hidden
    assert "(hidden," not in log
    assert accel_ppp.lac_log().count("PPP session reset to link phase (peer)") == SESSIONS
    accel_ppp.terminate()


@pytest.mark.full
def test_hide_avps(accel_ppp):
    """Hidden AVPs sent by accel-ppp (hide-avps) are decrypted by the LAC
    and the hidden proxy authentication AVPs of the LAC by accel-ppp."""
    accel_ppp.start_lns(hide_avps=True)
    accel_ppp.start_lac("CHAP", **{"proxy-lcp": True, "proxy-auth": True, "proxy-auth-hidden": True})
    assert accel_ppp.addresses() == EXPECTED_ADDRESSES
    assert "<Proxy-Authen-Name user1@test>" in accel_ppp.accel_log()
    accel_ppp.terminate()


@pytest.mark.full
def test_access_line(accel_ppp):
    """The optional access line AVPs (RFC 5515) in ICRQ, unknown to
    accel-ppp, are ignored and the sessions are established."""
    accel_ppp.start_lns()
    accel_ppp.start_lac("PAP", access={"agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:{session-global}",
                                       "agent-remote-id": "DEU.RTBRICK.{session-global}",
                                       "rate-up": 2000, "rate-down": 16000, "dsl-type": 5,
                                       "access-line-profile-id": 1},
                        access_line_profiles=[{"access-line-profile-id": 1, "max-up": 5000,
                                               "max-down": 50000, "data-link-encaps": 0x010200,
                                               "pon-type": 2, "etr-down": 1200}])
    assert accel_ppp.addresses() == EXPECTED_ADDRESSES
    accel_ppp.terminate()
