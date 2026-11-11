"""
BNG Blaster L2TP LAC against BNG Blaster L2TP LNS

Namespace A runs the LAC with PPPoL2TP sessions, namespace B the LNS.
Every test ends with a clean exit of both instances within a timeout,
which verifies the L2TP teardown (CDN/StopCCN) of LAC and LNS.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

import helpers
from helpers import BngBlaster, wait_until

SESSIONS = 10
LAC_ADDRESS = "10.0.0.1"
LNS_ADDRESS = "10.0.0.2"
EXIT_TIMEOUT = 30


def lac_config(ifname, sessions=SESSIONS, ip6cp=False, keepalive=0, auth="PAP",
               client_options=None):
    """client_options maps the LAC number (1 or 2) to additional
    l2tp-client options of this LAC."""
    client_options = client_options or {}
    return {
        "interfaces": {
            "network": {
                "interface": ifname,
                "address": LAC_ADDRESS + "/24",
                "gateway": LNS_ADDRESS
            },
            "access": [
                {
                    "interface": ifname,
                    "type": "pppol2tp",
                    "l2tp-client-group-id": 1,
                    "outer-vlan-min": 1,
                    "outer-vlan-max": 4000,
                    "authentication-protocol": auth
                }
            ]
        },
        "sessions": {
            "count": sessions,
            "start-rate": 100,
            "stop-rate": 100,
            "reconnect": False
        },
        "ppp": {
            "authentication": {
                "username": "user{session-global}@test",
                "password": "test"
            },
            "lcp": {
                "conf-request-timeout": 1,
                "conf-request-retry": 10,
                "keepalive-interval": keepalive,
                "keepalive-retry": 3
            },
            "ipcp": {"enable": True},
            "ip6cp": {"enable": ip6cp}
        },
        "session-traffic": {
            "autostart": False,
            "ipv4-pps": 10
        },
        "l2tp-client": [
            {
                "group-id": 1,
                "name": "LAC%d" % i,
                "network-interface": ifname,
                "client-address": "10.0.0.1%d" % i,
                "server-address": LNS_ADDRESS,
                "secret": "test",
                "max-retry": 3,
                **client_options.get(i, {})
            } for i in (1, 2)
        ]
    }


def lns_config(ifname, lcp_conf_request=True):
    return {
        "interfaces": {
            "network": {
                "interface": ifname,
                "address": LNS_ADDRESS + "/24",
                "gateway": LAC_ADDRESS
            }
        },
        "l2tp-server": [
            {
                "name": "LNS",
                "address": LNS_ADDRESS,
                "secret": "test",
                "max-retry": 3,
                "lcp-conf-request": lcp_conf_request
            }
        ]
    }


def lac_counters(lac):
    return lac.ctrl("session-counters")["session-counters"]


def lns_sessions(lns, state="Established"):
    return [s for s in lns.ctrl("l2tp-sessions")["l2tp-sessions"] if s["state"] == state]


def lns_tunnels(lns, state="Established"):
    return [t for t in lns.ctrl("l2tp-tunnels")["l2tp-tunnels"] if t["state"] == state]


@pytest.fixture
def lac_lns(topology, processes, tmp_path):
    """Start LNS and LAC and wait until all sessions are established."""
    def start(**lac_args):
        lns = BngBlaster(topology.b, tmp_path, "lns").start(
            lns_config(topology.if_b), logging=("info", "l2tp"))
        processes.append(lns)
        lac = BngBlaster(topology.a, tmp_path, "lac").start(
            lac_config(topology.if_a, **lac_args), logging=("info", "l2tp", "pppoe"))
        processes.append(lac)
        sessions = lac_args.get("sessions", SESSIONS)
        wait_until(lambda: lac_counters(lac)["sessions-established"] == sessions,
                   30, message="LAC sessions established")
        wait_until(lambda: len(lns_sessions(lns)) == sessions,
                   10, message="LNS sessions established")
        return lac, lns
    return start


def assert_clean_exit(lac, lns):
    """Terminate LAC first (CDN/StopCCN towards LNS), then LNS."""
    assert lac.terminate(EXIT_TIMEOUT) == 0
    wait_until(lambda: not lns_sessions(lns), 10, message="LNS sessions removed")
    assert lns.terminate(EXIT_TIMEOUT) == 0


def test_setup_traffic_teardown(lac_lns):
    lac, lns = lac_lns()
    assert len(lns_tunnels(lns)) == 2
    # l2tp-sessions lists the LAC sessions as well.
    assert len(lns_sessions(lac)) == SESSIONS

    lac.ctrl("session-traffic-start")
    wait_until(lambda: all(s["data-ipv4-packets-rx"] >= 20 for s in lns_sessions(lns)),
               15, message="LNS session traffic")
    lac.ctrl("session-traffic-stop")

    def upstream_tx():
        total = 0
        for session_id in range(1, SESSIONS + 1):
            info = lac.ctrl("session-info", **{"session-id": session_id})["session-info"]
            total += info["session-traffic"]["upstream-ipv4-tx-packets"]
        return total

    # Upstream packets sent by the LAC must all be received by the LNS.
    wait_until(lambda: sum(s["data-ipv4-packets-rx"] for s in lns_sessions(lns)) == upstream_tx(),
               5, message="no session traffic loss")
    assert_clean_exit(lac, lns)


def test_ppp_terminate_from_lac(lac_lns):
    """LCP terminate of a PPPoL2TP session must send CDN to the LNS."""
    lac, lns = lac_lns()
    lac.ctrl("session-stop", **{"session-id": 1})
    wait_until(lambda: len(lns_sessions(lns)) == SESSIONS - 1, 10,
               message="LNS session removed after LCP terminate")
    wait_until(lambda: lac_counters(lac)["sessions-established"] == SESSIONS - 1, 10,
               message="LAC session terminated")
    assert_clean_exit(lac, lns)


def test_l2tp_session_terminate_from_lac(lac_lns):
    lac, lns = lac_lns()
    response = lac.ctrl("l2tp-session-terminate", **{"session-id": 1})
    assert response["code"] == 200, response
    wait_until(lambda: len(lns_sessions(lns)) == SESSIONS - 1, 10,
               message="LNS session removed after CDN")
    wait_until(lambda: lac_counters(lac)["sessions-established"] == SESSIONS - 1, 10,
               message="LAC session terminated")
    assert_clean_exit(lac, lns)


def tunnel_session_counts(bbl):
    """Return (sessions, sessions-established) summed over all tunnels and
    check that the counts of each tunnel match its l2tp-sessions."""
    sessions = established = 0
    for tunnel in bbl.ctrl("l2tp-tunnels")["l2tp-tunnels"]:
        listed = bbl.ctrl("l2tp-sessions", **{"tunnel-id": tunnel["tunnel-id"]})["l2tp-sessions"]
        assert tunnel["sessions"] == len(listed), tunnel
        assert tunnel["sessions-established"] == \
            len([s for s in listed if s["state"] == "Established"]), tunnel
        sessions += tunnel["sessions"]
        established += tunnel["sessions-established"]
    return sessions, established


def test_tunnel_session_counts(lac_lns):
    """l2tp-tunnels reports the sessions of each tunnel on LNS and LAC."""
    lac, lns = lac_lns()
    for bbl in (lns, lac):
        assert tunnel_session_counts(bbl) == (SESSIONS, SESSIONS)

    for session_id in (1, 2):
        response = lac.ctrl("l2tp-session-terminate", **{"session-id": session_id})
        assert response["code"] == 200, response
    for bbl in (lns, lac):
        wait_until(lambda: tunnel_session_counts(bbl) == (SESSIONS - 2, SESSIONS - 2), 10,
                   message="tunnel sessions after terminate")
    assert_clean_exit(lac, lns)


def test_csurq(lac_lns):
    """Connect speed update requests are limited to the number of AVPs
    fitting into a control message, invalid session IDs are ignored."""
    lac, lns = lac_lns()
    tunnel_id = lns_tunnels(lns)[0]["tunnel-id"]
    csurq = lambda sessions: lns.ctrl("l2tp-csurq", **{"tunnel-id": tunnel_id, "sessions": sessions})
    assert csurq(list(range(1, 51)))["code"] == 200
    assert csurq(list(range(1, 61)))["code"] == 400
    assert csurq([1, -1, "x", 70000])["code"] == 200
    assert_clean_exit(lac, lns)


def test_l2tp_tunnel_terminate_from_lns(lac_lns):
    lac, lns = lac_lns()
    tunnel_id = lns_tunnels(lns)[0]["tunnel-id"]
    remaining = len([s for s in lns_sessions(lns) if s["tunnel-id"] != tunnel_id])
    assert 0 < remaining < SESSIONS
    response = lns.ctrl("l2tp-tunnel-terminate", **{"tunnel-id": tunnel_id})
    assert response["code"] == 200, response
    # The tunnel is deleted with all sessions after StopCCN (up to 5s).
    wait_until(lambda: len(lns_sessions(lns)) == remaining, 15,
               message="LNS sessions of terminated tunnel removed")
    wait_until(lambda: lac_counters(lac)["sessions-established"] == remaining, 15,
               message="LAC sessions of terminated tunnel down")
    assert_clean_exit(lac, lns)


@pytest.mark.slow
def test_lcp_echo_timeout(lac_lns):
    """LNS dies: the LAC detects the LCP echo timeout, tears down all
    sessions and tunnels (retries towards the dead LNS) and exits."""
    lac, lns = lac_lns(keepalive=1)
    lns.kill()
    wait_until(lambda: lac_counters(lac)["sessions-established"] == 0, 15,
               message="LAC sessions down after LCP echo timeout")
    stats = lac.ctrl("access-protocol-stats")["access-protocol-stats"]
    assert sum(i["lcp-echo-expired"] for i in stats) == SESSIONS
    name = stats[0]["name"]
    assert [i["name"] for i in lac.ctrl("access-protocol-stats", interface=name)["access-protocol-stats"]] == [name]
    assert lac.ctrl("access-protocol-stats", interface="unknown")["access-protocol-stats"] == []
    assert lac.terminate(60) == 0


def test_dual_stack(lac_lns):
    lac, lns = lac_lns(sessions=2, ip6cp=True)

    def ipv6_ready(session_id):
        info = lac.ctrl("session-info", **{"session-id": session_id})["session-info"]
        return info.get("ip6cp-state") == "Opened" and info.get("ipv6-prefix")

    for session_id in (1, 2):
        wait_until(lambda: ipv6_ready(session_id), 10, message="IP6CP and RA")
    assert_clean_exit(lac, lns)


def test_chap(lac_lns):
    """The LNS proposes PAP, switches to CHAP after the Conf-Nak of the
    client and sends the CHAP challenge once LCP is opened."""
    lac, lns = lac_lns(sessions=2, auth="CHAP")
    assert_clean_exit(lac, lns)


def test_lcp_conf_request_disabled(topology, processes, tmp_path):
    """Without LCP Conf-Request from LNS (and no proxy LCP from the LAC)
    the PPP sessions can't complete LCP."""
    lns = BngBlaster(topology.b, tmp_path, "lns").start(
        lns_config(topology.if_b, lcp_conf_request=False), logging=("info", "l2tp"))
    processes.append(lns)
    lac = BngBlaster(topology.a, tmp_path, "lac").start(
        lac_config(topology.if_a, sessions=2), logging=("info", "l2tp", "pppoe"))
    processes.append(lac)
    wait_until(lambda: len(lns_sessions(lns)) == 2, 10, message="LNS sessions established")
    time.sleep(3)
    assert lac_counters(lac)["sessions-established"] == 0
    assert_clean_exit(lac, lns)


PAP, CHAP = 0xc023, 0xc223
PAP_ACK, CHAP_SUCCESS = 2, 3


@pytest.mark.parametrize("auth,auth_id,proxy_auth,expected", [
    ("pap", 7, None, [(PAP, PAP_ACK, 7)]),
    ("chap", 42, None, [(CHAP, CHAP_SUCCESS, 42)]),
    # Without the Proxy Authen ID the identifier of the client request
    # is unknown, so the LNS waits for the request of the client.
    ("pap", None, None, []),
    ("pap", 7, False, []),
    ("chap", 42, False, []),
])
def test_proxy_auth(topology, processes, tmp_path, auth, auth_id, proxy_auth, expected):
    """With proxy authentication (RFC 2661) the LNS sends PAP
    Authenticate-Ack or CHAP Success immediately after the ICCN instead
    of waiting for a retransmitted request of the client (issue #154)."""
    config = lns_config(topology.if_b)
    del config["l2tp-server"][0]["secret"]
    if proxy_auth is not None:
        config["l2tp-server"][0]["proxy-auth"] = proxy_auth
    lns = BngBlaster(topology.b, tmp_path, "lns").start(config, logging=("info", "l2tp"))
    processes.append(lns)
    helpers.kernel_address(topology.a, topology.if_a, LAC_ADDRESS + "/24")

    cmd = [sys.executable, "-I", str(Path(__file__).parent / "l2tp_proxy_lac.py"),
           "--local", LAC_ADDRESS, "--server", LNS_ADDRESS, "--auth", auth]
    if auth_id is not None:
        cmd += ["--auth-id", str(auth_id)]
    result = subprocess.run(topology.a.cmd(cmd), capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert [tuple(p) for p in json.loads(result.stdout)] == expected

    session = lns_sessions(lns)[0]
    assert session["peer-proxy-auth-name"] == "user@proxy"


def lns_sessions_by_lac(lns):
    """Map LAC name (peer name of the tunnel) to its LNS sessions."""
    names = {t["tunnel-id"]: t["peer-name"] for t in lns_tunnels(lns)}
    sessions = {}
    for session in lns_sessions(lns):
        sessions.setdefault(names[session["tunnel-id"]], []).append(session)
    return sessions


def connect_speed_avp(avp_type, value, mandatory):
    """L2TP AVP (RFC 2661) with 32 bit value as sent in ICCN."""
    flags_len = (0x8000 if mandatory else 0) | 10
    return struct.pack("!HHHI", flags_len, 0, avp_type, value)


def test_connect_speed(lac_lns):
    """TX (AVP 24) and RX (AVP 38) connect speeds are configurable per
    LAC, the defaults (100 Mbps TX, no RX) remain unchanged."""
    lac, lns = lac_lns(sessions=4, client_options={
        1: {"tx-connect-speed": 22001000, "rx-connect-speed": 1172000}})
    sessions = lns_sessions_by_lac(lns)
    assert set(sessions) == {"LAC1", "LAC2"}
    for session in sessions["LAC1"]:
        assert (session["peer-tx-bps"], session["peer-rx-bps"]) == (22001000, 1172000)
    for session in sessions["LAC2"]:
        assert (session["peer-tx-bps"], session["peer-rx-bps"]) == (100000000, 0)
    assert_clean_exit(lac, lns)

    # The M-bit is set for TX and must not be set for RX connect speed.
    with open(lac.path("pcap"), "rb") as f:
        pcap = f.read()
    assert connect_speed_avp(24, 22001000, True) in pcap
    assert connect_speed_avp(38, 1172000, False) in pcap
    assert connect_speed_avp(24, 100000000, True) in pcap
    assert struct.pack("!HHH", 10, 0, 38) + struct.pack("!I", 0) not in pcap


def test_connect_speed_limits(lac_lns):
    """Connect speeds use the full 32 bit range of the AVP."""
    lac, lns = lac_lns(sessions=4, client_options={
        1: {"tx-connect-speed": 4294967295, "rx-connect-speed": 4294967295},
        2: {"tx-connect-speed": 1, "rx-connect-speed": 1}})
    sessions = lns_sessions_by_lac(lns)
    for session in sessions["LAC1"]:
        assert (session["peer-tx-bps"], session["peer-rx-bps"]) == (4294967295, 4294967295)
    for session in sessions["LAC2"]:
        assert (session["peer-tx-bps"], session["peer-rx-bps"]) == (1, 1)
    assert_clean_exit(lac, lns)


@pytest.mark.parametrize("option", ["tx-connect-speed", "rx-connect-speed"])
@pytest.mark.parametrize("value", [0, 4294967296, "100M"])
def test_connect_speed_invalid(topology, tmp_path, option, value):
    lac = BngBlaster(topology.a, tmp_path, "lac")
    with pytest.raises(RuntimeError, match="exited on start"):
        lac.start(lac_config(topology.if_a, sessions=1, client_options={1: {option: value}}))
    with open(lac.path("stdout")) as f:
        assert "Invalid value for l2tp-client->%s" % option in f.read()


def test_invalid_icrq(topology, processes, tmp_path):
    """An invalid ICRQ is rejected with a CDN to the session ID of the
    LAC (RFC 2661) and is not counted as session, a valid ICRQ with the
    Broadband Forum ACI and ARI AVPs is accepted and cleared by the LAC.
    A CDN with session ID 0, sent by a LAC which clears the call before
    the ICRP is received, deletes the session by the Assigned Session ID
    of the LAC (issue #396, the session was kept and counted)."""
    config = lns_config(topology.if_b)
    del config["l2tp-server"][0]["secret"]
    lns = BngBlaster(topology.b, tmp_path, "lns").start(config, logging=("info", "l2tp"))
    processes.append(lns)
    helpers.kernel_address(topology.a, topology.if_a, LAC_ADDRESS + "/24")

    cmd = [sys.executable, "-I", str(Path(__file__).parent / "l2tp_proxy_lac.py"),
           "--local", LAC_ADDRESS, "--server", LNS_ADDRESS, "--icrq"]
    result = subprocess.run(topology.a.cmd(cmd), capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    replies = json.loads(result.stdout)
    assert replies["cdn-session-id"] == 201
    assert replies["cdn-result-code"] == 2
    assert replies["icrp"]
    wait_until(lambda: not lns.ctrl("l2tp-sessions")["l2tp-sessions"], 5,
               message="LNS session cleared by CDN")

    assert lns.terminate(30) == 0
    # The rejected ICRQ is not counted (the maximum would be 2).
    assert lns.report()["report"]["l2tp"]["sessions"] == 1



def start_pair(topology, processes, tmp_path, sessions=2, update=None):
    """Start LNS and LAC, update modifies the LAC config."""
    lns = BngBlaster(topology.b, tmp_path, "lns").start(
        lns_config(topology.if_b), logging=("info", "l2tp"))
    processes.append(lns)
    config = lac_config(topology.if_a, sessions=sessions)
    if update:
        update(config)
    lac = BngBlaster(topology.a, tmp_path, "lac").start(config, logging=("info", "l2tp", "pppoe"))
    processes.append(lac)
    wait_until(lambda: lac_counters(lac)["sessions-established"] == sessions,
               30, message="LAC sessions established")
    return lac, lns


def test_session_traffic_both_directions(topology, processes, tmp_path):
    """Downstream session traffic of PPPoL2TP sessions is sent as IP from
    the network interface (routed by the LNS), upstream through the tunnel
    is counted in the network interface and session statistics."""
    lac, lns = start_pair(topology, processes, tmp_path)
    lac.ctrl("session-traffic-start")

    def streams(direction):
        return [s for s in lac.ctrl("session-streams", **{"session-id": 1})["session-streams"]["streams"]
                if s["direction"] == direction]

    wait_until(lambda: streams("downstream") and all(s["tx-packets"] >= 10 for s in streams("downstream")),
               10, message="downstream session traffic sent")
    assert all(s["tx-packets"] >= 10 for s in streams("upstream"))
    lac.ctrl("session-traffic-stop")
    network = lac.ctrl("network-interfaces")["network-interfaces"][0]
    assert network["tx-packets-streams"] > 0 and network["tx-packets-session-ipv4"] > 0, network
    assert lac.ctrl("session-streams", **{"session-id": 1})["session-streams"]["tx-packets"] > 0
    assert "Failed to build packet" not in open(lac.path("log")).read()
    assert_clean_exit(lac, lns)


def test_stream_ports(topology, processes, tmp_path):
    """Upstream streams of PPPoL2TP sessions use the iterated ports of each
    stream (captured inside the L2TP tunnel in the LNS namespace)."""
    def update(config):
        config["interfaces"]["access"][0]["stream-group-id"] = 1
        config["streams"] = [{"name": "S1", "stream-group-id": 1, "type": "ipv4", "direction": "upstream",
                              "pps": 10, "source-port": 10000, "source-port-step": 1,
                              "source-port-max": 10010, "destination-port": 20000}]
        config["traffic"] = {"autostart": False}

    lac, lns = start_pair(topology, processes, tmp_path, sessions=3, update=update)
    ports = set()
    for session_id in (1, 2, 3):
        for stream in lac.ctrl("session-streams", **{"session-id": session_id})["session-streams"]["streams"]:
            if stream["name"] == "S1":
                ports.add(stream["source-port"])
    assert len(ports) == 3, ports
    capture = subprocess.Popen(topology.b.cmd(["timeout", "8", "tcpdump", "-nn", "-l", "-i", topology.if_b,
                                               "udp port 1701"]),
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(1)
    lac.ctrl("traffic-start")
    out = capture.communicate(timeout=15)[0]
    lac.ctrl("traffic-stop")
    seen = {int(p) for p in __import__("re").findall(r"\.(\d+) > [\d.]+\.20000:", out)}
    assert seen == ports, (seen, ports)
    assert_clean_exit(lac, lns)


def test_icmp_client(topology, processes, tmp_path):
    """The ICMP client of a PPPoL2TP session sends through the tunnel."""
    def update(config):
        config["interfaces"]["access"][0]["icmp-client-group-id"] = 1
        config["icmp-client"] = [{"icmp-client-group-id": 1, "destination-address": "192.0.2.1",
                                  "interval": 0.2}]

    lac, lns = start_pair(topology, processes, tmp_path, sessions=1, update=update)
    wait_until(lambda: lns_sessions(lns) and lns_sessions(lns)[0]["data-ipv4-packets-rx"] >= 3, 10,
               message="ICMP requests received by the LNS")
    assert_clean_exit(lac, lns)


def test_session_restart(topology, processes, tmp_path):
    """session-restart restarts a PPPoL2TP session without reconnect."""
    lac, lns = start_pair(topology, processes, tmp_path)
    assert lac.ctrl("session-restart", **{"session-id": 1})["code"] == 200
    wait_until(lambda: lac.ctrl("session-info", **{"session-id": 1})["session-info"]["flapped"] == 1, 10,
               message="session flapped")
    wait_until(lambda: lac_counters(lac)["sessions-established"] == 2, 20, message="session established again")
    assert_clean_exit(lac, lns)


def test_lac_lns_same_instance(local_veth, processes, tmp_path):
    """LAC and LNS in one instance: the PAP reply of the LNS naming its own
    session does not relink the LAC session to the LNS session, which sent
    all upstream packets back into the LNS tunnel and terminated the
    sessions by LCP echo timeout."""
    config = lac_config(local_veth.if1, sessions=1, keepalive=1)
    lns = lns_config(local_veth.if2)
    config["interfaces"]["network"] = [config["interfaces"]["network"], lns["interfaces"]["network"]]
    config["l2tp-server"] = lns["l2tp-server"]
    config["l2tp-client"] = config["l2tp-client"][:1]
    bbl = BngBlaster(local_veth.ns, tmp_path, "bbl").start(config, logging=("info", "l2tp"))
    processes.append(bbl)
    wait_until(lambda: lac_counters(bbl)["sessions-established"] == 1, 15, message="session established")
    lac_tunnel = [t["tunnel-id"] for t in bbl.ctrl("l2tp-tunnels")["l2tp-tunnels"] if "client-name" in t]
    assert len(lac_tunnel) == 1
    lac_tunnel = lac_tunnel[0]
    time.sleep(8)
    info = bbl.ctrl("session-info", **{"session-id": 1})["session-info"]
    assert info["session-state"] == "Established", info
    assert info["l2tp"]["tunnel-id"] == lac_tunnel
    assert "Tunnelled session with BNG Blaster LNS" not in open(bbl.path("log")).read()
    assert bbl.terminate(EXIT_TIMEOUT) == 0


def test_stream_a10nsp_config_error(local_veth, processes, tmp_path):
    """A PPPoL2TP upstream stream without network interface (A10NSP
    selected) is a configuration error instead of a crash."""
    config = lac_config(local_veth.if1, sessions=1)
    config["interfaces"]["a10nsp"] = [{"interface": local_veth.if2}]
    config["interfaces"]["access"][0]["stream-group-id"] = 1
    config["streams"] = [{"name": "S1", "stream-group-id": 1, "type": "ipv4", "direction": "upstream",
                          "pps": 1, "a10nsp-interface": local_veth.if2}]
    bbl = BngBlaster(local_veth.ns, tmp_path, "lac")
    processes.append(bbl)
    with pytest.raises(RuntimeError) as error:
        bbl.start(config)
    assert bbl.proc.returncode > 0, str(error.value)
    assert "requires a network interface" in open(bbl.path("log")).read()


@pytest.mark.slow
def test_retransmission_backoff(topology, processes, tmp_path):
    """Control messages to a dead LNS are retransmitted with backoff capped
    at 8 seconds, so max-retry 6 is reached after about 39 seconds."""
    # Gateway resolved, but no LNS listening.
    helpers.kernel_address(topology.b, topology.if_b, LNS_ADDRESS + "/24")
    config = lac_config(topology.if_a, sessions=1, client_options={1: {"max-retry": 6}, 2: {"max-retry": 6}})
    lac = BngBlaster(topology.a, tmp_path, "lac").start(config, logging=("info", "l2tp"))
    processes.append(lac)
    start = time.monotonic()
    wait_until(lambda: "max retry" in open(lac.path("log")).read(), 60, interval=1, message="max retry")
    assert time.monotonic() - start < 50
    assert lac.terminate(EXIT_TIMEOUT) == 0
