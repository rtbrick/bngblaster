"""
BNG Blaster L2TP LAC against BNG Blaster L2TP LNS

Namespace A runs the LAC with PPPoL2TP sessions, namespace B the LNS.
Every test ends with a clean exit of both instances within a timeout,
which verifies the L2TP teardown (CDN/StopCCN) of LAC and LNS.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import time

import pytest

from helpers import BngBlaster, wait_until

SESSIONS = 10
LAC_ADDRESS = "10.0.0.1"
LNS_ADDRESS = "10.0.0.2"
EXIT_TIMEOUT = 30


def lac_config(ifname, sessions=SESSIONS, ip6cp=False, keepalive=0, auth="PAP"):
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
                "max-retry": 3
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


def test_lcp_echo_timeout(lac_lns):
    """LNS dies: the LAC detects the LCP echo timeout, tears down all
    sessions and tunnels (retries towards the dead LNS) and exits."""
    lac, lns = lac_lns(keepalive=1)
    lns.kill()
    wait_until(lambda: lac_counters(lac)["sessions-established"] == 0, 15,
               message="LAC sessions down after LCP echo timeout")
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
