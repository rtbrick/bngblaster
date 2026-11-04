"""
BNG Blaster PPPoE LCP restart (lcp-restart)

A single BNG Blaster instance runs an A10NSP server and PPPoE clients
on both ends of a veth pair. The A10NSP server answers every LCP
configure-request with configure-ack and its own configure-request
(PAP), as a PPP peer in state opened does (RFC 1661). The command
lcp-restart sends a new configure-request on established sessions
without PADT, after which authentication, IPCP and IP6CP are
negotiated again on the same PPPoE session.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import BngBlaster, wait_until

SESSIONS = 4
EXIT_TIMEOUT = 30


@pytest.fixture
def instance(local_veth, processes, tmp_path):
    config = {
        "interfaces": {
            "a10nsp": [{"interface": local_veth.if1}],
            "access": [{
                "interface": local_veth.if2,
                "type": "pppoe",
                "outer-vlan-min": 1,
                "outer-vlan-max": 4000,
                "inner-vlan": 7
            }]
        },
        "sessions": {"count": SESSIONS},
        "session-traffic": {"ipv4-pps": 10, "ipv6-pps": 10}
    }
    bbl = BngBlaster(local_veth.ns, tmp_path).start(config, logging=("info", "pppoe"))
    processes.append(bbl)
    wait_established(bbl)
    return bbl


def counters(bbl):
    return bbl.ctrl("session-counters")["session-counters"]


def wait_established(bbl):
    wait_until(lambda: counters(bbl)["sessions-established"] == SESSIONS, 30,
               message="all sessions established")
    # IPv4 and IPv6 session traffic in both directions
    wait_until(lambda: counters(bbl)["session-traffic-flows-verified"] == 4 * SESSIONS, 15,
               message="session traffic verified")


def session_info(bbl, session_id):
    return bbl.ctrl("session-info", **{"session-id": session_id})["session-info"]


def tx_pap(bbl):
    return bbl.ctrl("access-protocol-stats")["access-protocol-stats"][0]["tx-pap"]


def restarted(before, after):
    """Session renegotiated PPP (state changes) on the same PPPoE session."""
    assert after["session-state"] == "Established"
    assert after["session-version"] > before["session-version"]
    assert after["pppoe-session-id"] == before["pppoe-session-id"]
    assert after["flapped"] == before["flapped"] == 0
    assert after["lcp-state"] == after["ipcp-state"] == after["ip6cp-state"] == "Opened"
    assert after["ipv4-address"] == before["ipv4-address"]


def test_lcp_restart_session(instance):
    before = {i: session_info(instance, i) for i in range(1, SESSIONS + 1)}
    pap = tx_pap(instance)

    assert instance.ctrl("lcp-restart", **{"session-id": 1})["code"] == 200
    wait_until(lambda: session_info(instance, 1)["session-version"] > before[1]["session-version"] and
               session_info(instance, 1)["session-state"] == "Established", 15,
               message="session 1 established after LCP restart")
    wait_established(instance)

    restarted(before[1], session_info(instance, 1))
    for i in range(2, SESSIONS + 1):
        assert session_info(instance, i)["session-version"] == before[i]["session-version"]
    assert tx_pap(instance) == pap + 1
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_lcp_restart_all(instance):
    before = {i: session_info(instance, i) for i in range(1, SESSIONS + 1)}
    pap = tx_pap(instance)

    assert instance.ctrl("lcp-restart")["code"] == 200
    wait_until(lambda: all(session_info(instance, i)["session-version"] > before[i]["session-version"]
                           for i in before), 15, message="all sessions restarted")
    wait_established(instance)

    for i in before:
        restarted(before[i], session_info(instance, i))
    assert tx_pap(instance) == pap + SESSIONS
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_lcp_restart_errors(instance):
    assert instance.ctrl("lcp-restart", **{"session-id": SESSIONS + 1})["code"] == 404
    assert instance.ctrl("lcp-restart", **{"session-group-id": -1})["code"] == 400
    assert instance.terminate(EXIT_TIMEOUT) == 0
