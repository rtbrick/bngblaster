"""
BNG Blaster IPoE sessions with static addresses

A single BNG Blaster instance runs a network interface, answering ARP
for the gateway address, and static IPoE sessions on both ends of a
veth pair (N:1 VLAN mode).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import time

import pytest

from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30
VLAN = 100
GATEWAY = "10.0.0.1"


@pytest.fixture
def bbl(local_veth, processes, tmp_path):
    def start(config):
        instance = BngBlaster(local_veth.ns, tmp_path).start(config, logging=("info", "ip"))
        processes.append(instance)
        return instance
    return start


def ipoe_config(veth, sessions, start_rate=None):
    config = {
        "interfaces": {
            "network": [{"interface": veth.if1, "address": GATEWAY + "/16",
                         "gateway": "10.0.0.2", "vlan": VLAN,
                         "gateway-resolve-wait": False}],
            "access": [{
                "interface": veth.if2,
                "type": "ipoe",
                "vlan-mode": "N:1",
                "outer-vlan": VLAN,
                "ipv6": False,
                "address": "10.0.1.1",
                "address-iter": "0.0.0.1",
                "gateway": GATEWAY
            }]
        },
        "sessions": {"count": sessions, "reconnect": True},
        "dhcp": {"enable": False}
    }
    if start_rate:
        config["sessions"]["start-rate"] = start_rate
    return config


def counters(bbl):
    return bbl.ctrl("session-counters")["session-counters"]


def session_info(bbl, session_id):
    return bbl.ctrl("session-info", **{"session-id": session_id})["session-info"]


def assert_static(bbl, sessions):
    for session_id in range(1, sessions + 1):
        info = session_info(bbl, session_id)
        assert info["session-state"] == "Established", session_id
        assert info["dhcp-state"] == "Disabled", session_id
        assert info["ipv4-address"] == "10.0.1.%d" % session_id, session_id
        assert info["ipv4-gateway"] == GATEWAY, session_id


def test_static_restart(local_veth, bbl):
    """Static sessions keep their address after session-restart,
    session-stop/session-start and do not fall back to DHCP."""
    sessions = 3
    instance = bbl(ipoe_config(local_veth, sessions))
    wait_until(lambda: counters(instance)["sessions-established"] == sessions, 15,
               message="all sessions established")
    assert_static(instance, sessions)

    # Restart (reconnect).
    instance.ctrl("session-restart")
    wait_until(lambda: counters(instance)["sessions-flapped"] == sessions, 10,
               message="all sessions flapped")
    wait_until(lambda: counters(instance)["sessions-established"] == sessions, 15,
               message="all sessions established after restart")
    assert_static(instance, sessions)

    # Stop and start.
    instance.ctrl("session-stop")
    wait_until(lambda: counters(instance)["sessions-established"] == 0, 10,
               message="all sessions stopped")
    instance.ctrl("session-start")
    wait_until(lambda: counters(instance)["sessions-established"] == sessions, 15,
               message="all sessions established after start")
    assert_static(instance, sessions)
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_restart_idle(local_veth, bbl):
    """session-restart of idle sessions during a rate-limited ramp-up
    (sessions-pending | session-restart) must not corrupt the idle queue."""
    sessions = 20
    instance = bbl(ipoe_config(local_veth, sessions, start_rate=5))
    wait_until(lambda: counters(instance)["sessions-established"] >= 2, 10,
               message="first sessions established")

    pending = [s["session-id"] for s in instance.ctrl("sessions-pending")["sessions-pending"]
               if s["session-state"] == "Idle"]
    assert len(pending) > 10
    # Idle sessions behind the queue head, reconnected by the reconnect timer.
    for session_id in pending[5:]:
        instance.ctrl("session-restart", **{"session-id": session_id})
    time.sleep(1.5)
    # And the session-start path for one of them, if still terminated.
    instance.ctrl("session-start", **{"session-id": pending[-1]})

    wait_until(lambda: counters(instance)["sessions-established"] == sessions, 30,
               message="all sessions established")
    assert_static(instance, sessions)
    assert instance.terminate(EXIT_TIMEOUT) == 0
