"""
BNG Blaster control socket arguments and commands executed by the main loop

Numeric session arguments out of range are rejected instead of being
converted to another session. Commands walking dynamic structures
(e.g. session-info, isis-database) are executed by the main loop.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import BngBlaster


def config(ifname):
    return {
        "interfaces": {
            "network": [{
                "interface": ifname,
                "address": "192.0.2.10/24",
                "gateway": "192.0.2.1"
            }]
        }
    }


@pytest.fixture
def instance(topology, processes, tmp_path):
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    processes.append(instance)
    instance.start(config(topology.if_a))
    yield instance
    assert instance.terminate() == 0


@pytest.mark.parametrize("argument,value", [
    ("session-id", -1),
    ("session-id", 1e12),
    ("session-id", "1"),
    ("ifindex", -1),
    ("outer-vlan", 70000),
    ("outer-vlan", -1),
    ("inner-vlan", 1e9),
])
def test_invalid_session_argument(instance, argument, value):
    response = instance.ctrl("session-info", **{argument: value})
    assert response["code"] == 400


def test_main_loop_commands(instance):
    # Repeated requests of commands executed by the main loop.
    for _ in range(20):
        assert instance.ctrl("session-info", **{"session-id": 1})["code"] in (400, 404)
        assert instance.ctrl("li-flows")["code"] == 200
        assert instance.ctrl("l2tp-tunnels")["code"] == 200
    assert instance.ctrl("network-interfaces")["code"] == 200
