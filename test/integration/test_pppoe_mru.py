"""
BNG Blaster PPPoE LCP MRU negotiation with PPP-Max-Payload (RFC 4638)

The BNG Blaster PPPoE client runs against a minimal PPPoE server
(pppoe_server.py). An MRU larger than 1492 may be accepted from or
suggested by the server only if the server echoed a larger
PPP-Max-Payload tag. A configure-request with a larger MRU is answered
with configure-nak suggesting the maximum, and a configure-nak
suggesting a larger MRU is limited to the maximum.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import BngBlaster, wait_until

CONF_REQUEST, CONF_ACK, CONF_NAK = 1, 2, 3


@pytest.fixture
def server(topology, tmp_path):
    started = []

    def start(*args):
        log = str(tmp_path / "pppoe_server.json")
        cmd = [sys.executable, str(Path(__file__).parent / "pppoe_server.py"),
               "--interface", topology.if_b, "--log", log] + [str(a) for a in args]
        with open(str(tmp_path / "pppoe_server.log"), "w") as out:
            proc = subprocess.Popen(topology.b.cmd(cmd), stdout=out, stderr=subprocess.STDOUT)
        started.append(proc)
        wait_until(lambda: os.path.exists(log) or proc.poll() is not None, 10, 0.2, "PPPoE server")
        if proc.poll() is not None:
            raise RuntimeError("PPPoE server exited on start, see pppoe_server.log")
        return log
    yield start
    for proc in started:
        proc.terminate()
        proc.wait(10)


def received(log):
    """LCP configure packets received by the server from the client."""
    with open(log) as f:
        return [json.loads(line) for line in f]


def config(ifname, mru, max_payload=None):
    config = {
        "interfaces": {
            "access": [{
                "interface": ifname,
                "type": "pppoe",
                "outer-vlan-min": 100,
                "outer-vlan-max": 100
            }]
        },
        "sessions": {"count": 1},
        "ppp": {"mru": mru}
    }
    if max_payload:
        config["pppoe"] = {"max-payload": max_payload}
    return config


def mru_invalid(instance):
    return instance.ctrl("access-protocol-stats")["access-protocol-stats"][0]["lcp-mru-invalid"]


def start(topology, processes, tmp_path, mru, max_payload=None):
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    processes.append(instance)
    instance.start(config(topology.if_a, mru, max_payload), logging=("info", "pppoe"))
    return instance


def responses(log, code):
    """MRU of client responses (ack/nak) to configure-requests of the server."""
    return [p["mru"] for p in received(log) if p["code"] == code]


@pytest.mark.parametrize("max_payload,echo,server_mru,expected", [
    # Server requests an MRU above the echoed PPP-Max-Payload.
    (1570, True, 1600, 1570),
    # Server requests more than 1492 without echoing PPP-Max-Payload.
    (1570, False, 1600, 1492),
    # Server requests more than 1492 without PPP-Max-Payload requested.
    (None, False, 1500, 1492),
])
def test_nak_peer_mru(topology, processes, tmp_path, server, max_payload, echo, server_mru, expected):
    log = server("--mru", server_mru, *(["--echo-max-payload"] if echo else []))
    instance = start(topology, processes, tmp_path, 1570 if echo else 1492, max_payload)

    wait_until(lambda: responses(log, CONF_ACK), 15, message="configure-ack of server request")
    assert responses(log, CONF_NAK) == [expected]
    assert responses(log, CONF_ACK) == [expected]
    assert mru_invalid(instance) == 1
    assert instance.terminate() == 0


@pytest.mark.parametrize("max_payload,echo,server_mru", [
    (1570, True, 1570),
    (1570, True, 1500),
    (None, False, 1492),
    (1570, False, 1492),
])
def test_ack_peer_mru(topology, processes, tmp_path, server, max_payload, echo, server_mru):
    log = server("--mru", server_mru, *(["--echo-max-payload"] if echo else []))
    instance = start(topology, processes, tmp_path, 1492, max_payload)

    wait_until(lambda: responses(log, CONF_ACK), 15, message="configure-ack of server request")
    assert responses(log, CONF_NAK) == []
    assert responses(log, CONF_ACK) == [server_mru]
    assert mru_invalid(instance) == 0
    assert instance.terminate() == 0


@pytest.mark.parametrize("max_payload,echo,client_mru,nak_mru,expected,invalid", [
    # Server suggests an MRU above the echoed PPP-Max-Payload.
    (1570, True, 1570, 1600, 1570, 1),
    # Server suggests more than 1492 without echoing PPP-Max-Payload.
    (None, False, 1492, 1500, 1492, 1),
    # Server suggests an allowed MRU.
    (1570, True, 1492, 1570, 1570, 0),
])
def test_peer_nak_mru(topology, processes, tmp_path, server,
                      max_payload, echo, client_mru, nak_mru, expected, invalid):
    log = server("--nak-mru", nak_mru, *(["--echo-max-payload"] if echo else []))
    instance = start(topology, processes, tmp_path, client_mru, max_payload)

    requests = lambda: [p["mru"] for p in received(log) if p["code"] == CONF_REQUEST]
    wait_until(lambda: len(requests()) >= 2, 15, message="configure-request after configure-nak")
    assert requests()[:2] == [client_mru, expected]
    assert mru_invalid(instance) == invalid
    assert instance.terminate() == 0
