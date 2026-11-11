"""
BNG Blaster control socket arguments and commands executed by the main loop

Numeric session arguments out of range are rejected instead of being
converted to another session. Commands walking dynamic structures
(e.g. session-info, isis-database) are executed by the main loop.
Clients which stall a request or response are timed out and do not
block the main loop.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import socket
import time

import pytest

import helpers
from helpers import BngBlaster, lspgen, wait_until


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


@pytest.mark.parametrize("request_data", [b"", b'{"command": '])
def test_idle_client(instance, request_data):
    """A client which does not send a complete request is timed out, other
    commands are answered afterwards and the instance exits (fixture)."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(instance.socket)
    client.sendall(request_data)
    try:
        # The request waits for the idle client timeout (10 seconds).
        start = time.time()
        request = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        request.settimeout(30)
        request.connect(instance.socket)
        request.sendall(json.dumps({"command": "test-info"}).encode())
        data = b""
        while True:
            chunk = request.recv(65536)
            if not chunk:
                break
            data += chunk
        request.close()
        assert json.loads(data)["code"] == 200
        assert time.time() - start < 15
    finally:
        client.close()


@pytest.mark.parametrize("arguments", [
    {"session-id": 0},
    {"ifindex": 5},
    {"session-group-id": 5},
])
def test_terminate_selector(instance, arguments):
    """terminate with a session selector which matches no session does not
    stop the test, session-group-id is not supported."""
    assert instance.ctrl("terminate", **arguments)["code"] in (400, 404)
    time.sleep(1)
    assert instance.alive()
    assert instance.ctrl("test-info")["test-info"]["status"] == "running"


def test_stalled_client_main_loop(topology, processes, tmp_path):
    """A client which does not read the large response of a command executed
    by the main loop (isis-database) does not stop the main loop, the BNG
    Blaster answers ping meanwhile."""
    mrt = str(tmp_path / "isis.mrt")
    lspgen(["-a", "49.0001/24", "-c", "5000", "-C", "0000.0000.0001", "-m", mrt], timeout=120)
    helpers.kernel_address(topology.b, topology.if_b, "192.0.2.1/24")
    conf = config(topology.if_a)
    conf["interfaces"]["network"][0].update({"isis-instance-id": 1, "isis-level": 1})
    conf["isis"] = [{"instance-id": 1, "area": ["49.0001/24"], "system-id": "0000.0000.0001",
                     "external": {"mrt-file": mrt, "connections": [
                         {"system-id": "1921.6800.0000.00", "l1-metric": 1000}]}}]
    instance = BngBlaster(topology.a, tmp_path, "bbl").start(conf, logging=("info", "isis"))
    processes.append(instance)
    wait_until(lambda: len(instance.ctrl("isis-database", instance=1, level=1)["isis-database"]) > 1000,
               30, message="ISIS database loaded")

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    client.connect(instance.socket)
    client.sendall(json.dumps({"command": "isis-database",
                               "arguments": {"instance": 1, "level": 1}}).encode())
    try:
        time.sleep(0.5)
        out = helpers.run(topology.b.cmd(["ping", "-n", "-q", "-i", "0.2", "-c", "15", "-W", "1",
                                          "192.0.2.10"]), check=False)
    finally:
        client.close()
    assert " 15 received" in out or " 14 received" in out, out
    assert instance.ctrl("test-info")["code"] == 200
    assert instance.terminate() == 0


def test_socket_used_by_other_instance(instance, topology, processes, tmp_path):
    """A second instance with the control socket path of a running instance
    fails without removing that socket (it unlinked the socket of the
    running instance, which kept running without control socket)."""
    other = BngBlaster(topology.b, tmp_path, "other")
    other.socket = instance.socket
    processes.append(other)
    # The socket path exists already, so start() can return before the
    # second instance exited (test-info is answered by the first one).
    try:
        other.start(config(topology.if_b), wait_started=False)
    except RuntimeError:
        pass
    wait_until(lambda: other.proc.poll() is not None, 10, 0.1, "second instance exit")
    assert other.proc.returncode != 0
    assert "used by another instance" in open(other.path("stdout")).read()
    assert instance.ctrl("test-info")["code"] == 200
