"""
BNG Blaster HTTP server and HTTP client

The HTTP server on a network interface is tested with curl and a raw
Python client from the kernel (namespace B). The HTTP client runs on
static IPoE sessions against the HTTP server of the same instance on
both ends of a veth pair.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import sys
import time

import pytest

import helpers
from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30
BBL_ADDRESS, KERNEL_ADDRESS = "10.0.0.1", "10.0.0.2"
BBL_ADDRESS6, KERNEL_ADDRESS6 = "fc00::1", "fc00::2"

RESET_CLIENT = """
import socket, struct, sys
for _ in range(int(sys.argv[2])):
    s = socket.create_connection((sys.argv[1], 80), timeout=5)
    s.sendall(b"GET / HTTP/1.1\\r\\nHost: bbl\\r\\n\\r\\n")
    assert s.recv(1024).startswith(b"HTTP/1.1 200 OK")
    # Close with RST instead of FIN.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
"""


@pytest.fixture
def server(topology, processes, tmp_path):
    """HTTP server on IPv4 and IPv6 of the network interface in namespace A."""
    helpers.kernel_address(topology.b, topology.if_b, KERNEL_ADDRESS + "/24", KERNEL_ADDRESS6 + "/64")
    config = {
        "interfaces": {
            "network": [{"interface": topology.if_a, "address": BBL_ADDRESS + "/24",
                         "gateway": KERNEL_ADDRESS, "address-ipv6": BBL_ADDRESS6 + "/64",
                         "gateway-ipv6": KERNEL_ADDRESS6}]
        },
        "http-server": [
            {"name": "SRV4", "network-interface": topology.if_a, "ipv4-address": BBL_ADDRESS},
            {"name": "SRV6", "network-interface": topology.if_a, "ipv6-address": BBL_ADDRESS6}
        ]
    }
    instance = BngBlaster(topology.a, tmp_path, "bbl").start(config, logging=("info", "http", "tcp"))
    processes.append(instance)
    yield instance
    assert instance.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.parametrize("url", ["http://%s/" % BBL_ADDRESS, "http://[%s]/" % BBL_ADDRESS6])
def test_server_response(topology, server, url):
    """The response has Content-Length 0 and no trailing NUL byte, so curl
    completes the request without waiting for its timeout (RFC 9112 6.3)."""
    start = time.time()
    out = helpers.run(topology.b.cmd(["curl", "-s", "-m", "5", "-o", "/dev/null", "-w",
                                      "%{http_code} %{size_download}", url]), check=False)
    assert out.strip() == "200 0", out
    assert time.time() - start < 3


def test_server_reset(topology, server):
    """Connections reset by the client are deleted."""
    helpers.run(topology.b.cmd([sys.executable, "-c", RESET_CLIENT, BBL_ADDRESS, "3"]))
    wait_until(lambda: open(server.path("log")).read().count("delete connection from %s" % KERNEL_ADDRESS)
               == 3, 15, message="reset connections deleted")


def test_client_session_flap(local_veth, processes, tmp_path):
    """After a session reconnect the HTTP client reports the new response
    (X-Client-Port of the new connection) instead of the old one."""
    config = {
        "interfaces": {
            # The network interface sends all traffic to its gateway, the session.
            "network": [{"interface": local_veth.if1, "address": BBL_ADDRESS + "/16",
                         "gateway": "10.0.1.1", "gateway-resolve-wait": False}],
            "access": [{"interface": local_veth.if2, "type": "ipoe", "vlan-mode": "N:1",
                        "ipv6": False, "address": "10.0.1.1", "gateway": BBL_ADDRESS,
                        "http-client-group-id": 1}]
        },
        "sessions": {"count": 1, "reconnect": True},
        "dhcp": {"enable": False},
        "http-server": [{"name": "SRV", "network-interface": local_veth.if1, "ipv4-address": BBL_ADDRESS}],
        "http-client": [{"name": "CLIENT", "http-client-group-id": 1, "url": "bbl.test",
                         "destination-ipv4-address": BBL_ADDRESS, "autostart": True}]
    }
    instance = BngBlaster(local_veth.ns, tmp_path, "bbl").start(config, logging=("info", "http"))
    processes.append(instance)

    def client_port():
        clients = instance.ctrl("http-clients", **{"session-id": 1}).get("http-clients", [])
        if not clients or clients[0]["response"]["status"] != 200:
            return None
        headers = {h["name"]: h["value"] for h in clients[0]["response"]["headers"]}
        return headers.get("X-Client-Port")

    wait_until(client_port, 20, message="HTTP response")
    port = client_port()
    assert instance.ctrl("session-restart", **{"session-id": 1})["code"] == 200
    wait_until(lambda: instance.ctrl("session-info", **{"session-id": 1})["session-info"]["flapped"] == 1,
               10, message="session flapped")
    wait_until(lambda: client_port() not in (None, port), 20, message="new HTTP response")
    assert instance.terminate(EXIT_TIMEOUT) == 0
