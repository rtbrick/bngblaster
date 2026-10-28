"""
BNG Blaster BGP sessions accepted on many local addresses

300 sessions from distinct local addresses (more than the 256 listen
sockets of lwIP) to a peer which never accepts connections but
connects actively to every BNG Blaster address (bgp_sink.py --connect).
The connects of the BNG Blaster are refused, so every session must come
up by a connection accepted on the shared BGP listen socket. Connection
requests to an address without a session are not answered.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import ipaddress
import subprocess
import sys

import helpers
from bgp_common import BBL_ADDRESS, BBL_AS, GOBGP_ADDRESS
from helpers import BgpSink, BngBlaster, wait_until

SESSIONS = 300
SINK_AS = 65001
FIRST_LOCAL = ipaddress.ip_address("10.0.1.1")


def bbl_config(ifname):
    return {
        "interfaces": {
            "network": {
                "interface": ifname,
                "address": BBL_ADDRESS + "/16",
                "gateway": GOBGP_ADDRESS
            }
        },
        "bgp": [{
            "local-address": str(FIRST_LOCAL + i),
            "peer-address": GOBGP_ADDRESS,
            "local-as": BBL_AS,
            "peer-as": SINK_AS,
            "id": BBL_ADDRESS,
            "hold-time": 90,
            "family": ["ipv4-unicast"]
        } for i in range(SESSIONS)]
    }


def test_passive_sessions(topology, processes, tmp_path):
    helpers.kernel_address(topology.b, topology.if_b, GOBGP_ADDRESS + "/16")
    bbl = BngBlaster(topology.a, tmp_path).start(bbl_config(topology.if_a), logging=("info", "bgp"))
    processes.append(bbl)
    sink = BgpSink(topology.b, tmp_path).start(
        ["--asn", str(SINK_AS), "--pause-probability", "0",
         "--connect", str(FIRST_LOCAL), str(SESSIONS)])
    processes.append(sink)

    def sessions():
        return bbl.ctrl("bgp-sessions")["bgp-sessions"]

    try:
        wait_until(lambda: all(s["state"] == "established" for s in sessions()), 90,
                   message="all BGP sessions established")
    except TimeoutError:
        down = [s["local-address"] for s in sessions() if s["state"] != "established"]
        raise AssertionError("%d of %d sessions not established: %s" % (
            len(down), SESSIONS, ", ".join(down[:20])))
    stats = sink.stats()
    assert sorted(stats) == sorted(str(FIRST_LOCAL + i) for i in range(SESSIONS))
    assert all(p["open"] == 1 for p in stats.values())

    # No session for the interface address itself: no SYN-ACK.
    probe = ("import socket, sys\n"
             "s = socket.create_connection(('%s', 179), timeout=3)\n" % BBL_ADDRESS)
    result = subprocess.run(topology.b.cmd([sys.executable, "-I", "-c", probe]),
                            capture_output=True, text=True)
    assert result.returncode != 0 and "timed out" in result.stderr
