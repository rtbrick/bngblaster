"""
BNG Blaster raw updates over many BGP sessions in parallel

1000 sessions (scale target) from one BNG Blaster to a passive BGP
sink (bgp_sink.py) in namespace B, which accepts all peer addresses
10.1.0.0/16 via a local route. All sessions start their raw update at
the same time against a slow receiver with zero windows, so the lwIP
memory pools shared by all sessions are under pressure. Every session
must complete and the sink must receive every update of every session.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import ipaddress
import time

import helpers
from bgp_common import BBL_ADDRESS, BBL_AS, GOBGP_ADDRESS
from helpers import BgpSink, BngBlaster, bgpupdate, wait_until

SESSIONS = 1000
PREFIXES = 50000
SINK_AS = 65001
PEER_NETWORK = ipaddress.ip_network("10.1.0.0/16")


def peer_addresses():
    return [str(PEER_NETWORK.network_address + 1 + i) for i in range(SESSIONS)]


def bbl_config(ifname, raw_update_file):
    return {
        "interfaces": {
            "network": {
                "interface": ifname,
                "address": BBL_ADDRESS + "/24",
                "gateway": GOBGP_ADDRESS
            }
        },
        "bgp": [{
            "local-address": BBL_ADDRESS,
            "peer-address": peer,
            "local-as": BBL_AS,
            "peer-as": SINK_AS,
            "id": BBL_ADDRESS,
            "hold-time": 90,
            "family": ["ipv4-unicast"],
            "raw-update-file": raw_update_file
        } for peer in peer_addresses()]
    }


def test_raw_update_sessions(topology, processes, tmp_path):
    helpers.kernel_address(topology.b, topology.if_b, GOBGP_ADDRESS + "/24")
    topology.b.exec(["ip", "route", "add", "local", str(PEER_NETWORK), "dev", "lo"])
    sink = BgpSink(topology.b, tmp_path).start(["--asn", str(SINK_AS)])
    processes.append(sink)

    raw_update_file = str(tmp_path / "unicast.bgp")
    bgpupdate(["-f", raw_update_file, "-a", str(BBL_AS), "-n", BBL_ADDRESS,
               "-p", "10.200.0.0/24", "-P", str(PREFIXES), "--end-of-rib"])

    bbl = BngBlaster(topology.a, tmp_path).start(
        bbl_config(topology.if_a, raw_update_file), logging=("info", "bgp"))
    processes.append(bbl)
    updates = bbl.ctrl("bgp-raw-update-list")["bgp-raw-update-list"][0]["updates"]

    def sessions():
        return bbl.ctrl("bgp-sessions")["bgp-sessions"]

    wait_until(lambda: all(s["state"] == "established" for s in sessions()), 60,
               message="all BGP sessions established")

    # Wait until no session makes progress any more, a stalled session
    # stays in sending forever and is reported below.
    deadline = time.monotonic() + 300
    last = None
    while time.monotonic() < deadline:
        current = sink.stats()
        states = [s["raw-update-state"] for s in sessions()]
        if all(state == "done" for state in states):
            break
        if current == last:
            break
        last = current
        time.sleep(10)

    # The sink writes its counters once per second.
    try:
        wait_until(lambda: all(p["update"] == updates for p in sink.stats().values()) and
                   len(sink.stats()) == SESSIONS, 5, message="BGP sink counters")
    except TimeoutError:
        pass
    stats = sink.stats()
    failed = []
    for session in sessions():
        peer = stats.get(session["peer-address"], {})
        if (session["raw-update-state"] != "done" or
                session["stats"]["update-tx"] != updates or
                session["raw-update-bytes-acked"] != session["raw-update-bytes"] or
                peer.get("update") != updates):
            failed.append("%s: %s update-tx %d, acked %d/%d bytes, tcp %s, sink %s" % (
                session["peer-address"], session["raw-update-state"],
                session["stats"]["update-tx"], session["raw-update-bytes-acked"],
                session["raw-update-bytes"], session.get("tcp"), peer.get("update")))
    assert not failed, "%d of %d sessions incomplete (%d updates each):\n%s" % (
        len(failed), SESSIONS, updates, "\n".join(failed[:20]))
    assert bbl.terminate(60) == 0
