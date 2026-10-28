"""
BNG Blaster BGP control command address filters

One IPv4 and one IPv6 BGP session without a peer: the IPv4 and IPv6
address filters of bgp-sessions, bgp-raw-update and bgp-disconnect
select only sessions of their own address family.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from bgp_common import BBL_ADDRESS, BBL_ADDRESS6, BBL_AS, GOBGP_ADDRESS, GOBGP_ADDRESS6
from helpers import BngBlaster, bgpupdate

V4 = {"local-ipv4-address": BBL_ADDRESS, "peer-ipv4-address": GOBGP_ADDRESS}
V6 = {"local-ipv6-address": BBL_ADDRESS6, "peer-ipv6-address": GOBGP_ADDRESS6}


def bbl_config(ifname):
    def session(local, peer, family):
        return {
            "local-address": local,
            "peer-address": peer,
            "local-as": BBL_AS,
            "peer-as": BBL_AS,
            "id": BBL_ADDRESS,
            "family": [family]
        }
    return {
        "interfaces": {
            "network": {
                "interface": ifname,
                "address": BBL_ADDRESS + "/24",
                "gateway": GOBGP_ADDRESS,
                "address-ipv6": BBL_ADDRESS6 + "/64",
                "gateway-ipv6": GOBGP_ADDRESS6
            }
        },
        "bgp": [session(BBL_ADDRESS, GOBGP_ADDRESS, "ipv4-unicast"),
                session(BBL_ADDRESS6, GOBGP_ADDRESS6, "ipv6-unicast")]
    }


@pytest.fixture
def bbl(topology, processes, tmp_path):
    instance = BngBlaster(topology.a, tmp_path).start(bbl_config(topology.if_a))
    processes.append(instance)
    yield instance
    instance.terminate()


@pytest.mark.parametrize("arguments, peers", [
    ({}, [GOBGP_ADDRESS, GOBGP_ADDRESS6]),
    (V4, [GOBGP_ADDRESS]),
    (V6, [GOBGP_ADDRESS6]),
    ({"local-ipv6-address": BBL_ADDRESS6}, [GOBGP_ADDRESS6]),
    ({"peer-ipv6-address": GOBGP_ADDRESS6}, [GOBGP_ADDRESS6]),
    ({"peer-ipv6-address": "fc00::99"}, []),
])
def test_sessions_filter(bbl, arguments, peers):
    sessions = bbl.ctrl("bgp-sessions", **arguments)["bgp-sessions"]
    assert [s["peer-address"] for s in sessions] == peers


@pytest.mark.parametrize("arguments, started", [
    (V4, [GOBGP_ADDRESS]),
    (V6, [GOBGP_ADDRESS6]),
])
def test_raw_update_filter(bbl, tmp_path, arguments, started):
    raw_update_file = str(tmp_path / "update.bgp")
    bgpupdate(["-f", raw_update_file, "-a", str(BBL_AS), "-n", BBL_ADDRESS,
               "-p", "10.200.0.0/24", "-P", "1"])
    result = bbl.ctrl("bgp-raw-update", file=raw_update_file, **arguments)["bgp-raw-update"]
    assert result["started"] == 1
    assert result["filtered"] == 1
    sessions = bbl.ctrl("bgp-sessions")["bgp-sessions"]
    assert [s["peer-address"] for s in sessions if s.get("raw-update-file")] == started


@pytest.mark.parametrize("arguments", [V4, V6])
def test_disconnect_filter(bbl, arguments):
    result = bbl.ctrl("bgp-disconnect", **arguments)["bgp-disconnect"]
    assert result["disconnected"] + result["skipped"] == 1
    assert result["filtered"] == 1
