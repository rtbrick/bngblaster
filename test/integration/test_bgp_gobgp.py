"""
BNG Blaster BGP against GoBGP (unicast, collision, MD5)

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import time

import pytest

from bgp_common import BBL_ADDRESS, BBL_ADDRESS6, BBL_AS, GOBGP_ADDRESS, GOBGP_ADDRESS6, GOBGP_AS, BgpSetup
from helpers import AFI_IP, AFI_IP6, SAFI_UNICAST, bgpupdate, wait_until

BBL_PREFIXES = 1000
GOBGP_PREFIXES = 32

pytestmark = pytest.mark.usefixtures("gobgp_bin")


@pytest.fixture
def bgp(topology, processes, tmp_path):
    return BgpSetup(topology, processes, tmp_path)


def raw_update_file(tmp_path):
    """IPv4 and IPv6 unicast prefixes sent by the BNG Blaster."""
    path = str(tmp_path / "unicast.bgp")
    bgpupdate(["-f", path, "-a", str(BBL_AS), "-n", BBL_ADDRESS,
               "-p", "10.200.0.0/24", "-P", str(BBL_PREFIXES)])
    bgpupdate(["-f", path, "--append", "-a", str(BBL_AS), "-n", BBL_ADDRESS6,
               "-p", "fc00:200::/64", "-P", str(BBL_PREFIXES), "--end-of-rib"])
    return path


def test_unicast(bgp, tmp_path):
    bgp.start(bbl={"bgp": {"raw-update-file": raw_update_file(tmp_path)}})
    bgp.wait_established()
    session = bgp.bbl_session()
    assert session["peer-as"] == GOBGP_AS

    # BNG Blaster to GoBGP
    wait_until(lambda: bgp.gobgp.received(BBL_ADDRESS, AFI_IP, SAFI_UNICAST) == BBL_PREFIXES,
               30, message="GoBGP IPv4 prefixes received")
    wait_until(lambda: bgp.gobgp.received(BBL_ADDRESS, AFI_IP6, SAFI_UNICAST) == BBL_PREFIXES,
               30, message="GoBGP IPv6 prefixes received")

    # GoBGP to BNG Blaster (4-octet AS path)
    for i in range(GOBGP_PREFIXES):
        bgp.gobgp.cli(["global", "rib", "-a", "ipv4", "add", "10.100.%d.0/24" % i,
                       "aspath", "4200000002", "nexthop", GOBGP_ADDRESS], json_output=False)
        bgp.gobgp.cli(["global", "rib", "-a", "ipv6", "add", "fc00:100:%x::/48" % i,
                       "aspath", "4200000002", "nexthop", GOBGP_ADDRESS6], json_output=False)
    wait_until(lambda: len(bgp.bbl_routes("ipv4-unicast")) == GOBGP_PREFIXES, 15,
               message="BNG Blaster IPv4 routes learned")
    wait_until(lambda: len(bgp.bbl_routes("ipv6-unicast")) == GOBGP_PREFIXES, 15,
               message="BNG Blaster IPv6 routes learned")
    route = next(r for r in bgp.bbl_routes("ipv4-unicast") if r["prefix"] == "10.100.0.0/24")
    assert route["as-path"] == "%d 4200000002" % GOBGP_AS
    assert route["nexthop"] == GOBGP_ADDRESS

    # Withdraw
    bgp.gobgp.cli(["global", "rib", "-a", "ipv4", "del", "10.100.0.0/24"], json_output=False)
    wait_until(lambda: len(bgp.bbl_routes("ipv4-unicast")) == GOBGP_PREFIXES - 1, 10,
               message="BNG Blaster IPv4 route withdrawn")
    bgp.teardown()


@pytest.mark.parametrize("bbl_id", ["10.0.0.1", "10.0.0.3"], ids=["gobgp-wins", "bbl-wins"])
def test_connection_collision(bgp, bbl_id):
    """Both sides connect actively. RFC 4271 section 6.8 keeps the
    connection opened by the speaker with the higher BGP identifier and
    the remaining session must stay established."""
    bgp.start(gobgp={"passive": False}, bbl={"bgp": {"id": bbl_id}})
    bgp.wait_established()
    uptime = bgp.gobgp.neighbor(BBL_ADDRESS)["timers"]["state"]["uptime"]
    for _ in range(10):
        time.sleep(1)
        assert bgp.established()
    assert bgp.gobgp.neighbor(BBL_ADDRESS)["timers"]["state"]["uptime"] == uptime
    bgp.teardown()


@pytest.mark.usefixtures("md5_kernel")
def test_md5(bgp):
    bgp.start(gobgp={"md5": "BNGBlasterMD5"},
              bbl={"bgp": {"tcp-ao-algorithm": "md5", "tcp-ao-key": "BNGBlasterMD5"}})
    bgp.wait_established()
    assert bgp.bbl_session()["tcp-auth"] == "md5"
    bgp.teardown()


@pytest.mark.usefixtures("md5_kernel")
@pytest.mark.parametrize("gobgp_md5,bbl_md5", [
    ("BNGBlasterMD5", "WrongKey"),
    ("BNGBlasterMD5", None),
    (None, "BNGBlasterMD5"),
], ids=["wrong-key", "gobgp-only", "bbl-only"])
def test_md5_mismatch(bgp, gobgp_md5, bbl_md5):
    bbl = {"tcp-ao-algorithm": "md5", "tcp-ao-key": bbl_md5} if bbl_md5 else {}
    bgp.start(gobgp={"md5": gobgp_md5}, bbl={"bgp": bbl})
    bgp.assert_not_established()
    bgp.teardown()
