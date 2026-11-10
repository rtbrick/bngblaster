"""
BNG Blaster BGP against GoBGP (unicast, labeled unicast, collision, hold time, MD5)

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import os
import signal
import time

import pytest

from bgp_common import BBL_ADDRESS, BBL_ADDRESS6, BBL_AS, GOBGP_ADDRESS, GOBGP_ADDRESS6, GOBGP_AS, BgpSetup
from helpers import AFI_IP, AFI_IP6, SAFI_LABELED_UNICAST, SAFI_UNICAST, bgpupdate, wait_until

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
    # The IPv6 End-of-RIB is an empty MP_UNREACH_NLRI (RFC 4724).
    wait_until(lambda: bgp.gobgp.end_of_rib(BBL_ADDRESS, AFI_IP6, SAFI_UNICAST), 10,
               message="GoBGP IPv6 End-of-RIB received")

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


def test_labeled_unicast(bgp, tmp_path):
    """Labeled unicast raw updates with End-of-RIB per family, and
    withdrawn routes packed into few updates with the RFC 8277 withdraw
    label instead of one update per prefix."""
    update, withdraw = str(tmp_path / "labeled.bgp"), str(tmp_path / "withdraw.bgp")
    for path, args in ((update, ["-l", "100", "--med", "10", "--end-of-rib"]), (withdraw, ["-w"])):
        bgpupdate(["-f", path, "-a", str(BBL_AS), "-n", BBL_ADDRESS, "-p", "10.200.0.0/24",
                   "-P", str(BBL_PREFIXES), "-m", "10000", "-M", "100"] + args)
        bgpupdate(["-f", path, "--append", "-a", str(BBL_AS), "-n", BBL_ADDRESS6, "-p", "fc00:200::/64",
                   "-P", str(BBL_PREFIXES), "-m", "20000"] + args)
    # 2 x 1000 withdrawn prefixes fit into 5 updates (one per prefix
    # would be about 80 KB).
    assert os.path.getsize(withdraw) < 6 * 4096

    bgp.start(bbl={"bgp": {"raw-update-file": update}},
              families=("ipv4-labeled-unicast", "ipv6-labeled-unicast"))
    bgp.wait_established()
    for afi in (AFI_IP, AFI_IP6):
        wait_until(lambda: bgp.gobgp.received(BBL_ADDRESS, afi, SAFI_LABELED_UNICAST) == BBL_PREFIXES,
                   30, message="GoBGP labeled prefixes received (AFI %d)" % afi)
        wait_until(lambda: bgp.gobgp.end_of_rib(BBL_ADDRESS, afi, SAFI_LABELED_UNICAST), 10,
                   message="GoBGP labeled End-of-RIB received (AFI %d)" % afi)
    route = bgp.gobgp.adj_in(BBL_ADDRESS, "ipv4-mpls")["10.200.1.0/24"][0]
    assert route["nlri"]["labels"] == [10001]
    route = bgp.gobgp.adj_in(BBL_ADDRESS, "ipv6-mpls")["fc00:200:0:1::/64"][0]
    assert route["nlri"]["labels"] == [20000]

    response = bgp.bbl.ctrl("bgp-raw-update", file=withdraw)
    assert response["bgp-raw-update"]["started"] == 1, response
    for afi in (AFI_IP, AFI_IP6):
        wait_until(lambda: bgp.gobgp.received(BBL_ADDRESS, afi, SAFI_LABELED_UNICAST) == 0,
                   30, message="GoBGP labeled prefixes withdrawn (AFI %d)" % afi)
    assert bgp.established()
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


def test_peer_close(bgp):
    """The peer closes the established connection without NOTIFICATION
    (GoBGP killed, the kernel sends FIN). The session must go down
    immediately instead of waiting for the next KEEPALIVE."""
    bgp.start()
    bgp.wait_established()
    bgp.gobgp.proc.kill()
    bgp.gobgp.proc.wait(5)
    wait_until(lambda: bgp.bbl_session()["state"] != "established", 5,
               message="BNG Blaster session down after peer close")
    assert bgp.bbl.terminate(30) == 0


def test_hold_time_negotiated(bgp):
    """The smaller hold time of GoBGP is used (RFC 4271 section 4.2),
    so a silent peer is detected after 6 instead of 30 seconds."""
    bgp.start(gobgp={"hold_time": 6})
    bgp.wait_established()
    os.kill(bgp.gobgp.proc.pid, signal.SIGSTOP)
    try:
        start = time.monotonic()
        wait_until(lambda: bgp.bbl_session()["state"] != "established", 12,
                   message="BNG Blaster hold timer expired")
        assert time.monotonic() - start < 10
    finally:
        os.kill(bgp.gobgp.proc.pid, signal.SIGCONT)


def test_hold_time_zero(bgp):
    """Hold time zero disables hold timer and keepalives (RFC 4271
    section 4.4), the session must stay up without keepalives."""
    bgp.start(bbl={"bgp": {"hold-time": 0}})
    bgp.wait_established()
    keepalive_tx = bgp.bbl_session()["stats"]["keepalive-tx"]
    time.sleep(8)
    assert bgp.established()
    assert bgp.bbl_session()["stats"]["keepalive-tx"] == keepalive_tx
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
    # Each mismatch waits for the hold timer, only wrong-key runs by default.
    ("BNGBlasterMD5", "WrongKey"),
    pytest.param("BNGBlasterMD5", None, marks=pytest.mark.slow),
    pytest.param(None, "BNGBlasterMD5", marks=pytest.mark.slow),
], ids=["wrong-key", "gobgp-only", "bbl-only"])
def test_md5_mismatch(bgp, gobgp_md5, bbl_md5):
    bbl = {"tcp-ao-algorithm": "md5", "tcp-ao-key": bbl_md5} if bbl_md5 else {}
    bgp.start(gobgp={"md5": gobgp_md5}, bbl={"bgp": bbl})
    bgp.assert_not_established()
    bgp.teardown()
