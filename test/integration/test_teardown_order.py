"""
BNG Blaster teardown order of BGP and IGP

BGP sessions are often established between loopback addresses, which
are reachable only via the IGP of the BNG Blaster. On teardown, the IGP
withdraw must wait until the BGP sessions are closed, otherwise the
peer can't send the packets to close the session (e.g. TCP FIN), which
leaves the session pending on the peer.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import re
from datetime import datetime

import pytest

from helpers import Frr, wait_until
from igp_common import BBL_ROUTER_ID, FRR_ADDRESS, FRR_ROUTER_ID, IsisSetup

AS = 65000

pytestmark = pytest.mark.usefixtures("frr_bin")


class IsisBgpSetup(IsisSetup):
    """IS-IS and iBGP from the BNG Blaster loopback (router-id) to FRR."""

    logging = ("info", "isis", "bgp")

    def start_frr(self, frr=None):
        config = self.frr_config(**(frr or {})) + "\n".join([
            "router bgp %d" % AS,
            " bgp router-id %s" % FRR_ROUTER_ID,
            " no bgp ebgp-requires-policy",
            " neighbor %s remote-as %d" % (BBL_ROUTER_ID, AS),
            " neighbor %s update-source %s" % (BBL_ROUTER_ID, FRR_ADDRESS),
            "exit",
        ]) + "\n"
        self.frr = Frr(self.topology.b, self.tmp_path, ("isisd", "bgpd")).start(config)
        self.processes.append(self.frr)
        return self

    def bbl_config(self, bgp=True, **kwargs):
        config = super().bbl_config(**kwargs)
        if bgp:
            config["bgp"] = [{
                "network-interface": self.topology.if_a,
                "local-ipv4-address": BBL_ROUTER_ID,
                "peer-ipv4-address": FRR_ADDRESS,
                "local-as": AS,
                "peer-as": AS,
                "id": BBL_ROUTER_ID,
            }]
        return config

    def frr_bgp_neighbor(self):
        return self.frr.vtysh("show bgp neighbors %s" % BBL_ROUTER_ID).get(BBL_ROUTER_ID, {})


def log_time(log, pattern):
    """Timestamp of the first log line matching pattern."""
    for line in log.splitlines():
        if re.search(pattern, line):
            return datetime.strptime(line.split()[2], "%H:%M:%S.%f")
    raise AssertionError("no log line matching %r" % pattern)


@pytest.fixture
def isis_bgp(topology, processes, tmp_path):
    return IsisBgpSetup(topology, processes, tmp_path)


def test_bgp_closed_before_isis_withdraw(isis_bgp):
    isis_bgp.start()
    isis_bgp.wait_established(1)
    wait_until(lambda: "%s/32" % BBL_ROUTER_ID in isis_bgp.frr_routes("ip"), 15,
               message="FRR IS-IS route to BNG Blaster loopback")
    wait_until(lambda: isis_bgp.frr_bgp_neighbor().get("bgpState") == "Established", 30,
               message="BGP session to BNG Blaster loopback established")

    isis_bgp.teardown()

    with open(isis_bgp.bbl.path("log")) as f:
        log = f.read()
    closed = log_time(log, r"BGP .* state changed from closing -> closed")
    withdraw = log_time(log, r"Withdraw IS-IS instance")
    assert (withdraw - closed).total_seconds() >= 1, (closed, withdraw)
    # FRR received our notification, as the session was closed while
    # the BNG Blaster loopback was still reachable.
    wait_until(lambda: "Cease" in str(isis_bgp.frr_bgp_neighbor().get("lastNotificationReason", "")),
               10, message="FRR received Cease notification")


def test_isis_teardown_delay(isis_bgp):
    isis_bgp.start(bbl={"bgp": False, "isis": {"teardown-delay": 3}})
    isis_bgp.wait_established(1)
    isis_bgp.teardown()

    with open(isis_bgp.bbl.path("log")) as f:
        log = f.read()
    teardown = log_time(log, r"Teardown IS-IS instance")
    withdraw = log_time(log, r"Withdraw IS-IS instance")
    assert 3 <= (withdraw - teardown).total_seconds() < 4, (teardown, withdraw)
