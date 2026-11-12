"""
BNG Blaster OSPFv3 against FRR (adjacency, DR election, topology, prefixes)

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import wait_until
from igp_common import BBL_ROUTER_ID, Ospf6Setup

NODES = 20

pytestmark = pytest.mark.usefixtures("frr_bin")

# Interface types with the expected FRR neighbor state of the BNG Blaster.
INTERFACES = pytest.mark.parametrize("p2p,bbl_priority,frr_priority,frr_state", [
    (True, None, None, "Full/PointToPoint"),
    pytest.param(False, 64, 1, "Full/DR", marks=pytest.mark.full),
    pytest.param(False, 1, 64, "Full/BDR", marks=pytest.mark.full),
    pytest.param(False, 0, 64, "Full/DROther", marks=pytest.mark.full),
], ids=["p2p", "bbl-dr", "bbl-bdr", "bbl-drother"])


@pytest.fixture
def ospf(topology, processes, tmp_path):
    return Ospf6Setup(topology, processes, tmp_path)


def start(ospf, p2p, bbl_priority, frr_priority, mrt=None, address6=None):
    bbl = {"p2p": p2p, "mrt": mrt, "address6": address6}
    if bbl_priority is not None:
        bbl["ospf"] = {"router-priority": bbl_priority}
    ospf.start(frr={"p2p": p2p, "priority": frr_priority}, bbl=bbl)
    ospf.wait_established()


@INTERFACES
def test_database_sync_bbl_to_frr(ospf, tmp_path, p2p, bbl_priority, frr_priority, frr_state):
    """Topology loaded from MRT file is flooded to FRR and FRR installs
    routes to all emulated nodes via the BNG Blaster. On broadcast
    interfaces, the BNG Blaster advertises a transit link to the DR and
    as DR the network LSA with the link prefix (RFC 5340 A.4.3 and A.4.4)."""
    topo = ospf.lspgen(tmp_path / "ospf3", NODES)
    start(ospf, p2p, bbl_priority, frr_priority, mrt=topo.mrt)
    assert ospf.frr_neighbor_state() == frr_state
    wait_until(lambda: topo.nodes <= ospf.frr_router_lsas(), 30,
               message="router LSAs of all nodes in FRR database")
    wait_until(lambda: topo.prefixes6 <= ospf.frr_routes("ipv6"), 15,
               message="FRR routes to all nodes")
    assert len(topo.prefixes6) == NODES
    if frr_state == "Full/DR":
        assert ospf.frr_network_lsas() == {BBL_ROUTER_ID}
        prefixes = [p["prefix"] for lsa in ospf.frr_lsas("intra-prefix")
                    if lsa["reference"] == "Network" for p in lsa["prefix"]]
        assert prefixes == ["fd00::/64"]
    ospf.teardown()


@pytest.mark.full
@pytest.mark.parametrize("address6,prefix", [
    ("fd00::1/48", "fd00::/48"),
    ("fd00::5/126", "fd00::4/126"),
], ids=["48", "126"])
def test_prefix_encoding(ospf, address6, prefix):
    """Prefixes are encoded in 32-bit words without host bits (RFC 5340 A.4.1),
    FRR installs the interface prefix of the BNG Blaster."""
    start(ospf, True, None, None, address6=address6)
    wait_until(lambda: prefix in ospf.frr_routes("ipv6"), 15,
               message="FRR route to %s" % prefix)
    lsas = [lsa for lsa in ospf.frr_lsas("intra-prefix") if lsa["advertisingRouter"] == BBL_ROUTER_ID]
    assert [p["prefix"] for lsa in lsas for p in lsa["prefix"]] == [prefix]
    assert [(lsa["referenceId"], lsa["length"] % 4) for lsa in lsas] == [("0.0.0.0", 0)]
    ospf.teardown()


@pytest.mark.full
def test_restart_flush_network_lsa(ospf):
    """The BNG Blaster is restarted without purge and is no longer DR.
    The network LSA of the previous run is flushed (RFC 2328 section 13.4)
    instead of staying in the FRR database until MaxAge."""
    start(ospf, False, 64, 1)
    wait_until(lambda: ospf.frr_network_lsas() == {BBL_ROUTER_ID}, 10,
               message="network LSA of the BNG Blaster in FRR database")
    ospf.bbl.kill()
    wait_until(lambda: ospf.frr_neighbor_state() is None, 15, message="FRR neighbor down")
    ospf.start_bbl({"p2p": False, "ospf": {"router-priority": 0}})
    ospf.wait_established()
    wait_until(lambda: BBL_ROUTER_ID not in ospf.frr_network_lsas(), 15,
               message="network LSA of the BNG Blaster flushed")
    ospf.teardown()
