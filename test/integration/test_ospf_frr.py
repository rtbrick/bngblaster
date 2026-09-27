"""
BNG Blaster OSPFv2 against FRR (adjacency, database sync, authentication)

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import ipaddress

import pytest

from helpers import wait_until
from igp_common import BBL_ADDRESS, BBL_ROUTER_ID, FRR_PREFIX, FRR_ROUTER_ID, OspfSetup

NODES = 50
FRR_PREFIXES = 8
OSPF_LSA_TYPE_ROUTER = 1
OSPF_LSA_TYPE_EXTERNAL = 5
OSPF_MAX_AGE = 3600

pytestmark = pytest.mark.usefixtures("frr_bin")


@pytest.fixture
def ospf(topology, processes, tmp_path):
    return OspfSetup(topology, processes, tmp_path)


def bbl_lsas(ospf, lsa_type, router):
    """Return IDs of valid (not MaxAge) LSAs in the BNG Blaster database."""
    return {lsa["id"] for lsa in ospf.bbl_database()
            if lsa["type"] == lsa_type and lsa["router"] == router and lsa["age"] < OSPF_MAX_AGE}


def frr_external_ids(count):
    return {str(ipaddress.ip_network(FRR_PREFIX % i).network_address) for i in range(count)}


@pytest.mark.parametrize("p2p", [True, False], ids=["p2p", "broadcast"])
def test_adjacency(ospf, p2p):
    ospf.start(frr={"p2p": p2p}, bbl={"p2p": p2p})
    ospf.wait_established()
    wait_until(lambda: BBL_ROUTER_ID in ospf.frr_router_lsas(), 10,
               message="BNG Blaster router LSA in FRR database")
    wait_until(lambda: bbl_lsas(ospf, OSPF_LSA_TYPE_ROUTER, FRR_ROUTER_ID), 10,
               message="FRR router LSA in BNG Blaster database")
    ospf.teardown()
    wait_until(lambda: not ospf.frr_full(), 15,
               message="FRR neighbor down after BNG Blaster teardown")


@pytest.mark.parametrize("bbl_priority,frr_priority,bbl_state,frr_role", [
    (64, 1, "DR", "DR"),
    (1, 64, "BACKUP", "Backup"),
    (0, 64, "DROTHER", "DROther"),
], ids=["bbl-dr", "bbl-bdr", "bbl-drother"])
def test_dr_election(ospf, bbl_priority, frr_priority, bbl_state, frr_role):
    """DR/BDR election on broadcast interfaces after the wait timer. The
    adjacency is established with the DR and BDR (RFC 2328 section 10.4)."""
    ospf.start(frr={"p2p": False, "priority": frr_priority},
               bbl={"p2p": False, "ospf": {"router-priority": bbl_priority}})
    ospf.wait_established()
    assert ospf.bbl_interface()["state"] == bbl_state
    assert ospf.frr_neighbor_state() == "Full/%s" % frr_role
    ospf.teardown()


def test_dr_election_existing_dr(ospf):
    """The BNG Blaster joins a segment with an elected DR. The DR is
    not preempted, even with higher priority, and the BNG Blaster
    becomes BDR (RFC 2328 section 9.4)."""
    ospf.start_frr(frr={"p2p": False, "priority": 1})
    wait_until(lambda: ospf.frr_interface_state() == "DR", 15,
               message="FRR elected as DR")
    ospf.start_bbl(bbl={"p2p": False, "ospf": {"router-priority": 64}})
    ospf.wait_established()
    assert ospf.bbl_interface()["state"] == "BACKUP"
    assert ospf.frr_neighbor_state() == "Full/Backup"
    ospf.teardown()


@pytest.mark.parametrize("p2p", [True, False], ids=["p2p", "broadcast"])
def test_database_sync_bbl_to_frr(ospf, tmp_path, p2p):
    """Topology loaded from MRT file is flooded to FRR and FRR installs
    routes to all emulated nodes via the BNG Blaster."""
    topo = ospf.lspgen(tmp_path / "ospf", NODES)
    ospf.start(frr={"p2p": p2p}, bbl={"p2p": p2p, "mrt": topo.mrt})
    ospf.wait_established()
    wait_until(lambda: topo.nodes <= ospf.frr_router_lsas(), 30,
               message="router LSAs of all nodes in FRR database")
    wait_until(lambda: topo.prefixes <= ospf.frr_routes("ip"), 15,
               message="FRR routes to all nodes")
    assert len(topo.nodes) == NODES
    assert ospf.frr_nexthops(sorted(topo.prefixes)[-1]) == [BBL_ADDRESS]
    ospf.teardown()


def test_database_sync_frr_to_bbl(ospf):
    """FRR external LSAs are flooded to the BNG Blaster, including
    new and flushed LSAs."""
    ospf.frr_redistribute_connected(FRR_PREFIXES)
    ospf.start(frr={"redistribute": True})
    ospf.wait_established()
    wait_until(lambda: bbl_lsas(ospf, OSPF_LSA_TYPE_EXTERNAL, FRR_ROUTER_ID) >=
               frr_external_ids(FRR_PREFIXES), 15, message="FRR external LSAs")

    ospf.frr_add_prefix(FRR_PREFIXES)
    wait_until(lambda: bbl_lsas(ospf, OSPF_LSA_TYPE_EXTERNAL, FRR_ROUTER_ID) >=
               frr_external_ids(FRR_PREFIXES + 1), 15, message="new FRR external LSA")

    ospf.frr_del_prefix(0)
    wait_until(lambda: frr_external_ids(1).isdisjoint(bbl_lsas(ospf, OSPF_LSA_TYPE_EXTERNAL, FRR_ROUTER_ID)), 15,
               message="flushed FRR external LSA")
    ospf.teardown()


@pytest.mark.parametrize("auth_type", ["md5", "simple"])
def test_authentication(ospf, tmp_path, auth_type):
    key = "BBL%s" % auth_type  # simple passwords are limited to 8 bytes
    topo = ospf.lspgen(tmp_path / "ospf", 10)
    ospf.start(frr={"auth": (auth_type, key)},
               bbl={"mrt": topo.mrt, "ospf": {"auth-type": auth_type, "auth-key": key}})
    ospf.wait_established()
    wait_until(lambda: topo.prefixes <= ospf.frr_routes("ip"), 30,
               message="FRR routes to all nodes")
    ospf.teardown()


@pytest.mark.parametrize("frr_key,bbl_key", [
    ("BNGBlasterMD5", "WrongKey"),
    ("BNGBlasterMD5", None),
    (None, "BNGBlasterMD5"),
], ids=["wrong-key", "frr-only", "bbl-only"])
def test_authentication_mismatch(ospf, frr_key, bbl_key):
    bbl = {"auth-type": "md5", "auth-key": bbl_key} if bbl_key else {}
    ospf.start(frr={"auth": ("md5", frr_key) if frr_key else None}, bbl={"ospf": bbl})
    ospf.assert_not_established()
    ospf.teardown()


def test_opaque_incapable_neighbor(ospf, tmp_path):
    """Opaque LSAs (SR) generated by lspgen must not be sent to FRR
    without opaque capability (RFC 5250), otherwise FRR rejects them
    and restarts the database exchange."""
    topo = ospf.lspgen(tmp_path / "ospf", 10)
    ospf.start(frr={"opaque": False}, bbl={"mrt": topo.mrt})
    ospf.wait_established()
    wait_until(lambda: topo.prefixes <= ospf.frr_routes("ip"), 15,
               message="FRR routes to all nodes")
    ospf.teardown()
