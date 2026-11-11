"""
BNG Blaster OSPFv2 against FRR (adjacency, database sync, authentication)

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import ipaddress
import socket
import struct
import time

import pytest

from helpers import Frr, wait_until
from igp_common import BBL_ADDRESS, BBL_ROUTER_ID, FRR_PREFIX, FRR_ROUTER_ID, OspfSetup
from isis_peer import fletcher

NODES = 50
FRR_PREFIXES = 8
OSPF_LSA_TYPE_ROUTER = 1
OSPF_LSA_TYPE_EXTERNAL = 5
OSPF_LSA_TYPE_OPAQUE_AREA = 10
OSPF_MAX_AGE = 3600
OSPF_MAX_LINK_METRIC = 0xffff

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
    wait_until(lambda: ospf.bbl_interface()["state"] == bbl_state, 5,
               message="BNG Blaster interface state %s" % bbl_state)
    wait_until(lambda: ospf.frr_neighbor_state() == "Full/%s" % frr_role, 5,
               message="FRR neighbor state Full/%s" % frr_role)
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
    wait_until(lambda: ospf.bbl_interface()["state"] == "BACKUP", 5,
               message="BNG Blaster interface state BACKUP")
    wait_until(lambda: ospf.frr_neighbor_state() == "Full/Backup", 5,
               message="FRR neighbor state Full/Backup")
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


def frr_router_information(ospf):
    """Return the router information LSA of the BNG Blaster in FRR."""
    database = ospf.frr.vtysh("show ip ospf database opaque-area adv-router %s" % BBL_ROUTER_ID)
    for lsa in database.get("areaLocalOpaqueLsa", {}).get("areas", {}).get("0.0.0.0", []):
        if lsa.get("opaqueType") == "Router Information LSA":
            return lsa
    return None


def bbl_router_information(ospf):
    for lsa in ospf.bbl_database():
        if lsa["type"] == OSPF_LSA_TYPE_OPAQUE_AREA and lsa["router"] == BBL_ROUTER_ID:
            return lsa
    return None


def test_router_information_restart(ospf):
    """FRR still holds the router information LSA of a previous run
    (BNG Blaster killed without purge) with another hostname, the same
    sequence number and a larger checksum, so FRR's copy is more recent
    (RFC 2328 section 13.1). The BNG Blaster must re-originate its own
    LSA above the received sequence number (RFC 2328 section 13.4)."""
    ospf.start(bbl={"ospf": {"hostname": "new"}})
    ospf.wait_established()
    wait_until(lambda: frr_router_information(ospf), 10, message="router information LSA in FRR database")
    old = frr_router_information(ospf)
    ospf.bbl.kill()

    ospf.start_bbl({"ospf": {"hostname": "bngblaster-new"}})
    ospf.wait_established()
    own = bbl_router_information(ospf)
    if own["seq"] == "0x%s" % old["lsaSeqNumber"]:
        assert int(old["checksum"], 16) > int(own["checksum"], 16)

    def replaced():
        lsa = frr_router_information(ospf)
        own = bbl_router_information(ospf)
        return (lsa and own and lsa["checksum"] != old["checksum"] and
                int(lsa["checksum"], 16) == int(own["checksum"], 16))
    wait_until(replaced, 10, message="router information LSA replaced in FRR database")
    ospf.teardown()


def test_overload(ospf, tmp_path):
    """The overloaded BNG Blaster advertises its transit links with
    MaxLinkMetric (RFC 6987), which FRR adds to the route cost."""
    topo = ospf.lspgen(tmp_path / "ospf", 10)
    ospf.start(bbl={"mrt": topo.mrt, "ospf": {"overload": True}})
    ospf.wait_established()
    wait_until(lambda: topo.prefixes <= ospf.frr_routes("ip"), 30,
               message="FRR routes to all nodes")
    assert all(ospf.frr_metric(prefix) >= OSPF_MAX_LINK_METRIC for prefix in topo.prefixes)
    ospf.teardown()


@pytest.mark.parametrize("frr", [
    {"area": "0.0.0.1"},
    {"router_id": BBL_ROUTER_ID},
], ids=["area", "router-id"])
def test_header_mismatch(ospf, frr):
    """PDUs of another area or with the own router-id are discarded
    (RFC 2328 section 8.2), no neighbor is created."""
    ospf.start(frr=frr)
    ospf.assert_not_established(duration=6)
    assert ospf.bbl_neighbors() == []
    ospf.teardown()


def test_bbl_master(ospf, tmp_path):
    """The BNG Blaster with the higher router-id is master of the database
    exchange. It stays in state Exchange until the last DD packet is
    acknowledged (RFC 2328 section 10.8), the neighbor does not fall
    back from Full to Loading when the acknowledgement arrives. The
    topology requires several DD packets of the BNG Blaster."""
    frr_router_id = "10.9.0.2"
    topo = ospf.lspgen(tmp_path / "ospf", 200)
    ospf.frr_redistribute_connected(FRR_PREFIXES)
    ospf.start(frr={"router_id": frr_router_id, "redistribute": True}, bbl={"mrt": topo.mrt})
    ospf.wait_established()
    wait_until(lambda: topo.prefixes <= ospf.frr_routes("ip"), 30,
               message="FRR routes to all nodes")
    wait_until(lambda: bbl_lsas(ospf, OSPF_LSA_TYPE_EXTERNAL, frr_router_id) >=
               frr_external_ids(FRR_PREFIXES), 15, message="FRR external LSAs")
    log = open(ospf.bbl.path("log")).read()
    assert "state Exchange -> Loading" in log or "state Exchange -> Full" in log
    assert "Full -> Loading" not in log
    ospf.teardown()


def test_router_id_change(ospf, tmp_path):
    """FRR changes its router-id. The neighbor with the previous router-id
    is removed after the dead interval and the router LSA of the BNG Blaster
    links to the new neighbor, so FRR still routes to all nodes."""
    topo = ospf.lspgen(tmp_path / "ospf", 10)
    ospf.start(bbl={"mrt": topo.mrt})
    ospf.wait_established()
    wait_until(lambda: topo.prefixes <= ospf.frr_routes("ip"), 30,
               message="FRR routes to all nodes")
    ospf.frr.vtysh_exec("configure terminal", "router ospf", "ospf router-id 10.10.0.3")
    ospf.frr.vtysh_exec("clear ip ospf process")
    wait_until(lambda: [(n["router-id"], n["state"]) for n in ospf.bbl_neighbors()] ==
               [("10.10.0.3", "Full")], 20, message="only the new neighbor in BNG Blaster")
    wait_until(lambda: topo.prefixes <= ospf.frr_routes("ip"), 30,
               message="FRR routes to all nodes after router-id change")
    ospf.teardown()


def test_restart_flush_network_lsa(ospf):
    """The BNG Blaster is restarted without purge and is no longer DR.
    The network LSA of the previous run is flushed (RFC 2328 section 13.4)
    instead of staying in the FRR database until MaxAge."""
    ospf.start(frr={"p2p": False, "priority": 1},
               bbl={"p2p": False, "ospf": {"router-priority": 64}})
    ospf.wait_established()
    wait_until(lambda: ospf.frr_network_lsas() == {BBL_ROUTER_ID}, 10,
               message="network LSA of the BNG Blaster in FRR database")
    ospf.bbl.kill()
    wait_until(lambda: ospf.frr_neighbor_state() is None, 15, message="FRR neighbor down")
    ospf.start_bbl({"p2p": False, "ospf": {"router-priority": 0}})
    ospf.wait_established()
    wait_until(lambda: BBL_ROUTER_ID not in ospf.frr_network_lsas(), 15,
               message="network LSA of the BNG Blaster flushed")
    ospf.teardown()


SR = {"sr-base": 20000, "sr-range": 8000, "sr-node-sid": 1}


def frr_opaque_lsas(ospf):
    """Return the valid (not MaxAge) opaque LSAs of the BNG Blaster in FRR."""
    database = ospf.frr.vtysh("show ip ospf database opaque-area adv-router %s" % BBL_ROUTER_ID)
    return [lsa for lsa in database.get("areaLocalOpaqueLsa", {}).get("areas", {}).get("0.0.0.0", [])
            if lsa.get("lsaAge", 0) < OSPF_MAX_AGE]


def test_teardown_purge_opaque(ospf):
    """Router information and extended prefix LSAs are purged on
    teardown like all other self originated LSAs."""
    ospf.start(bbl={"ospf": SR})
    ospf.wait_established()
    wait_until(lambda: len(frr_opaque_lsas(ospf)) == 2, 10,
               message="router information and extended prefix LSA in FRR database")
    # FRR discards newer instances received within MinLSArrival (1 second).
    wait_until(lambda: ospf.bbl_neighbors()[0]["retry-tree-entries"] == 0, 10,
               message="flooding acknowledged")
    time.sleep(1)
    ospf.teardown()
    wait_until(lambda: not frr_opaque_lsas(ospf), 10,
               message="opaque LSAs of the BNG Blaster purged")


def test_segment_routing_algorithm(ospf):
    """The router information LSA advertises the SR-Algorithm TLV with
    the SID/Label Range TLV (RFC 8665 section 3.1)."""
    ospf.start(frr={"segment_routing": True}, bbl={"ospf": SR})
    ospf.wait_established()
    # The FRR SR database assumes SPF without TLV, the LSA detail shows the TLV.
    wait_until(lambda: "Segment Routing Algorithm TLV:\n    Algorithm 0: SPF" in ospf.frr.vtysh(
               "show ip ospf database opaque-area adv-router %s" % BBL_ROUTER_ID, json_output=False),
               10, message="SR-Algorithm TLV of the BNG Blaster in FRR")
    ospf.teardown()


def test_database_load_rate(ospf):
    """The next LS request is sent once the previous is satisfied
    (RFC 2328 section 10.9), not only with the 1 second retransmission
    timer, which would take about 25 seconds for 3000 LSAs."""
    count = 3000
    ospf.start_frr({"statics": count})
    wait_until(lambda: ospf.frr_external_count() >= count, 30, message="FRR external LSAs")
    ospf.start_bbl()
    ospf.wait_established(timeout=10)
    assert len(bbl_lsas(ospf, OSPF_LSA_TYPE_EXTERNAL, FRR_ROUTER_ID)) >= count
    ospf.teardown()


def opaque_lsa(router, size):
    """Return an opaque area LSA (router information) of the given size."""
    body = struct.pack(">HH", 32000, size - 24) + b"x" * (size - 24)
    data = bytearray(struct.pack(">HBB4s4sIHH", 0, 0x42, OSPF_LSA_TYPE_OPAQUE_AREA,
                                 socket.inet_aton("4.0.0.0"), socket.inet_aton(router),
                                 0x80000001, 0, size) + body)
    data[16:18] = fletcher(data[2:], 14)
    return data.hex()


def frr_has_opaque(ospf, router):
    database = ospf.frr.vtysh("show ip ospf database opaque-area adv-router %s" % router)
    return bool(database.get("areaLocalOpaqueLsa", {}).get("areas", {}).get("0.0.0.0", []))


@pytest.mark.parametrize("auth", [None, "md5"])
def test_lsa_size_limit(ospf, auth):
    """The largest LSA accepted by ospf-lsa-update fits into an IPv4
    datagram with IPv4 and OSPFv2 header, LSA count and MD5 digest and
    is delivered to FRR. Larger LSAs were accepted, but never delivered
    (retransmitted forever) and sent without digest."""
    key = "BBLmd5"
    bbl = {"auth-type": "md5", "auth-key": key} if auth else {}
    ospf.start(frr={"auth": ("md5", key) if auth else None}, bbl={"ospf": bbl})
    ospf.wait_established()
    size = 65535 - 20 - 24 - 4 - (16 if auth else 0)
    # FRR accepts only LSAs with a length of a multiple of 4 (TLV padding).
    result = ospf.bbl.ctrl("ospf-lsa-update", instance=1, lsa=[opaque_lsa("10.10.0.98", (size + 4) & ~3)])
    assert result["code"] != 200
    result = ospf.bbl.ctrl("ospf-lsa-update", instance=1, lsa=[opaque_lsa("10.10.0.99", size & ~3)])
    assert result["code"] == 200
    wait_until(lambda: frr_has_opaque(ospf, "10.10.0.99"), 20, message="largest LSA in FRR")
    ospf.teardown()


def test_md5_restart(ospf):
    """The MD5 cryptographic sequence number does not restart at zero
    (RFC 2328 appendix D.3), otherwise FRR ignores the restarted BNG
    Blaster until the new sequence number exceeds the last one of the
    previous run (one hello per second) or the dead interval expires."""
    key = "BBLmd5"
    ospf.frr = Frr(ospf.topology.b, ospf.tmp_path, (ospf.daemon,)).start(
        ospf.frr_config(auth=("md5", key)).replace("dead-interval 4", "dead-interval 120"))
    ospf.processes.append(ospf.frr)
    bbl = {"ospf": {"auth-type": "md5", "auth-key": key, "dead-interval": 120}}
    ospf.start_bbl(bbl)
    ospf.wait_established()
    time.sleep(30)
    ospf.bbl.kill()
    # The sequence number follows the time in seconds, it may be ahead by
    # the packets sent faster than one per second (database exchange), so
    # the restarted instance is accepted after a few seconds.
    ospf.start_bbl(bbl)
    ospf.wait_established(timeout=20)
    ospf.teardown()
