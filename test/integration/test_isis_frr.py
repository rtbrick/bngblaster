"""
BNG Blaster ISIS against FRR (adjacency, database sync, authentication)

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import time

import pytest

from helpers import wait_until
from igp_common import (BBL_ADDRESS, BBL_ROUTER_ID, BBL_SYSTEM_ID, FRR_SYSTEM_ID,
                        IsisSetup, levels)

NODES = 50
FRR_PREFIXES = 8

pytestmark = pytest.mark.usefixtures("frr_bin")

LEVEL_IDS = {1: "L1", 2: "L2", 3: "L1L2"}


@pytest.fixture
def isis(topology, processes, tmp_path):
    return IsisSetup(topology, processes, tmp_path)


def lsp_id(system_id):
    return "%s.00-00" % system_id


@pytest.mark.parametrize("level", [1, 2, 3], ids=LEVEL_IDS.get)
@pytest.mark.parametrize("p2p", [True, False], ids=["p2p", "broadcast"])
def test_adjacency(isis, p2p, level):
    isis.start(frr={"level": level, "p2p": p2p}, bbl={"level": level, "p2p": p2p})
    isis.wait_established(level)
    for l in levels(level):
        # Self originated LSP exchanged in both directions.
        wait_until(lambda: lsp_id(BBL_SYSTEM_ID) in isis.frr_database(l), 10,
                   message="BNG Blaster LSP in FRR L%d database" % l)
        wait_until(lambda: lsp_id(FRR_SYSTEM_ID) in isis.bbl_database(l), 10,
                   message="FRR LSP in BNG Blaster L%d database" % l)
    isis.teardown()
    wait_until(lambda: not any(state == "Up" for _, state in isis.frr_neighbors()), 15,
               message="FRR adjacency down after BNG Blaster teardown")


@pytest.mark.parametrize("level", [1, 2], ids=LEVEL_IDS.get)
@pytest.mark.parametrize("p2p", [True, False], ids=["p2p", "broadcast"])
def test_database_sync_bbl_to_frr(isis, tmp_path, p2p, level):
    """Topology loaded from MRT file is flooded to FRR and FRR installs
    routes to all emulated nodes via the BNG Blaster."""
    topo = isis.lspgen(tmp_path / "isis", NODES, level)
    isis.start(frr={"level": level, "p2p": p2p}, bbl={"level": level, "p2p": p2p, "mrt": topo.mrt})
    isis.wait_established(level)
    wait_until(lambda: set(isis.bbl_database(level)) <= set(isis.frr_database(level)), 30,
               message="BNG Blaster database synchronized to FRR")
    wait_until(lambda: topo.prefixes <= isis.frr_routes("ip"), 15,
               message="FRR IPv4 routes to all nodes")
    wait_until(lambda: topo.prefixes6 <= isis.frr_routes("ipv6"), 15,
               message="FRR IPv6 routes to all nodes")
    assert len(topo.prefixes) == NODES
    assert isis.frr_nexthops(sorted(topo.prefixes)[-1]) == [BBL_ADDRESS]
    isis.teardown()


@pytest.mark.parametrize("level", [1, 2], ids=LEVEL_IDS.get)
def test_database_sync_frr_to_bbl(isis, level):
    """FRR LSP updates are flooded to the BNG Blaster."""
    isis.frr_redistribute_connected(FRR_PREFIXES)
    isis.start(frr={"level": level, "redistribute": True}, bbl={"level": level})
    isis.wait_established(level)
    frr_lsp = lsp_id(FRR_SYSTEM_ID)

    def synchronized():
        frr_seq = isis.frr_database(level).get(frr_lsp)
        return frr_seq and isis.bbl_database(level).get(frr_lsp) == frr_seq

    wait_until(synchronized, 15, message="FRR LSP synchronized")
    seq = isis.bbl_database(level)[frr_lsp]

    # New prefix triggers a new LSP sequence number.
    isis.frr_add_prefix(FRR_PREFIXES)
    wait_until(lambda: synchronized() and isis.bbl_database(level)[frr_lsp] > seq, 15,
               message="FRR LSP update synchronized")
    isis.teardown()


@pytest.mark.parametrize("auth_type", ["md5", "simple"])
@pytest.mark.parametrize("level", [1, 2], ids=LEVEL_IDS.get)
def test_authentication(isis, tmp_path, level, auth_type):
    """Authenticated hellos, LSPs and SNPs. The emulated topology
    verifies that the BNG Blaster floods authenticated LSPs."""
    key = "BNGBlaster%s" % auth_type
    topo = isis.lspgen(tmp_path / "isis", 10, level, auth=(auth_type, key))
    isis.start(frr={"level": level, "auth": (auth_type, key)},
               bbl={"level": level, "mrt": topo.mrt, "isis": {
                   "level%d-auth-key" % level: key,
                   "level%d-auth-type" % level: auth_type}})
    isis.wait_established(level)
    wait_until(lambda: set(isis.bbl_database(level)) <= set(isis.frr_database(level)), 30,
               message="BNG Blaster database synchronized to FRR")
    wait_until(lambda: lsp_id(FRR_SYSTEM_ID) in isis.bbl_database(level), 10,
               message="FRR LSP in BNG Blaster database")
    wait_until(lambda: topo.prefixes <= isis.frr_routes("ip"), 15,
               message="FRR IPv4 routes to all nodes")
    isis.teardown()


@pytest.mark.parametrize("frr_key,bbl_key", [
    ("BNGBlasterMD5", "WrongKey"),
    ("BNGBlasterMD5", None),
    (None, "BNGBlasterMD5"),
], ids=["wrong-key", "frr-only", "bbl-only"])
def test_authentication_mismatch(isis, frr_key, bbl_key):
    bbl = {"level1-auth-key": bbl_key, "level1-auth-type": "md5"} if bbl_key else {}
    isis.start(frr={"auth": ("md5", frr_key) if frr_key else None}, bbl={"isis": bbl})
    isis.assert_not_established(1)
    isis.teardown()


@pytest.mark.parametrize("level", [1, 2], ids=LEVEL_IDS.get)
def test_overload(isis, tmp_path, level):
    """FRR does not use the overloaded BNG Blaster as transit, so the
    emulated topology is synchronized but no routes are installed."""
    topo = isis.lspgen(tmp_path / "isis", 10, level)
    isis.start(frr={"level": level}, bbl={"level": level, "mrt": topo.mrt,
                                          "isis": {"overload": True}})
    isis.wait_established(level)
    wait_until(lambda: set(isis.bbl_database(level)) <= set(isis.frr_database(level)), 30,
               message="BNG Blaster database synchronized to FRR")
    wait_until(lambda: isis.frr_overload(level, lsp_id(BBL_SYSTEM_ID)), 10,
               message="overload bit of BNG Blaster LSP in FRR database")
    # Give FRR time for SPF before checking the routes.
    time.sleep(3)
    assert not topo.prefixes & isis.frr_routes("ip")
    isis.teardown()


def test_sr_algorithms(isis, tmp_path):
    """lspgen advertises one node SID per SR algorithm for IPv4 and IPv6
    and the SR algorithms in the router capability, decoded by FRR."""
    algos = [0, 1, 128]
    topo = isis.lspgen(tmp_path / "isis", 10, sr_algo=algos)
    isis.start(bbl={"mrt": topo.mrt})
    isis.wait_established(1)
    wait_until(lambda: set(isis.bbl_database(1)) <= set(isis.frr_database(1)), 30,
               message="BNG Blaster database synchronized to FRR")

    def frr_sids():
        sids, _ = isis.frr_prefix_sids()
        return {p: sids.get(p) for p in topo.prefix_sids}

    wait_until(lambda: frr_sids() == topo.prefix_sids, 10, message="Prefix-SIDs in FRR")
    _, lsp_algos = isis.frr_prefix_sids()
    assert all(len(s) == len(algos) for s in topo.prefix_sids.values())
    assert len(topo.prefix_sids) == 2 * len(topo.nodes)
    assert all(lsp_algos.get("%s-00" % node) == algos for node in topo.nodes)
    isis.teardown()


def test_flex_algo_definition(isis, tmp_path):
    """lspgen advertises Flex-Algo definitions (RFC 9350) from two nodes,
    with node SIDs and the SR-Algorithm list for all algorithms."""
    topo = isis.lspgen(tmp_path / "isis", 10, flex_algo="128:igp,129:min-delay:200")
    isis.start(bbl={"mrt": topo.mrt})
    isis.wait_established(1)
    wait_until(lambda: set(isis.bbl_database(1)) <= set(isis.frr_database(1)), 30,
               message="BNG Blaster database synchronized to FRR")
    expected = {128: {"Metric-Type": "0", "Calc-Type": "0", "Priority": "128", "M-Flag": "0"},
                129: {"Metric-Type": "1", "Calc-Type": "0", "Priority": "200", "M-Flag": "0"}}

    def frr_fads():
        return {lsp: {algo: {k: fad[k] for k in expected[algo]} for algo, fad in fads.items()}
                for lsp, fads in isis.frr_flex_algo_definitions().items()}

    wait_until(lambda: len(frr_fads()) == 2, 10, message="Flex-Algo definitions in FRR")
    assert all(fads == expected for fads in frr_fads().values())
    _, lsp_algos = isis.frr_prefix_sids()
    assert all(lsp_algos.get("%s-00" % node) == [0, 128, 129] for node in topo.nodes)
    isis.teardown()


def test_flex_algo_spf(isis, tmp_path):
    """FRR elects the Flex-Algo definition advertised by lspgen and computes
    the Flex-Algo SPF via the BNG Blaster. The application-specific link
    attributes (ASLA) generated by lspgen are decoded by FRR. All links need
    subTLVs, therefore the BNG Blaster advertises adjacency SIDs."""
    topo = isis.lspgen(tmp_path / "isis", 10, flex_algo="128:igp",
                       link_delay="10:1000", te_metric="100:200")
    isis.start(frr={"flex_algo": [128]},
               bbl={"mrt": topo.mrt, "isis": {"sr-base": 10000, "sr-range": 100,
                                              "sr-algo": [0, 128], "adjacency-sid-base": 1000}})
    isis.wait_established(1)
    wait_until(lambda: set(isis.bbl_database(1)) <= set(isis.frr_database(1)), 30,
               message="BNG Blaster database synchronized to FRR")
    wait_until(lambda: "%s.00" % isis.frr_flex_algo_source(128) in topo.nodes, 10,
               message="Flex-Algo definition of lspgen elected")
    wait_until(lambda: topo.prefixes <= isis.frr_algo_routes(128), 15,
               message="Flex-Algo 128 routes to all nodes")
    asla = {(lsp[:-3], nbr): v for (lsp, nbr), v in isis.frr_asla().items()}
    assert {k: asla.get(k) for k in topo.asla} == topo.asla
    assert len(topo.asla) and all(100 <= te <= 200 and 10 <= dmin == dmax <= 1000
                                  for te, dmin, dmax in topo.asla.values())
    isis.teardown()


def test_node_msd(isis, tmp_path):
    """lspgen advertises the node MSD (RFC 8491) and the E-flag (ELC) of the
    node prefixes (RFC 9088), FRR decodes the node MSD of all nodes."""
    topo = isis.lspgen(tmp_path / "isis", 10, node_msd=10, elc=True)
    isis.start(bbl={"mrt": topo.mrt})
    isis.wait_established(1)
    wait_until(lambda: set(isis.bbl_database(1)) <= set(isis.frr_database(1)), 30,
               message="BNG Blaster database synchronized to FRR")
    wait_until(lambda: {"%s-00" % n for n in topo.nodes} <= set(isis.frr_node_msd(1)), 10,
               message="node MSD of all nodes in FRR")
    msd = isis.frr_node_msd(1)
    assert all(msd["%s-00" % n] == 10 for n in topo.nodes)
    wait_until(lambda: topo.prefixes <= isis.frr_routes("ip"), 15,
               message="FRR routes to all nodes")
    isis.teardown()


def test_bbl_flex_algo(isis, tmp_path):
    """The BNG Blaster advertises node SIDs per SR algorithm, the node MSD,
    application-specific link attributes and a Flex-Algo definition, which
    wins the election with higher priority. The definition excludes the
    admin group of the link to the emulated topology, which is therefore
    not reachable with Flex-Algo 128 but with algorithm 0."""
    topo = isis.lspgen(tmp_path / "isis", 10, flex_algo="128:igp")
    isis.start(frr={"flex_algo": [128]}, bbl={
        "mrt": topo.mrt,
        "isis": {"sr-base": 10000, "sr-range": 100, "sr-algo": [0, 128],
                 "sr-node-sids": [{"algo": 0, "index": 90}, {"algo": 128, "index": 91}],
                 "adjacency-sid-base": 1000, "node-msd": 8,
                 "flex-algo": [{"algo": 128, "priority": 200, "exclude-any": 1}]},
        "connection": {"te-metric": 100, "delay": 50, "admin-group": 1},
        "network": {"isis-te-metric": 100, "isis-delay": 50}})
    isis.wait_established(1)
    wait_until(lambda: set(isis.bbl_database(1)) <= set(isis.frr_database(1)), 30,
               message="BNG Blaster database synchronized to FRR")
    wait_until(lambda: isis.frr_flex_algo_source(128) == BBL_SYSTEM_ID, 10,
               message="Flex-Algo definition of the BNG Blaster elected")
    wait_until(lambda: "%s/32" % BBL_ROUTER_ID in isis.frr_algo_routes(128), 15,
               message="Flex-Algo 128 route to the BNG Blaster")
    wait_until(lambda: topo.prefixes <= isis.frr_routes("ip"), 15,
               message="FRR algorithm 0 routes to all nodes")
    assert not topo.prefixes & isis.frr_algo_routes(128)
    sids, algos = isis.frr_prefix_sids()
    assert sids["%s/32" % BBL_ROUTER_ID] == {(90, 0), (91, 128)}
    assert algos["%s.00-00" % BBL_SYSTEM_ID] == [0, 128]
    assert isis.frr_node_msd(1)["%s.00-00" % BBL_SYSTEM_ID] == 8
    asla = isis.frr_asla()
    assert asla[("%s.00-00" % BBL_SYSTEM_ID, "%s.00" % FRR_SYSTEM_ID)] == (100, 50, 50)
    isis.teardown()
