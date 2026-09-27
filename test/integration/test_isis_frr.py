"""
BNG Blaster ISIS against FRR (adjacency, database sync, authentication)

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import wait_until
from igp_common import (BBL_ADDRESS, BBL_SYSTEM_ID, FRR_SYSTEM_ID,
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
