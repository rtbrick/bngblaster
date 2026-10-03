"""
BNG Blaster OSPFv2 and OSPFv3 against BIRD (adjacency, DR election,
database sync, authentication)

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import Bird, wait_until
from igp_common import BBL_ADDRESS, BBL_ROUTER_ID, FRR_ROUTER_ID, OspfSetup

BIRD_ROUTER_ID = FRR_ROUTER_ID
BIRD_PREFIXES = 8
NODES = 50
OSPF_LSA_TYPE_ROUTER = 1
OSPF_LSA_TYPE_EXTERNAL = 5
OSPF_MAX_AGE = 3600

# BIRD LSA types (OSPFv3 function codes with flooding scope bits).
BIRD_LSA_TYPE = {
    2: {OSPF_LSA_TYPE_ROUTER: 0x0001, OSPF_LSA_TYPE_EXTERNAL: 0x0005},
    3: {OSPF_LSA_TYPE_ROUTER: 0x2001, OSPF_LSA_TYPE_EXTERNAL: 0x4005},
}

pytestmark = pytest.mark.usefixtures("bird_bin")

VERSIONS = pytest.mark.parametrize("version", [2, 3], ids=["v2", "v3"])


class BirdOspfSetup(OspfSetup):
    """BIRD in namespace B instead of FRR, see OspfSetup."""

    def __init__(self, topology, processes, tmp_path):
        super().__init__(topology, processes, tmp_path)
        self.version = 2
        self.bird_args = {}
        self.prefixes = set()

    def start(self, bird=None, bbl=None):
        return self.start_bird(bird).start_bbl(bbl)

    def start_bird(self, bird=None):
        self.bird_args = dict(bird or {})
        self.version = self.bird_args.get("version", 2)
        self.prefixes = {self.bird_prefix(i) for i in range(self.bird_args.get("prefixes", 0))}
        self.frr = Bird(self.topology.b, self.tmp_path).start(self.bird_config())
        self.processes.append(self.frr)
        return self

    def start_bbl(self, bbl=None):
        bbl = dict(bbl or {})
        bbl.setdefault("version", self.version)
        return super().start_bbl(bbl)

    def bird_prefix(self, i):
        return "fd99:%x::/64" % i if self.version == 3 else "10.99.%d.0/24" % i

    def bird_config(self):
        """Return BIRD config. The auth tuple is (type, key) with type
        simple or md5 (key ID 1). The static prefixes (count set by
        prefixes) are exported as external LSAs."""
        args = self.bird_args
        afi = "ipv6" if self.version == 3 else "ipv4"
        lines = [
            "router id %s;" % BIRD_ROUTER_ID,
            "log stderr all;",
            "protocol device { scan time 1; }",
            "protocol static static1 {",
            "  %s;" % afi,
        ]
        lines += ["  route %s blackhole;" % p for p in sorted(self.prefixes)]
        lines += [
            "}",
            "protocol ospf v%d ospf1 {" % self.version,
            "  %s { import all; export where source = RTS_STATIC; };" % afi,
            "  area 0 {",
            "    interface \"%s\" {" % self.topology.if_b,
            "      type %s;" % ("ptp" if args.get("p2p", True) else "broadcast"),
            "      hello 1; dead 4; wait 4;",
        ]
        if args.get("priority") is not None:
            lines.append("      priority %d;" % args["priority"])
        auth = args.get("auth")
        if auth and auth[0] == "md5":
            lines += ["      authentication cryptographic;",
                      "      password \"%s\" { id 1; algorithm keyed md5; };" % auth[1]]
        elif auth:
            lines += ["      authentication simple;",
                      "      password \"%s\";" % auth[1]]
        lines += ["    };", "  };", "}"]
        return "\n".join(lines) + "\n"

    def bird_add_prefix(self, i):
        self.prefixes.add(self.bird_prefix(i))
        self.bird_reconfigure()

    def bird_del_prefix(self, i):
        self.prefixes.discard(self.bird_prefix(i))
        self.bird_reconfigure()

    def bird_reconfigure(self):
        (self.tmp_path / "bird.conf").write_text(self.bird_config())
        self.frr.birdc("configure")

    def bird_interface_state(self):
        """Return BIRD interface state (e.g. DR)."""
        for line in self.frr.birdc("show ospf interface ospf1"):
            if line.strip().startswith("State:"):
                return line.split(":", 1)[1].strip()
        return None

    def frr_neighbor_state(self):
        """Return BIRD neighbor state (e.g. Full/DR) of the BNG Blaster."""
        for line in self.frr.birdc("show ospf neighbors ospf1"):
            fields = line.split()
            if fields and fields[0] == BBL_ROUTER_ID:
                return fields[2]
        return None

    def bird_lsadb(self):
        """Return (type, id, router) of all LSAs in the BIRD database."""
        lsas = set()
        for line in self.frr.birdc("show ospf lsadb ospf1"):
            fields = line.split()
            if len(fields) == 6 and fields[0] != "Type":
                lsas.add((int(fields[0], 16), fields[1], fields[2]))
        return lsas

    def bird_lsa_ids(self, lsa_type, router):
        bird_type = BIRD_LSA_TYPE[self.version][lsa_type]
        return {lsa_id for t, lsa_id, r in self.bird_lsadb() if t == bird_type and r == router}

    def frr_router_lsas(self):
        bird_type = BIRD_LSA_TYPE[self.version][OSPF_LSA_TYPE_ROUTER]
        return {r for t, _, r in self.bird_lsadb() if t == bird_type}

    def frr_routes(self, afi="ip"):
        """Return prefixes of all OSPF routes in the BIRD table."""
        return {line.split()[0] for line in self.frr.birdc("show route protocol ospf1")
                if not line[0].isspace() and "/" in line.split()[0]}

    def frr_nexthops(self, prefix):
        return [line.split()[1] for line in self.frr.birdc("show route for %s protocol ospf1" % prefix)
                if line.strip().startswith("via")]


@pytest.fixture
def ospf(topology, processes, tmp_path):
    return BirdOspfSetup(topology, processes, tmp_path)


def bbl_lsas(ospf, lsa_type, router):
    """Return IDs of valid (not MaxAge) LSAs in the BNG Blaster database."""
    return {lsa["id"] for lsa in ospf.bbl_database()
            if lsa["type"] == lsa_type and lsa["router"] == router and lsa["age"] < OSPF_MAX_AGE}


@VERSIONS
@pytest.mark.parametrize("p2p", [True, False], ids=["p2p", "broadcast"])
def test_adjacency(ospf, version, p2p):
    ospf.start(bird={"version": version, "p2p": p2p}, bbl={"p2p": p2p})
    ospf.wait_established()
    wait_until(lambda: BBL_ROUTER_ID in ospf.frr_router_lsas(), 10,
               message="BNG Blaster router LSA in BIRD database")
    wait_until(lambda: bbl_lsas(ospf, OSPF_LSA_TYPE_ROUTER, BIRD_ROUTER_ID), 10,
               message="BIRD router LSA in BNG Blaster database")
    ospf.teardown()
    wait_until(lambda: not ospf.frr_full(), 15,
               message="BIRD neighbor down after BNG Blaster teardown")


@VERSIONS
@pytest.mark.parametrize("bbl_priority,bird_priority,bbl_state,bird_role", [
    (64, 1, "DR", "Full/DR"),
    (1, 64, "BACKUP", "Full/BDR"),
    (0, 64, "DROTHER", "Full/Other"),
], ids=["bbl-dr", "bbl-bdr", "bbl-drother"])
def test_dr_election(ospf, version, bbl_priority, bird_priority, bbl_state, bird_role):
    """DR/BDR election on broadcast interfaces after the wait timer. The
    adjacency is established with the DR and BDR (RFC 2328 section 10.4)."""
    ospf.start(bird={"version": version, "p2p": False, "priority": bird_priority},
               bbl={"p2p": False, "ospf": {"router-priority": bbl_priority}})
    ospf.wait_established()
    wait_until(lambda: ospf.bbl_interface()["state"] == bbl_state, 5,
               message="BNG Blaster interface state %s" % bbl_state)
    wait_until(lambda: ospf.frr_neighbor_state() == bird_role, 5,
               message="BIRD neighbor state %s" % bird_role)
    ospf.teardown()


@VERSIONS
def test_dr_election_existing_dr(ospf, version):
    """The BNG Blaster joins a segment with an elected DR. The DR is
    not preempted, even with higher priority, and the BNG Blaster
    becomes BDR (RFC 2328 section 9.4)."""
    ospf.start_bird(bird={"version": version, "p2p": False, "priority": 1})
    wait_until(lambda: ospf.bird_interface_state() == "DR", 15,
               message="BIRD elected as DR")
    ospf.start_bbl(bbl={"p2p": False, "ospf": {"router-priority": 64}})
    ospf.wait_established()
    wait_until(lambda: ospf.bbl_interface()["state"] == "BACKUP", 5,
               message="BNG Blaster interface state BACKUP")
    wait_until(lambda: ospf.frr_neighbor_state() == "Full/BDR", 5,
               message="BIRD neighbor state Full/BDR")
    ospf.teardown()


@pytest.mark.parametrize("p2p", [True, False], ids=["p2p", "broadcast"])
def test_database_sync_bbl_to_bird(ospf, tmp_path, p2p):
    """Topology loaded from MRT file is flooded to BIRD and BIRD installs
    routes to all emulated nodes via the BNG Blaster. BIRD is not opaque
    capable, so the SR opaque LSAs generated by lspgen must be filtered."""
    topo = ospf.lspgen(tmp_path / "ospf", NODES)
    ospf.start(bird={"p2p": p2p}, bbl={"p2p": p2p, "mrt": topo.mrt})
    ospf.wait_established()
    wait_until(lambda: topo.nodes <= ospf.frr_router_lsas(), 30,
               message="router LSAs of all nodes in BIRD database")
    wait_until(lambda: topo.prefixes <= ospf.frr_routes(), 15,
               message="BIRD routes to all nodes")
    assert len(topo.nodes) == NODES
    assert ospf.frr_nexthops(sorted(topo.prefixes)[-1]) == [BBL_ADDRESS]
    ospf.teardown()


@VERSIONS
def test_database_sync_bird_to_bbl(ospf, version):
    """BIRD external LSAs are flooded to the BNG Blaster, including
    new and flushed LSAs."""
    ospf.start(bird={"version": version, "prefixes": BIRD_PREFIXES})
    ospf.wait_established()

    def synced(count):
        expected = ospf.bird_lsa_ids(OSPF_LSA_TYPE_EXTERNAL, BIRD_ROUTER_ID)
        return len(expected) == count and \
            bbl_lsas(ospf, OSPF_LSA_TYPE_EXTERNAL, BIRD_ROUTER_ID) == expected

    wait_until(lambda: synced(BIRD_PREFIXES), 15, message="BIRD external LSAs")
    ospf.bird_add_prefix(BIRD_PREFIXES)
    wait_until(lambda: synced(BIRD_PREFIXES + 1), 15, message="new BIRD external LSA")
    ospf.bird_del_prefix(0)
    wait_until(lambda: synced(BIRD_PREFIXES), 15, message="flushed BIRD external LSA")
    ospf.teardown()


@pytest.mark.parametrize("auth_type", ["md5", "simple"])
def test_authentication(ospf, tmp_path, auth_type):
    key = "BBL%s" % auth_type  # simple passwords are limited to 8 bytes
    topo = ospf.lspgen(tmp_path / "ospf", 10)
    ospf.start(bird={"auth": (auth_type, key)},
               bbl={"mrt": topo.mrt, "ospf": {"auth-type": auth_type, "auth-key": key}})
    ospf.wait_established()
    wait_until(lambda: topo.prefixes <= ospf.frr_routes(), 30,
               message="BIRD routes to all nodes")
    ospf.teardown()


@pytest.mark.parametrize("bird_key,bbl_key", [
    ("BNGBlasterMD5", "WrongKey"),
    ("BNGBlasterMD5", None),
    (None, "BNGBlasterMD5"),
], ids=["wrong-key", "bird-only", "bbl-only"])
def test_authentication_mismatch(ospf, bird_key, bbl_key):
    bbl = {"auth-type": "md5", "auth-key": bbl_key} if bbl_key else {}
    ospf.start(bird={"auth": ("md5", bird_key) if bird_key else None}, bbl={"ospf": bbl})
    ospf.assert_not_established()
    ospf.teardown()
