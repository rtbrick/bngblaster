"""
BNG Blaster OSPF against another BNG Blaster instance

Instance A (namespace A) injects LSAs of instance B (namespace B)
with the ospf-lsa-update command, which are flooded to B.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import socket
import struct

import pytest

from helpers import BngBlaster, wait_until
from isis_peer import fletcher

ROUTER_ID_A = "10.10.0.1"
ROUTER_ID_B = "10.10.0.2"
OSPF_LSA_TYPE_OPAQUE_AREA = 10
OSPF_RI_LSA_ID = "4.0.0.0"
OSPF_RI_TLV_HOSTNAME = 7
OSPF_MAX_AGE = 3600
OSPF_SEQ_MAX = 0x7fffffff


def bbl_config(ifname, address, gateway, router_id, hostname):
    return {
        "interfaces": {"network": {
            "interface": ifname, "address": address + "/24", "gateway": gateway,
            "ospfv2-instance-id": 1, "ospfv2-type": "p2p"}},
        "ospf": [{"instance-id": 1, "version": 2, "router-id": router_id, "hostname": hostname,
                  "hello-interval": 1, "dead-interval": 4}]
    }


def ri_lsa(router_id, seq, hostname, age=0):
    """Return a router information LSA (RFC 7770) with hostname TLV."""
    name = hostname.encode()
    body = struct.pack(">HH", OSPF_RI_TLV_HOSTNAME, len(name)) + name + b"\x00" * (-len(name) % 4)
    data = bytearray(struct.pack(">HBB4s4sIHH", age, 0, OSPF_LSA_TYPE_OPAQUE_AREA,
                                 socket.inet_aton(OSPF_RI_LSA_ID), socket.inet_aton(router_id),
                                 seq, 0, 20 + len(body)) + body)
    # The checksum excludes the age.
    data[16:18] = fletcher(data[2:], 14)
    return data.hex()


def ri(instance, router_id):
    """Return the router information LSA, empty if not (or no longer) present."""
    for lsa in instance.ctrl("ospf-database", instance=1)["ospf-database"]:
        if lsa["type"] == OSPF_LSA_TYPE_OPAQUE_AREA and lsa["router"] == router_id:
            return lsa
    return {}


def start_instances(topology, processes, tmp_path, ospf_a=None):
    config_a = bbl_config(topology.if_a, "10.0.0.1", "10.0.0.2", ROUTER_ID_A, "A")
    config_a["ospf"][0].update(ospf_a or {})
    a = BngBlaster(topology.a, tmp_path, name="a").start(config_a, logging=("info", "ospf"))
    processes.append(a)
    b = BngBlaster(topology.b, tmp_path, name="b").start(
        bbl_config(topology.if_b, "10.0.0.2", "10.0.0.1", ROUTER_ID_B, "B"), logging=("info", "ospf"))
    processes.append(b)

    def full(instance):
        neighbors = instance.ctrl("ospf-neighbors", instance=1)["ospf-neighbors"]
        return len(neighbors) == 1 and neighbors[0]["state"] == "Full"
    wait_until(lambda: full(a) and full(b), 15, message="OSPF neighbors full")
    return a, b


@pytest.fixture
def instances(topology, processes, tmp_path):
    return start_instances(topology, processes, tmp_path)


@pytest.fixture
def instances_auto_refresh(topology, processes, tmp_path):
    """Instance A with external auto-refresh."""
    return start_instances(topology, processes, tmp_path, {"external": {"auto-refresh": True}})


@pytest.mark.slow
def test_sequence_wrap(instances):
    """A floods a copy of the router information LSA of B with
    MaxSequenceNumber. B flushes this instance with MaxAge and originates
    the LSA again with InitialSequenceNumber once the flush is acknowledged
    (RFC 2328 section 12.1.6). A accepts the new instance after removing
    the flushed one."""
    a, b = instances
    wait_until(lambda: ri(a, ROUTER_ID_B), 10, message="router information LSA of B in A")
    result = a.ctrl("ospf-lsa-update", instance=1, lsa=[ri_lsa(ROUTER_ID_B, OSPF_SEQ_MAX, "B")])
    assert result["code"] == 200, result
    wait_until(lambda: "sequence number wrap" in open(b.path("log")).read(), 10,
               message="sequence number wrap of B")
    wait_until(lambda: ri(b, ROUTER_ID_B).get("seq") == "0x80000001", 10,
               message="B originated the LSA with InitialSequenceNumber")
    wait_until(lambda: ri(a, ROUTER_ID_B).get("seq") == "0x80000001" and ri(a, ROUTER_ID_B)["age"] < OSPF_MAX_AGE,
               120, interval=2, message="new instance of B in A")
    assert ri(b, ROUTER_ID_B)["age"] < OSPF_MAX_AGE
    assert a.terminate(30) == 0
    assert b.terminate(30) == 0


@pytest.mark.parametrize("lsa,error", [
    ("", "invalid OSPF LSA hex string"),
    ("0001", "invalid OSPF LSA hex string"),
    ("zz" * 20, "invalid OSPF LSA hex string"),
    ("000", "invalid OSPF LSA hex string"),
], ids=["empty", "short", "non-hex", "odd"])
def test_lsa_update_invalid(instances, lsa, error):
    """Invalid hex strings are rejected by ospf-lsa-update."""
    a, _ = instances
    result = a.ctrl("ospf-lsa-update", instance=1, lsa=[lsa])
    assert (result["code"], result.get("message")) == (400, error)


def test_lsa_update_self_and_older(instances):
    """External LSAs do not replace self originated LSAs and must be newer
    than the stored instance (as with IS-IS), the own router information
    LSA was replaced and an older instance accepted."""
    a, _ = instances
    wait_until(lambda: ri(a, ROUTER_ID_A) and ri(a, ROUTER_ID_B), 10, message="router information LSAs")
    own_seq = ri(a, ROUTER_ID_A)["seq"]

    def update(lsa):
        result = a.ctrl("ospf-lsa-update", instance=1, lsa=[lsa])
        assert result["code"] == 200, result
        return result["lsa-skipped"]
    # Skipped LSAs are reported (it returned 200 only).
    assert update(ri_lsa(ROUTER_ID_A, 0x80000100, "X")) == 1
    # A router which is not simulated, B would originate its own LSA again.
    assert update(ri_lsa("10.10.0.99", 0x80000100, "C")) == 0
    assert update(ri_lsa("10.10.0.99", 0x80000050, "D")) == 1
    assert ri(a, ROUTER_ID_A)["seq"] == own_seq
    assert ri(a, "10.10.0.99")["seq"] == "0x80000100"
    assert a.alive()


def test_lsa_update_size_limit(instances):
    """An LSA which does not fit into an LS Update PDU in an IPv4 datagram
    (65535 bytes with headers) is rejected, it overflowed the PDU buffer
    when flooded. The largest LSA which fits is accepted and flooded."""
    a, b = instances

    def lsa(size):
        body = struct.pack(">HH", 7, size - 24) + b"x" * (size - 24)
        data = bytearray(struct.pack(">HBB4s4sIHH", 0, 0, OSPF_LSA_TYPE_OPAQUE_AREA,
                                     socket.inet_aton("4.0.0.0"), socket.inet_aton("10.10.0.98"),
                                     0x80000001, 0, size) + body)
        data[16:18] = fletcher(data[2:], 14)
        return data.hex()

    # IPv4 header (20), OSPFv2 header (24) and LSA count (4).
    assert a.ctrl("ospf-lsa-update", instance=1, lsa=[lsa(65535)])["code"] != 200
    assert a.ctrl("ospf-lsa-update", instance=1, lsa=[lsa(65488)])["code"] != 200
    assert a.ctrl("ospf-lsa-update", instance=1, lsa=[lsa(65487)])["code"] == 200
    # It was accepted up to 65507 bytes, but never delivered.
    wait_until(lambda: ri(b, "10.10.0.98"), 10, message="largest LSA flooded to B")
    assert a.alive()


def test_auto_refresh_update_older(instances_auto_refresh):
    """With external auto-refresh, the BNG Blaster increases the sequence
    number of external LSAs, a changed LSA with a lower sequence number
    (e.g. from lspgen) continues with the next sequence number, an
    unchanged one is skipped (it was dropped silently)."""
    a, b = instances_auto_refresh

    def update(lsa):
        result = a.ctrl("ospf-lsa-update", instance=1, lsa=[lsa])
        assert result["code"] == 200, result
        return result["lsa-skipped"]
    assert update(ri_lsa("10.10.0.99", 0x80000005, "C")) == 0
    assert update(ri_lsa("10.10.0.99", 0x80000001, "C")) == 1
    assert ri(a, "10.10.0.99")["seq"] == "0x80000005"
    assert update(ri_lsa("10.10.0.99", 0x80000001, "D")) == 0
    assert ri(a, "10.10.0.99")["seq"] == "0x80000006"
    wait_until(lambda: ri(b, "10.10.0.99").get("seq") == "0x80000006", 10,
               message="changed LSA flooded to B")
    # The checksum was updated with the new sequence number.
    assert ri(b, "10.10.0.99")["checksum"] == ri(a, "10.10.0.99")["checksum"]


@pytest.mark.slow
def test_auto_refresh_purge(instances_auto_refresh):
    """An external LSA loaded with MaxAge (purge) is not refreshed with
    external auto-refresh, but removed after the purge timer (it was
    re-originated with age 0 after LSRefreshTime)."""
    a, b = instances_auto_refresh
    assert a.ctrl("ospf-lsa-update", instance=1, lsa=[ri_lsa("10.10.0.99", 0x80000001, "C")])["code"] == 200
    wait_until(lambda: ri(b, "10.10.0.99"), 10, message="LSA flooded to B")
    result = a.ctrl("ospf-lsa-update", instance=1, lsa=[ri_lsa("10.10.0.99", 0x80000002, "C", OSPF_MAX_AGE)])
    assert result["code"] == 200 and result["lsa-skipped"] == 0
    wait_until(lambda: ri(b, "10.10.0.99").get("age", OSPF_MAX_AGE) == OSPF_MAX_AGE, 10,
               message="purge flooded to B")
    # A refreshed LSA would stay in the database of A until LSRefreshTime.
    wait_until(lambda: not ri(a, "10.10.0.99"), 100, interval=2, message="purged LSA removed")
