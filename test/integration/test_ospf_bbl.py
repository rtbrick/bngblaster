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


def ri_lsa(router_id, seq, hostname):
    """Return a router information LSA (RFC 7770) with hostname TLV."""
    name = hostname.encode()
    body = struct.pack(">HH", OSPF_RI_TLV_HOSTNAME, len(name)) + name + b"\x00" * (-len(name) % 4)
    data = bytearray(struct.pack(">HBB4s4sIHH", 0, 0, OSPF_LSA_TYPE_OPAQUE_AREA,
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


@pytest.fixture
def instances(topology, processes, tmp_path):
    a = BngBlaster(topology.a, tmp_path, name="a").start(
        bbl_config(topology.if_a, "10.0.0.1", "10.0.0.2", ROUTER_ID_A, "A"), logging=("info", "ospf"))
    processes.append(a)
    b = BngBlaster(topology.b, tmp_path, name="b").start(
        bbl_config(topology.if_b, "10.0.0.2", "10.0.0.1", ROUTER_ID_B, "B"), logging=("info", "ospf"))
    processes.append(b)

    def full(instance):
        neighbors = instance.ctrl("ospf-neighbors", instance=1)["ospf-neighbors"]
        return len(neighbors) == 1 and neighbors[0]["state"] == "Full"
    wait_until(lambda: full(a) and full(b), 15, message="OSPF neighbors full")
    return a, b


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
