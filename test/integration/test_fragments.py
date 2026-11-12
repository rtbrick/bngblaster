"""
BNG Blaster reassembly of fragmented IPv4 stream traffic

Namespace A runs the BNG Blaster with two network interfaces, namespace
B a Linux router between them which fragments the stream packets (MTU
1000 towards the second interface), optionally with duplicated packets
(netem).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

import helpers
from helpers import BngBlaster, wait_until
from test_io_interfaces import veth

EXIT_TIMEOUT = 30


@pytest.mark.parametrize("duplicate", [False, True], ids=["plain", "duplicate"])
def test_reassembly(topology, processes, tmp_path, duplicate):
    """Fragmented stream packets are reassembled and verified without loss,
    also if fragments are duplicated (RFC 791 reassembly by offset)."""
    n = helpers.if_id()
    frag_a, frag_b = "bbl%da" % n, "bbl%db" % n
    veth(topology.a, frag_a, topology.b, frag_b)
    topology.b.exec(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
    helpers.kernel_address(topology.b, topology.if_b, "10.1.0.1/24")
    helpers.kernel_address(topology.b, frag_b, "10.2.0.1/24")
    topology.b.exec(["ip", "link", "set", frag_b, "mtu", "1000"])
    if duplicate:
        topology.b.exec(["tc", "qdisc", "add", "dev", frag_b, "root", "netem", "duplicate", "50%"])
    instance = BngBlaster(topology.a, tmp_path, "bbl").start({
        "interfaces": {"network": [
            {"interface": topology.if_a, "address": "10.1.0.10/24", "gateway": "10.1.0.1"},
            {"interface": frag_a, "address": "10.2.0.10/24", "gateway": "10.2.0.1"}]},
        "traffic": {"reassemble-fragments": True},
        "streams": [{"name": "S1", "type": "ipv4", "direction": "downstream", "pps": 20, "length": 1400,
                     "ipv4-df": False, "network-interface": topology.if_a,
                     "destination-ipv4-address": "10.2.0.10"}]})
    processes.append(instance)

    def stream():
        return instance.ctrl("stream-info", **{"flow-id": 1})["stream-info"]

    wait_until(lambda: stream()["rx-packets"] >= 20, 15, message="reassembled stream packets")
    info = stream()
    assert info["rx-fragments"] >= 2, info
    assert info["rx-loss"] == 0, info
    assert instance.terminate(EXIT_TIMEOUT) == 0
