"""
BNG Blaster ICMP client on a network interface pinging the Linux peer

Small data sizes (0 and 1) are padded to the identifier and sequence
number, which overflowed the request data buffer before.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import BngBlaster, kernel_address, wait_until

COUNT = 3


def config(ifname, size):
    return {
        "interfaces": {
            "network": [{
                "interface": ifname,
                "address": "192.0.2.10/24",
                "gateway": "192.0.2.1"
            }]
        },
        "icmp-client": [{
            "network-interface": ifname,
            "destination-address": "192.0.2.1",
            "size": size,
            "interval": 0.2,
            "count": COUNT
        }]
    }


def client(instance):
    return instance.ctrl("icmp-clients")["icmp-clients"][0]


@pytest.mark.parametrize("size", [0, 1, 8])
def test_icmp_client_size(topology, processes, tmp_path, size):
    kernel_address(topology.b, topology.if_b, "192.0.2.1/24")
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    processes.append(instance)
    instance.start(config(topology.if_a, size))
    wait_until(lambda: client(instance)["received"] == COUNT, 15, message="ICMP echo replies")
    assert client(instance)["send"] == COUNT
    assert instance.terminate() == 0
