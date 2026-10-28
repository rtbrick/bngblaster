"""
BNG Blaster configuration values out of range

Values which would be converted to integer types out of range or are
of the wrong type are rejected on start instead of being truncated
or crashing.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import BngBlaster


def config(ifname, interfaces=None, link=None, isis=None):
    config = {
        "interfaces": dict({
            "links": [dict({"interface": ifname}, **(link or {}))],
            "network": [{
                "interface": ifname,
                "address": "192.0.2.10/24",
                "gateway": "192.0.2.1"
            }]
        }, **(interfaces or {}))
    }
    if isis is not None:
        config["interfaces"]["network"][0]["isis-instance-id"] = 1
        config["isis"] = [dict({"instance-id": 1}, **isis)]
    return config


@pytest.mark.parametrize("args,message", [
    ({"interfaces": {"tx-interval": -1}}, "interfaces->tx-interval"),
    ({"interfaces": {"rx-interval": 1e30}}, "interfaces->rx-interval"),
    ({"link": {"tx-interval": -1}}, "links->tx-interval"),
    ({"link": {"rx-cpuset": -1}}, "links->rx-cpuset"),
    ({"link": {"tx-cpuset": [0, 70000]}}, "links->tx-cpuset"),
    ({"isis": {"area": [5]}}, "isis->area"),
    ({"isis": {"sr-algo": 300}}, "isis->sr-algo"),
    ({"isis": {"sr-algo": [0, -1]}}, "isis->sr-algo"),
], ids=["tx-interval", "rx-interval", "link-tx-interval", "rx-cpuset", "tx-cpuset",
        "isis-area", "sr-algo", "sr-algo-list"])
def test_config_invalid(topology, tmp_path, args, message):
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    with pytest.raises(RuntimeError, match="exited on start"):
        instance.start(config(topology.if_a, **args))
    with open(instance.path("stdout")) as f:
        assert "Invalid value for %s" % message in f.read()
