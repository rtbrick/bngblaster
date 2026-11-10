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


@pytest.mark.parametrize("network,ospf,message", [
    ({"ospfv2-metric": 65536}, {}, "network->ospfv2-metric (0 - 65535)"),
    ({}, {"external": {"connections": [{"router-id": "10.10.0.2", "local-ipv4-address": "10.10.1.0",
                                         "metric": 65536}]}},
     "ospf->external->connections->metric (0 - 65535)"),
], ids=["interface-metric", "connection-metric"])
def test_config_invalid_ospf_metric(topology, tmp_path, network, ospf, message):
    """OSPF link metrics are 16 bit (RFC 2328 A.4.2)."""
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    bbl = config(topology.if_a)
    bbl["interfaces"]["network"][0].update(dict({"ospfv2-instance-id": 1}, **network))
    bbl["ospf"] = [dict({"instance-id": 1, "router-id": "10.10.0.1"}, **ospf)]
    with pytest.raises(RuntimeError, match="exited on start"):
        instance.start(bbl)
    with open(instance.path("stdout")) as f:
        assert "Invalid value for %s" % message in f.read()


@pytest.mark.parametrize("ldp,message", [
    ({"targeted-neighbors": [{"address": "10.0.0.256"}]},
     "Invalid value for ldp->targeted-neighbors->address"),
    ({"targeted-neighbors": [{"network-interface": "eth1"}]},
     "Missing value for ldp->targeted-neighbors->address"),
    ({"targeted-neighbors": [{"address": "10.0.0.1"}, {"address": "10.0.0.1"}]},
     "Duplicate ldp->targeted-neighbors->address 10.0.0.1"),
    ({"targeted-neighbors": [{"address": "10.0.0.1", "network-interface": "unknown"}]},
     "Failed to init LDP targeted neighbors"),
    ({"targeted-neighbors": [{"address": "fc00::1"}, {"address": "fc00::1"}],
      "ipv6-transport-address": "fc00::2"},
     "Duplicate ldp->targeted-neighbors->address fc00::1"),
    ({"targeted-neighbors": [{"address": "10.0.0.1", "source-address": "fc00::1"}]},
     "Invalid value for ldp->targeted-neighbors->source-address"),
    ({"targeted-neighbors": [{"address": "10.0.0.1"}], "no-ipv4-transport": True,
      "ipv6-transport-address": "fc00::2"},
     "LDP IPv4 targeted neighbors require IPv4 transport"),
    ({"targeted-neighbors": [{"address": "fc00::1"}]},
     "LDP IPv6 targeted neighbors require ldp->ipv6-transport-address"),
], ids=["address", "missing-address", "duplicate", "unknown-interface", "duplicate-ipv6",
        "source-family", "no-ipv4-transport", "no-ipv6-transport"])
def test_config_invalid_ldp_targeted(topology, tmp_path, ldp, message):
    cfg = config(topology.if_a)
    cfg["ldp"] = [dict({"instance-id": 1, "lsr-id": "10.10.10.2"}, **ldp)]
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    with pytest.raises(RuntimeError, match="exited on start"):
        instance.start(cfg)
    with open(instance.path("stdout")) as f:
        assert message in f.read()


def test_mtu_requires_jumbo_frames(topology, tmp_path):
    """PDUs are built up to the MTU, which must fit into the TX queue slots."""
    bbl_config = config(topology.if_a)
    bbl_config["interfaces"]["network"][0]["mtu"] = 4001
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    with pytest.raises(RuntimeError, match="exited on start"):
        instance.start(bbl_config)
    with open(instance.path("stdout")) as f:
        assert "mtu 4001 requires interfaces jumbo-frames" in f.read()
