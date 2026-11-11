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
    ({"instance-id": 0}, "Invalid value for ldp->instance-id (1 - 65535)"),
    ({"hold-time": 0}, "Invalid value for ldp->hold-time (1 - 65535)"),
], ids=["address", "missing-address", "duplicate", "unknown-interface", "duplicate-ipv6",
        "source-family", "no-ipv4-transport", "no-ipv6-transport", "instance-id", "hold-time"])
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


def _stream(ifname, **rate):
    return {"streams": [dict({"name": "s1", "type": "ipv4", "direction": "downstream",
                              "network-interface": ifname,
                              "destination-ipv4-address": "192.0.2.1"}, **rate)]}


def _bgp(ifname, **bgp):
    return {"bgp": [dict({"network-interface": ifname, "local-ipv4-address": "192.0.2.10",
                          "peer-ipv4-address": "192.0.2.1"}, **bgp)]}


@pytest.mark.parametrize("update,message", [
    # String options of another JSON type (R3-029).
    (lambda i: _bgp(i, **{"tcp-ao-algorithm": 1, "tcp-ao-key": "secret"}),
     "Invalid value for bgp->tcp-ao-algorithm (string expected)"),
    (lambda i: _bgp(i, **{"tcp-ao-algorithm": "md5", "tcp-ao-key": 12345}),
     "Invalid value for bgp->tcp-ao-key (string expected)"),
    (lambda i: _bgp(i, **{"local-ipv4-address": 1}),
     "Invalid value for bgp->local-ipv4-address (string expected)"),
    (lambda i: {"isis": [{"instance-id": 1, "level1-auth-key": 12345}]},
     "Invalid value for isis->level1-auth-key (string expected)"),
    (lambda i: {"ospf": [{"instance-id": 1, "auth-type": "simple", "auth-key": 12345}]},
     "Invalid value for ospf->auth-key (string expected)"),
    (lambda i: {"ppp": {"authentication": {"username": 1}}},
     "Invalid value for ppp->authentication->username (string expected)"),
    (lambda i: {"l2tp-server": [{"name": "LNS", "address": "192.0.2.20", "secret": 1}]},
     "Invalid value for l2tp-server->secret (string expected)"),
    # Sections of another JSON type (R3-029).
    (lambda i: {"sessions": 5}, "Invalid value for sessions (object expected)"),
    (lambda i: {"ppp": {"lcp": []}}, "Invalid value for lcp (object expected)"),
    (lambda i: {"isis": 5}, "Invalid value for isis (object expected)"),
    (lambda i: {"isis": [5]}, "Invalid value for isis (object expected)"),
    (lambda i: {"streams": ["s1"]}, "Invalid value for streams (object expected)"),
    (lambda i: {"l2tp-server": "lns"}, "Invalid value for l2tp-server (list expected)"),
    (lambda i: {"access-line-profiles": {}}, "Invalid value for access-line-profiles (list expected)"),
    (lambda i: {"bgp-raw-update-files": [1]}, "Invalid value for bgp-raw-update-files"),
    (lambda i: {"isis": [{"instance-id": 1, "area": 5}]}, "Invalid value for isis->area"),
    (lambda i: {"isis": [{"instance-id": 1, "external": {"connections": {}}}]},
     "Invalid value for isis->external->connections (list expected)"),
    # Rates which overflow the timers (R3-027, R3-028).
    (lambda i: {"igmp": {"multicast-traffic-pps": 0}},
     "Invalid value for igmp->multicast-traffic-pps (1 - 65535)"),
    (lambda i: _stream(i, pps=1e-30), "Invalid value for stream->pps (0.0001 - 1000000000"),
    (lambda i: _stream(i, pps=1e15), "Invalid value for stream->pps (0.0001 - 1000000000"),
    (lambda i: _stream(i, bps=1e-300), "Invalid value for stream->pps (0.0001 - 1000000000"),
    (lambda i: _stream(i, **{"pps": 1, "pps-upstream": 1e-30}),
     "Invalid value for stream->pps-upstream (0.0001 - 1000000000"),
    (lambda i: {"icmp-client": [{"network-interface": i, "destination-address": "192.0.2.1",
                                 "interval": 1e-10}]},
     "Invalid value for icmp-client->interval (0.001 - 86400)"),
    (lambda i: {"icmp-client": [{"network-interface": i, "destination-address": "192.0.2.1",
                                 "interval": 1e30}]},
     "Invalid value for icmp-client->interval (0.001 - 86400)"),
    # Counts which wrap 8-bit TLV lengths and counters (R3-030).
    (lambda i: {"isis": [{"instance-id": 1, "area": ["49.0001/24"] * 257}]},
     "Invalid value for isis->area (1 - 3 areas)"),
    (lambda i: {"isis": [{"instance-id": 1, "sr-algo": [0] * 234}]},
     "Invalid value for isis->sr-algo (0 - 233 algorithms)"),
    # Duplicate instances (R3-031).
    (lambda i: {"isis": [{"instance-id": 1}, {"instance-id": 1}]},
     "Duplicate isis->instance-id 1"),
    (lambda i: {"ospf": [{"instance-id": 2}, {"instance-id": 2}]},
     "Duplicate ospf->instance-id 2"),
    (lambda i: {"ldp": [{"instance-id": 3, "lsr-id": "10.0.0.1"},
                        {"instance-id": 3, "lsr-id": "10.0.0.2"}]},
     "Duplicate ldp->instance-id 3"),
    # TCP MD5/AO key length (R3-046).
    (lambda i: _bgp(i, **{"tcp-ao-algorithm": "md5", "tcp-ao-key": ""}),
     "Invalid value for bgp->tcp-ao-key (1 - 80 characters)"),
    (lambda i: _bgp(i, **{"tcp-ao-algorithm": "hmac-sha-256-128", "tcp-ao-key-id": 1,
                          "tcp-ao-key": "k" * 81}),
     "Invalid value for bgp->tcp-ao-key (1 - 80 characters)"),
], ids=["tcp-ao-algorithm", "tcp-ao-key-type", "bgp-local-address", "isis-auth-key",
        "ospf-auth-key", "ppp-username", "l2tp-secret", "sessions", "ppp-lcp", "isis-number",
        "isis-element", "stream-element", "l2tp-server", "access-line-profiles",
        "raw-update-files", "isis-area-type", "isis-connections", "multicast-traffic-pps",
        "pps-tiny", "pps-huge", "bps-tiny", "pps-upstream", "icmp-interval-tiny",
        "icmp-interval-huge", "isis-area-count", "sr-algo-count", "isis-duplicate",
        "ospf-duplicate", "ldp-duplicate", "tcp-ao-key-empty", "tcp-ao-key-long"])
def test_config_invalid_type(topology, tmp_path, update, message):
    """Options of the wrong JSON type or out of range are rejected instead
    of being ignored (e.g. sessions without authentication)."""
    bbl = config(topology.if_a)
    bbl.update(update(topology.if_a))
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    with pytest.raises(RuntimeError, match="exited on start"):
        instance.start(bbl)
    with open(instance.path("stdout")) as f:
        assert message in f.read()


@pytest.mark.parametrize("network", ["lag", "member"])
def test_config_network_on_lag_member(topology, tmp_path, network):
    """A network interface on a LAG member link would never receive (R3-032),
    on the LAG interface itself it is accepted."""
    bbl = config(topology.if_a)
    bbl["interfaces"]["lag"] = [{"interface": "lag0"}]
    bbl["interfaces"]["links"] = [{"interface": topology.if_a, "lag-interface": "lag0"}]
    bbl["interfaces"]["network"][0]["interface"] = "lag0" if network == "lag" else topology.if_a
    bbl["interfaces"]["network"][0]["gateway-resolve-wait"] = False
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    if network == "lag":
        instance.start(bbl)
        assert instance.terminate() == 0
        return
    with pytest.raises(RuntimeError, match="exited on start"):
        instance.start(bbl)
    with open(instance.path("stdout")) as f:
        assert "Interface %s is a member of lag-interface lag0" % topology.if_a in f.read()


@pytest.mark.parametrize("args,message", [
    (["-g", "239.0.0.300"], "invalid IGMP group: 239.0.0.300"),
    (["-s", "foo"], "invalid IGMP source: foo"),
    (["-r", "70000"], "invalid IGMP group count: 70000"),
    (["-z", "abc"], "invalid IGMP zapping interval: abc"),
    (["-c", "10x"], "invalid session count: 10x"),
], ids=["igmp-group", "igmp-source", "igmp-group-count", "igmp-zap-interval", "sessions"])
def test_config_invalid_command_line(topology, tmp_path, args, message):
    """Command line overrides are validated (R3-033)."""
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    with pytest.raises(RuntimeError, match="exited on start"):
        instance.start(config(topology.if_a), args=args)
    with open(instance.path("stdout")) as f:
        assert message in f.read()
