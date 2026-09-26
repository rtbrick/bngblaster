"""
BNG Blaster Quickstart Guide (docsrc/sources/quickstart.rst)

The configurations follow the quickstart guide, only the interface
names (veth1.1 and veth1.2) are replaced. All examples except BGP run
a single BNG Blaster instance on both ends of a veth pair.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

import helpers
from helpers import AFI_IP, AFI_IP6, SAFI_UNICAST, BngBlaster, GoBgp, bgpupdate, ldpupdate, lspgen, wait_until

SESSIONS = 10
EXIT_TIMEOUT = 30
REPORT_ARGS = ("-j", "sessions", "-j", "streams")


@pytest.fixture
def bbl(local_veth, processes, tmp_path):
    def start(config, logging=("info",)):
        instance = BngBlaster(local_veth.ns, tmp_path).start(config, logging=logging, args=REPORT_ARGS)
        processes.append(instance)
        return instance
    return start


def counters(bbl):
    return bbl.ctrl("session-counters")["session-counters"]


def streams_verified(bbl, count):
    """All streams verified without loss."""
    streams = bbl.ctrl("stream-summary")["stream-summary"]
    return (len(streams) == count and
            all(s["verified"] and s["rx-packets"] > 0 and s["rx-loss"] == 0 for s in streams))


def assert_clean_exit(bbl):
    assert bbl.terminate(EXIT_TIMEOUT) == 0
    return bbl.report()


def access_config(veth, access):
    """PPPoE and DHCP examples: A10NSP server and access client."""
    return {
        "interfaces": {
            "a10nsp": [{"interface": veth.if1}],
            "access": [dict({
                "interface": veth.if2,
                "outer-vlan-min": 1,
                "outer-vlan-max": 4000,
                "inner-vlan": 7,
                "stream-group-id": 1
            }, **access)]
        },
        "sessions": {"count": SESSIONS},
        "session-traffic": {"ipv4-pps": 1},
        "streams": [{
            "stream-group-id": 1,
            "name": "S1",
            "type": "ipv4",
            "direction": "both",
            "priority": 128,
            "length": 256,
            "pps": 1,
            "a10nsp-interface": veth.if1
        }]
    }


def wait_sessions_verified(bbl):
    wait_until(lambda: counters(bbl)["sessions-established"] == SESSIONS, 30,
               message="all sessions established")
    wait_until(lambda: counters(bbl)["session-traffic-flows-verified"] == 2 * SESSIONS and
               counters(bbl)["stream-traffic-flows-verified"] == 2 * SESSIONS, 15,
               message="session traffic and streams verified")


def test_pppoe(local_veth, bbl):
    config = access_config(local_veth, {"type": "pppoe"})
    config["pppoe"] = {"reconnect": True}
    config["dhcpv6"] = {"enable": False}
    instance = bbl(config, logging=("info", "ip"))
    wait_sessions_verified(instance)

    info = instance.ctrl("session-info", **{"session-id": 1})["session-info"]
    assert info["session-state"] == "Established"
    assert info["reply-message"] == "BNG-Blaster-A10NSP"
    assert info["ipcp-state"] == "Opened"
    assert info["a10nsp"]["interface"] == local_veth.if1

    report = assert_clean_exit(instance)
    assert len(report["report"]["sessions"]) == SESSIONS


def test_dhcp(local_veth, bbl):
    config = access_config(local_veth, {"type": "ipoe", "ipv6": False})
    config["access-line"] = {
        "agent-remote-id": "DEU.RTBRICK.{session-global}",
        "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:{session-global}"
    }
    config["dhcp"] = {"enable": True, "broadcast": False}
    instance = bbl(config, logging=("info", "dhcp"))
    wait_until(lambda: counters(instance)["dhcp-sessions-established"] == SESSIONS, 30,
               message="all DHCP sessions established")
    wait_sessions_verified(instance)

    info = instance.ctrl("session-info", **{"session-id": 1})["session-info"]
    assert info["a10nsp"]["dhcp-ari"] == "DEU.RTBRICK.1"
    assert_clean_exit(instance)


def test_isis(local_veth, bbl, tmp_path):
    mrt = str(tmp_path / "isis.mrt")
    lspgen(["-a", "49.0001/24", "-K", "secret123", "-T", "md5", "-C", "1921.6800.1001", "-m", mrt])

    def instance(instance_id, system_id, hostname, sid, external=None):
        config = {
            "instance-id": instance_id,
            "area": ["49.0001/24", "49.0002/24"],
            "system-id": system_id,
            "router-id": "192.168.1.%d" % instance_id,
            "hostname": hostname,
            "sr-base": 1000,
            "sr-range": 100,
            "sr-node-sid": sid,
            "level1-auth-key": "secret123",
            "level1-auth-type": "md5"
        }
        if external:
            config["external"] = external
        return config

    config = {
        "interfaces": {
            "network": [
                {
                    "interface": local_veth.if1,
                    "address": "10.0.0.1/24",
                    "gateway": "10.0.0.2",
                    "address-ipv6": "fc66:1337:7331::1/64",
                    "gateway-ipv6": "fc66:1337:7331::2",
                    "isis-instance-id": 1,
                    "isis-level": 1
                },
                {
                    "interface": local_veth.if2,
                    "address": "10.0.0.2/24",
                    "gateway": "10.0.0.1",
                    "address-ipv6": "fc66:1337:7331::2/64",
                    "gateway-ipv6": "fc66:1337:7331::1",
                    "isis-instance-id": 2,
                    "isis-level": 1
                }
            ]
        },
        "isis": [
            instance(1, "1921.6800.1001", "R1", 1, external={
                "mrt-file": mrt,
                "connections": [{"system-id": "1921.6800.0000.00", "l1-metric": 1000, "l2-metric": 2000}]
            }),
            instance(2, "1921.6800.1002", "R2", 2)
        ],
        "streams": [{
            "name": "RAW1",
            "type": "ipv4",
            "direction": "downstream",
            "priority": 128,
            "destination-ipv4-address": "192.168.1.2",
            "length": 256,
            "pps": 1,
            "network-interface": local_veth.if1
        }]
    }
    bbl_isis = bbl(config, logging=("info", "isis"))

    def adjacencies_up():
        adjacencies = bbl_isis.ctrl("isis-adjacencies")["isis-adjacencies"]
        return len(adjacencies) == 2 and all(a["adjacency-state"] == "Up" for a in adjacencies)

    wait_until(adjacencies_up, 30, message="ISIS adjacencies up")
    # R2 learns R1 and the emulated topology (10 nodes) behind R1.
    wait_until(lambda: len(bbl_isis.ctrl("isis-database", instance=2, level=1)["isis-database"]) >= 12,
               15, message="ISIS topology flooded to R2")
    wait_until(lambda: streams_verified(bbl_isis, 1), 15, message="stream verified")
    assert_clean_exit(bbl_isis)


def test_ldp(local_veth, bbl, tmp_path):
    raw_update = str(tmp_path / "out.ldp")
    ldpupdate(["-l", "10.2.3.1", "-p", "13.37.0.0/32", "-P", "10", "-M", "10000", "-f", raw_update])
    config = {
        "interfaces": {
            "capture-include-streams": True,
            "network": [
                {
                    "interface": local_veth.if1,
                    "address": "10.0.0.1/24",
                    "gateway": "10.0.0.2",
                    "ldp-instance-id": 1
                },
                {
                    "interface": local_veth.if2,
                    "address": "10.0.0.2/24",
                    "gateway": "10.0.0.1",
                    "ldp-instance-id": 2
                }
            ]
        },
        "ldp": [
            {"instance-id": 1, "lsr-id": "10.2.3.1", "raw-update-file": raw_update},
            {"instance-id": 2, "lsr-id": "10.2.3.2"}
        ],
        "streams": [{
            "name": "S1",
            "type": "ipv4",
            "direction": "downstream",
            "priority": 128,
            "network-interface": local_veth.if2,
            "destination-ipv4-address": "100.0.0.1",
            "ldp-ipv4-lookup-address": "13.37.0.1",
            "pps": 1
        }]
    }
    bbl_ldp = bbl(config, logging=("info", "ldp"))

    def sessions_operational():
        sessions = bbl_ldp.ctrl("ldp-sessions")["ldp-sessions"]
        return len(sessions) == 2 and all(s["state"] == "operational" for s in sessions)

    wait_until(sessions_operational, 30, message="LDP sessions operational")
    database = wait_until(lambda: [e for e in bbl_ldp.ctrl("ldp-database", **{"ldp-instance-id": 2})["ldp-database"]
                                   if e["prefix"].startswith("13.37.0.")], 15,
                          message="LDP labels learned")
    assert len(database) == 10
    wait_until(lambda: streams_verified(bbl_ldp, 1), 15, message="stream verified")
    assert_clean_exit(bbl_ldp)


def test_network_traffic(local_veth, bbl):
    config = {
        "interfaces": {
            "network": [
                {"interface": local_veth.if1, "address": "192.168.0.1/24", "gateway": "192.168.0.2"},
                {"interface": local_veth.if2, "address": "192.168.0.2/24", "gateway": "192.168.0.1"}
            ]
        },
        "streams": [
            {"name": "S1", "type": "ipv4", "pps": 1, "network-interface": local_veth.if1,
             "destination-ipv4-address": "192.168.0.2"},
            {"name": "S2", "type": "ipv4", "pps": 1, "network-interface": local_veth.if2,
             "destination-ipv4-address": "192.168.0.1"}
        ]
    }
    instance = bbl(config, logging=("info", "loss"))
    wait_until(lambda: streams_verified(instance, 2), 15, message="streams verified")
    report = assert_clean_exit(instance)
    assert len(report["report"]["streams"]) == 2


GOBGPD_CONF = """
[global.config]
    as = 65001
    router-id = "192.168.92.1"
    local-address-list = ["192.168.92.1"]

[[neighbors]]
    [neighbors.config]
        peer-as = 65001
        neighbor-address = "192.168.92.2"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-labelled-unicast"
    [[neighbors.afi-safis]]
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-labelled-unicast"
"""


@pytest.mark.usefixtures("gobgp_bin")
def test_bgp(topology, processes, tmp_path):
    """BNG Blaster (namespace A) with iBGP session to GoBGP (namespace B)."""
    prefixes, updates = 1000, 5000
    helpers.kernel_address(topology.b, topology.if_b, "192.168.92.1/24")
    raw_update = str(tmp_path / "out.bgp")
    bgpupdate(["-a", "65001", "-l", "100", "-n", "192.168.92.2", "-p", "11.0.0.0/28",
               "-P", str(prefixes), "-f", raw_update])
    bgpupdate(["-a", "65001", "-l", "100", "-n", "192.168.92.2", "-p", "fc66:11::/64",
               "-P", str(prefixes), "-f", raw_update, "--append"])

    gobgp = GoBgp(topology.b, tmp_path).start(GOBGPD_CONF)
    processes.append(gobgp)
    instance = BngBlaster(topology.a, tmp_path).start({
        "interfaces": {
            "network": {
                "interface": topology.if_a,
                "address": "192.168.92.2/24",
                "gateway": "192.168.92.1"
            }
        },
        "bgp": [{
            "local-ipv4-address": "192.168.92.2",
            "peer-ipv4-address": "192.168.92.1",
            "raw-update-file": raw_update,
            "local-as": 65001,
            "peer-as": 65001
        }]
    }, logging=("info", "bgp"))
    processes.append(instance)

    def session():
        return instance.ctrl("bgp-sessions")["bgp-sessions"][0]

    wait_until(lambda: session()["state"] == "established" and gobgp.session_established("192.168.92.2"),
               30, message="BGP session established")
    wait_until(lambda: session()["raw-update-state"] == "done", 15, message="raw update done")
    wait_until(lambda: gobgp.received("192.168.92.2", AFI_IP, SAFI_UNICAST) == prefixes and
               gobgp.received("192.168.92.2", AFI_IP6, SAFI_UNICAST) == prefixes, 15,
               message="GoBGP prefixes received")

    # Add and withdraw further routes via control socket.
    update, withdraw = str(tmp_path / "update.bgp"), str(tmp_path / "withdraw.bgp")
    bgpupdate(["-a", "65001", "-l", "100", "-n", "192.168.92.2", "-p", "22.0.0.0/28",
               "-P", str(updates), "-f", update])
    bgpupdate(["-a", "65001", "-n", "192.168.92.2", "-p", "22.0.0.0/28",
               "-P", str(updates), "-f", withdraw, "--withdraw"])
    response = instance.ctrl("bgp-raw-update", file=update, **{
        "peer-ipv4-address": "192.168.92.1", "local-ipv4-address": "192.168.92.2"})
    assert response["bgp-raw-update"]["started"] == 1, response
    wait_until(lambda: gobgp.received("192.168.92.2", AFI_IP, SAFI_UNICAST) == prefixes + updates, 30,
               message="GoBGP received additional prefixes")
    response = instance.ctrl("bgp-raw-update", file=withdraw)
    assert response["bgp-raw-update"]["started"] == 1, response
    wait_until(lambda: gobgp.received("192.168.92.2", AFI_IP, SAFI_UNICAST) == prefixes, 30,
               message="GoBGP prefixes withdrawn")
    assert instance.terminate(EXIT_TIMEOUT) == 0
