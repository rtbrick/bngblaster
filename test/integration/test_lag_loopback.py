"""
BNG Blaster LAG over loopback links

Two LAG interfaces with two members each, connected by loopback links,
which require neither network namespaces nor real interfaces. With
LACP, both LAG interfaces of the same instance negotiate with each
other like two BNG Blaster instances.
The LAG interfaces have no link configuration of their own, which the
I/O setup of all I/O modes must handle (e.g. the automatic CPU
placement, which crashed for LAG interfaces).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30
STREAMS = 10


class Host:
    """Run the BNG Blaster on the host instead of a network namespace."""
    name = "host"

    def cmd(self, cmd):
        return cmd


def lag_config(rx_threads, lacp, max_active_links=None):
    links = [
        {"interface": "lolA1", "loopback-peer": "lolB1", "lag-interface": "lagA"},
        {"interface": "lolA2", "loopback-peer": "lolB2", "lag-interface": "lagA"},
        {"interface": "lolB1", "lag-interface": "lagB"},
        {"interface": "lolB2", "lag-interface": "lagB"}
    ]
    if rx_threads:
        # TX threads are not supported for LAG members.
        for link in links:
            link.update({"rx-threads": 1, "rx-auto-cpuset": True})
    return {
        "interfaces": {
            "io-mode": "loopback",
            "lag": [dict({"interface": lag, "lacp": lacp, "lacp-timeout-short": True},
                         **({"lacp-max-active-links": max_active_links} if max_active_links else {}))
                    for lag in ("lagA", "lagB")],
            "links": links,
            "network": [
                {"interface": "lagA", "address": "10.0.0.1/24", "gateway": "10.0.0.2"},
                {"interface": "lagB", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}
            ]
        },
        "traffic": {"autostart": True},
        "streams": [
            {"name": "A", "type": "ipv4", "direction": "downstream", "network-interface": "lagA",
             "destination-ipv4-address": "10.0.0.2", "count": STREAMS, "pps": 100,
             "source-port": 10000, "source-port-step": 1},
            {"name": "B", "type": "ipv4", "direction": "downstream", "network-interface": "lagB",
             "destination-ipv4-address": "10.0.0.1", "count": STREAMS, "pps": 100,
             "source-port": 10000, "source-port-step": 1}
        ]
    }


def lags_up(instance):
    for lag in instance.ctrl("lag-info")["lag-info"]:
        if lag["state"] != "Up" or [m["state"] for m in lag["members"]] != ["Up", "Up"]:
            return False
    return True


@pytest.mark.parametrize("lacp", [False, True], ids=["static", "lacp"])
@pytest.mark.parametrize("rx_threads", [False, True], ids=["main-loop", "rx-threads"])
def test_lag_traffic(tmp_path, processes, rx_threads, lacp):
    instance = BngBlaster(Host(), tmp_path, "bbl").start(lag_config(rx_threads, lacp))
    processes.append(instance)
    # LACP converges within a few PDUs, as state changes are sent immediately.
    wait_until(lambda: lags_up(instance), 5, 0.1, message="LAG interfaces up")

    def stream_rx():
        return {i["name"]: i["rx-packets-streams"]
                for i in instance.ctrl("network-interfaces")["network-interfaces"]}
    wait_until(lambda: all(rx > 10 * STREAMS for rx in stream_rx().values()), 15,
               message="stream traffic over both LAG interfaces")

    # Streams are distributed over both members of each LAG.
    links = {i["name"]: i for i in instance.ctrl("interfaces")["interfaces"]}
    for member in ("lolA1", "lolA2", "lolB1", "lolB2"):
        assert links[member]["tx-packets"] > 0, links[member]

    assert instance.terminate(EXIT_TIMEOUT) == 0
    for interface in instance.report()["report"]["network-interfaces"]:
        assert interface["rx-stream-packets-loss"] == 0, interface


IN_SYNC = 0x08
COLLECTING = 0x10
DISTRIBUTING = 0x20


def members(instance):
    """Map member interface to (state, own LACP state) of all LAG interfaces."""
    return {m["interface"]: (m["state"], m["lacp"]["actor-state"])
            for lag in instance.ctrl("lag-info")["lag-info"] for m in lag["members"]}


def tx_packets(instance):
    return {i["name"]: i["tx-packets"] for i in instance.ctrl("interfaces")["interfaces"]}


def test_lacp_standby(tmp_path, processes):
    """With lacp-max-active-links 1, the second member of each LAG is
    standby, which is not in sync (IEEE 802.1AX), so that neither side
    uses it, and takes over if the active member fails."""
    instance = BngBlaster(Host(), tmp_path, "bbl").start(lag_config(False, True, 1))
    processes.append(instance)
    expected = {"lolA1": "Up", "lolA2": "Standby", "lolB1": "Up", "lolB2": "Standby"}
    wait_until(lambda: {i: m[0] for i, m in members(instance).items()} == expected, 5, 0.1,
               message="one active and one standby member per LAG")
    for interface, (state, actor_state) in members(instance).items():
        if state == "Standby":
            assert not actor_state & (IN_SYNC | COLLECTING | DISTRIBUTING), (interface, actor_state)
        else:
            assert actor_state & (IN_SYNC | COLLECTING | DISTRIBUTING) == \
                IN_SYNC | COLLECTING | DISTRIBUTING, (interface, actor_state)

    # Only the active members send stream traffic (standby only LACP).
    before = tx_packets(instance)
    wait_until(lambda: tx_packets(instance)["lolA1"] - before["lolA1"] > 10 * STREAMS, 10,
               message="stream traffic on active member")
    after = tx_packets(instance)
    for standby in ("lolA2", "lolB2"):
        assert after[standby] - before[standby] < 10, (standby, before, after)

    # The standby members take over if the active member of lagA fails,
    # lagB once LACP of the disabled member expired.
    assert instance.ctrl("interface-disable", interface="lolA1")["code"] == 200
    wait_until(lambda: (members(instance)["lolA2"][0], members(instance)["lolB2"][0]) == ("Up", "Up"),
               10, 0.1, message="standby members up after failure of active member")
    before = tx_packets(instance)
    wait_until(lambda: tx_packets(instance)["lolA2"] - before["lolA2"] > 10 * STREAMS, 10,
               message="stream traffic on former standby member")

    assert instance.terminate(EXIT_TIMEOUT) == 0
