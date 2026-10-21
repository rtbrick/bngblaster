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


def lag_config(rx_threads, lacp):
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
            "lag": [{"interface": lag, "lacp": lacp, "lacp-timeout-short": True}
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
