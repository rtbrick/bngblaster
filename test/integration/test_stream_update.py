"""
BNG Blaster stream-update

Updating the rate of streams must keep all of them sending, also if the
new rate equals the current one, so that the streams are added back to
the bucket being walked (same pps).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import time

import pytest

from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30
STREAMS = 8
PPS = 100


class Host:
    """Run the BNG Blaster on the host instead of a network namespace."""
    name = "host"

    def cmd(self, cmd):
        return cmd


def loopback_config(threads):
    if threads:
        links = [{"interface": "locA", "loopback-peer": "locB", "tx-threads": 1, "rx-threads": 1},
                 {"interface": "locB", "tx-threads": 1, "rx-threads": 1}]
    else:
        links = [{"interface": "locA", "loopback-peer": "locB"}]
    return {
        "interfaces": {
            "io-mode": "loopback",
            "links": links,
            "network": [
                {"interface": "locA", "address": "10.0.0.1/24", "gateway": "10.0.0.2"},
                {"interface": "locB", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}
            ]
        },
        "traffic": {"autostart": True},
        "streams": [
            {"name": "S%d" % i, "type": "ipv4", "direction": "downstream", "network-interface": "locA",
             "destination-ipv4-address": "10.0.0.2", "pps": PPS}
            for i in range(STREAMS)
        ]
    }


@pytest.mark.parametrize("threads", [False, True], ids=["main", "threads"])
def test_stream_update_same_pps(tmp_path, processes, threads):
    instance = BngBlaster(Host(), tmp_path, "bbl").start(loopback_config(threads))
    processes.append(instance)

    def tx_packets():
        return [instance.ctrl("stream-info", **{"flow-id": i + 1})["stream-info"]["tx-packets"]
                for i in range(STREAMS)]

    def sending():
        """Streams sending within one second."""
        before = tx_packets()
        time.sleep(1)
        return {i for i, (a, b) in enumerate(zip(before, tx_packets())) if b > a}

    all_streams = set(range(STREAMS))
    wait_until(lambda: sending() == all_streams, 10, message="all streams sending")

    # Same rate (twice), a new rate and back to a rate with existing bucket.
    for pps in (PPS, PPS, 2 * PPS, PPS):
        assert instance.ctrl("stream-update", pps=pps)["code"] == 200
        time.sleep(0.5)
        assert sending() == all_streams, "streams sending after stream-update pps %d" % pps
    assert instance.terminate(EXIT_TIMEOUT) == 0
