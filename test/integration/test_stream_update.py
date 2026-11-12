"""
BNG Blaster stream-update

Updating the rate of streams must keep all of them sending, also if the
new rate equals the current one, so that the streams are added back to
the bucket being walked (same pps).

stream-reset with TX and RX threads must not count packets received in
flight of the reset after it.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import subprocess
import sys
import time

import pytest

from helpers import REPO, BngBlaster, if_id, wait_until

EXIT_TIMEOUT = 30
STREAMS = 8
PPS = 100


class Host:
    """Run the BNG Blaster on the host instead of a network namespace."""
    name = "host"

    def cmd(self, cmd):
        return cmd


def loopback_config(threads, pps=PPS):
    n = if_id()
    link_a, link_b = "loc%da" % n, "loc%db" % n
    if threads:
        links = [{"interface": link_a, "loopback-peer": link_b, "tx-threads": 1, "rx-threads": 1},
                 {"interface": link_b, "tx-threads": 1, "rx-threads": 1}]
    else:
        links = [{"interface": link_a, "loopback-peer": link_b}]
    return {
        "interfaces": {
            "io-mode": "loopback",
            "links": links,
            "network": [
                {"interface": link_a, "address": "10.0.0.1/24", "gateway": "10.0.0.2"},
                {"interface": link_b, "address": "10.0.0.2/24", "gateway": "10.0.0.1"}
            ]
        },
        "traffic": {"autostart": True},
        "streams": [
            {"name": "S%d" % i, "type": "ipv4", "direction": "downstream", "network-interface": link_a,
             "destination-ipv4-address": "10.0.0.2", "pps": pps}
            for i in range(STREAMS)
        ]
    }


@pytest.mark.full
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


@pytest.mark.full
def test_stream_reset_in_flight(tmp_path, processes):
    """After stream-reset, each stream counts only the packets sent after
    it. The race of the RX thread with the reset is rare (about one in
    thousands of resets per flow), so this test does not fail reliably
    without the RX thread handling the reset."""
    instance = BngBlaster(Host(), tmp_path, "bbl").start(loopback_config(True, pps=5000))
    processes.append(instance)

    def verified():
        stats = instance.ctrl("stream-stats")["stream-stats"]
        return stats["verified-flows"] == stats["total-flows"]

    wait_until(verified, 10, message="streams verified")
    for _ in range(20):
        assert instance.ctrl("stream-reset")["code"] == 200
        wait_until(verified, 10, interval=0.05, message="streams verified after reset")
        assert instance.ctrl("stream-stop")["code"] == 200
        time.sleep(0.3)
        for i in range(STREAMS):
            info = instance.ctrl("stream-info", **{"flow-id": i + 1})["stream-info"]
            expected = info["rx-last-seq"] - info["rx-first-seq"] + 1
            assert info["rx-packets"] == expected and info["rx-packets"] <= info["tx-packets"], info
            assert info["rx-wrong-order"] == 0 and info["rx-loss"] == 0, info
        assert instance.ctrl("stream-start")["code"] == 200
    assert instance.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.parametrize("threads", [False, True], ids=["main", "threads"])
def test_stream_reset_stopped(tmp_path, processes, threads):
    """The RX sequence state and delays are cleared with the next packet
    of the flow after stream-reset. A stopped stream, which receives
    nothing more, must not show the values from before the reset."""
    config = loopback_config(threads)
    config["traffic"]["stream-delay-calculation"] = True
    instance = BngBlaster(Host(), tmp_path, "bbl").start(config)
    processes.append(instance)
    keys = ("rx-first-seq", "rx-last-seq", "rx-wrong-order", "rx-delay-us-min", "rx-delay-us-max")

    def info():
        return instance.ctrl("stream-info", **{"flow-id": 1})["stream-info"]

    wait_until(lambda: info()["rx-last-seq"] > 0, 10, message="stream receiving")
    assert instance.ctrl("stream-stop")["code"] == 200
    time.sleep(0.5)
    assert instance.ctrl("stream-reset")["code"] == 200
    time.sleep(0.5)
    stopped = info()
    assert stopped["tx-packets"] == 0 and stopped["rx-packets"] == 0, stopped
    assert all(stopped[k] == 0 for k in keys), stopped

    assert instance.ctrl("stream-start")["code"] == 200
    wait_until(lambda: info()["rx-last-seq"] > 0, 10, message="stream receiving after start")
    started = info()
    assert started["rx-first-seq"] == started["tx-first-seq"], started
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_stream_real_arguments(tmp_path, processes):
    """Integer arguments sent as integral reals (bngblaster-cli sends 2.0
    as real) must select the objects like integers, other reals must be
    rejected, instead of being ignored with the command applied to all."""
    instance = BngBlaster(Host(), tmp_path, "bbl").start(loopback_config(False))
    processes.append(instance)

    def info(flow_id):
        return instance.ctrl("stream-info", **{"flow-id": flow_id}, debug=True)["stream-info"]

    def enabled():
        return [info(i + 1)["enabled"] for i in range(STREAMS)]

    assert instance.ctrl("stream-stop", **{"flow-id": 2.0})["code"] == 200
    assert enabled() == [i != 1 for i in range(STREAMS)]
    assert instance.ctrl("stream-start")["code"] == 200
    assert instance.ctrl("stream-stop", flows=[1.0, 3])["code"] == 200
    assert enabled() == [i not in (0, 2) for i in range(STREAMS)]
    assert instance.ctrl("stream-start")["code"] == 200

    for args in ({"flow-id": 1.5}, {"flow-id-min": 3.5}, {"flows": [1.5]}, {"flow-id": 1e300}):
        assert instance.ctrl("stream-stop", **args)["code"] == 400, args
    assert all(enabled())

    assert instance.ctrl("stream-update", **{"flow-id": 1.0, "pps": 12.5})["code"] == 200
    assert [info(i + 1)["debug-tx-pps-config"] for i in range(STREAMS)] == [12.5] + [PPS] * (STREAMS - 1)

    # bngblaster-cli sends pps as number (announced type of the real argument).
    cli = [sys.executable, str(REPO / "code/bngblaster-cli"), instance.socket]
    for pps, flow_id in (("50", "2"), ("50.5", "3")):
        out = subprocess.run(cli + ["stream-update", "flow-id", flow_id, "pps", pps],
                             capture_output=True, text=True, timeout=30)
        assert json.loads(out.stdout)["code"] == 200, out.stdout + out.stderr
    assert [info(i + 1)["debug-tx-pps-config"] for i in range(3)] == [12.5, 50, 50.5]
    assert instance.terminate(EXIT_TIMEOUT) == 0
