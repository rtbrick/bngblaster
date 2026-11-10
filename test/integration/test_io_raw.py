"""
BNG Blaster io-mode raw

One BNG Blaster instance sends stream packets over a veth pair in both
directions with io-mode raw (recv() per packet), received by the main
loop or by RX threads.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30


@pytest.mark.parametrize("threads", [False, True], ids=["main", "threads"])
def test_io_raw(local_veth, processes, tmp_path, threads):
    interfaces = {
        "io-mode": "raw",
        "network": [
            {"interface": local_veth.if1, "address": "10.0.0.1/24", "gateway": "10.0.0.2"},
            {"interface": local_veth.if2, "address": "10.0.0.2/24", "gateway": "10.0.0.1"}
        ]
    }
    if threads:
        interfaces["links"] = [{"interface": i, "rx-threads": 1} for i in (local_veth.if1, local_veth.if2)]
    instance = BngBlaster(local_veth.ns, tmp_path).start({
        "interfaces": interfaces,
        "traffic": {"autostart": True},
        "streams": [
            {"name": "A", "type": "ipv4", "direction": "downstream", "network-interface": local_veth.if1,
             "destination-ipv4-address": "10.0.0.2", "pps": 200},
            {"name": "B", "type": "ipv4", "direction": "downstream", "network-interface": local_veth.if2,
             "destination-ipv4-address": "10.0.0.1", "pps": 200}
        ]
    })
    processes.append(instance)

    def info(flow_id):
        return instance.ctrl("stream-info", **{"flow-id": flow_id})["stream-info"]

    wait_until(lambda: all(info(f)["rx-packets"] >= 1000 for f in (1, 2)), 20,
               message="stream packets received")
    assert instance.terminate(EXIT_TIMEOUT) == 0
    for interface in instance.report()["report"]["network-interfaces"]:
        assert interface["rx-stream-packets-loss"] == 0, interface
