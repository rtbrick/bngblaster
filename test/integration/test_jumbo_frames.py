"""
BNG Blaster jumbo frames with PACKET_MMAP

One BNG Blaster instance sends 9000 byte stream packets over a veth pair
with MTU 9000 in both directions. The PACKET_MMAP ring frames must be a
multiple of the page size (e.g. 16K or 64K on some aarch64 systems).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import struct

import pytest

from helpers import BngBlaster, lspgen, wait_until
from igp_common import mrt_lengths

EXIT_TIMEOUT = 30
LENGTH = 9000


@pytest.mark.parametrize("io_mode", ["packet_mmap", "packet_mmap_raw"])
def test_jumbo_frames(local_veth, processes, tmp_path, io_mode):
    for ifname in (local_veth.if1, local_veth.if2):
        local_veth.ns.exec(["ip", "link", "set", ifname, "mtu", "9000"])
    instance = BngBlaster(local_veth.ns, tmp_path).start({
        "interfaces": {
            "io-mode": io_mode,
            "jumbo-frames": True,
            "network": [
                {"interface": local_veth.if1, "address": "10.0.0.1/24", "gateway": "10.0.0.2", "mtu": 9000},
                {"interface": local_veth.if2, "address": "10.0.0.2/24", "gateway": "10.0.0.1", "mtu": 9000}
            ]
        },
        "traffic": {"autostart": True},
        "streams": [
            {"name": "A", "type": "ipv4", "direction": "downstream", "network-interface": local_veth.if1,
             "destination-ipv4-address": "10.0.0.2", "pps": 100, "length": LENGTH},
            {"name": "B", "type": "ipv4", "direction": "downstream", "network-interface": local_veth.if2,
             "destination-ipv4-address": "10.0.0.1", "pps": 100, "length": LENGTH}
        ]
    })
    processes.append(instance)

    def info(flow_id):
        return instance.ctrl("stream-info", **{"flow-id": flow_id})["stream-info"]

    wait_until(lambda: all(info(f)["rx-packets"] >= 200 for f in (1, 2)), 15,
               message="jumbo stream packets received")
    for f in (1, 2):
        # Received length including the Ethernet header.
        assert info(f)["rx-len"] == LENGTH + 14, info(f)
    assert instance.terminate(EXIT_TIMEOUT) == 0
    for interface in instance.report()["report"]["network-interfaces"]:
        assert interface["rx-stream-packets-loss"] == 0, interface


def test_lspgen_lsp_buffer_size(tmp_path):
    """LSPs follow --lsp-buffer-size, which overrides the
    value of a config file. The pcap file must stay readable."""
    args = ["-a", "49.0001/24", "-V", "2", "-C", "1921.6800.1001"]
    size = 11997
    lspgen(args + ["-c", "5", "-e", "8000", "-b", str(size), "-w", "topo.json", "-m", "large.mrt",
                   "-p", "large.pcap"], cwd=str(tmp_path))
    large = mrt_lengths(tmp_path / "large.mrt")
    assert 9216 < max(large) <= size
    assert max(large) + 17 <= pcapng_snaplen(tmp_path / "large.pcap")

    lspgen(args + ["-r", "topo.json", "-m", "same.mrt"], cwd=str(tmp_path))
    assert max(mrt_lengths(tmp_path / "same.mrt")) == max(large)

    lspgen(args + ["-r", "topo.json", "-b", "1492", "-m", "small.mrt"], cwd=str(tmp_path))
    assert max(mrt_lengths(tmp_path / "small.mrt")) <= 1492

    # Also applies if the config file has no value.
    config = json.loads((tmp_path / "topo.json").read_text())
    for node in config["level2"]:
        del node["lsp_buffer_size"]
    (tmp_path / "topo.json").write_text(json.dumps(config))
    lspgen(args + ["-r", "topo.json", "-b", "4000", "-m", "nokey.mrt"], cwd=str(tmp_path))
    assert 1492 < max(mrt_lengths(tmp_path / "nokey.mrt")) <= 4000


def pcapng_snaplen(path):
    """Return the snaplen of the first interface description block."""
    data = path.read_bytes()
    offset = 0
    while True:
        block_type, block_len = struct.unpack_from("<II", data, offset)
        if block_type == 1:
            return struct.unpack_from("<I", data, offset + 12)[0]
        offset += block_len
