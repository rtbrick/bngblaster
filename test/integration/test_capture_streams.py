"""
BNG Blaster stream capture with TX/RX threads

With capture-include-streams, I/O threads copy stream packets to
queues drained into the PCAP file by the main thread. The capture can
be stopped and started again at runtime (pcap-stop/pcap-start).
With PACKET_MMAP, the kernel strips the outer VLAN of received packets,
which must be restored in the capture of stream packets (RX threads)
and of packets redirected to the main thread (e.g. ARP).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import os
import struct
import time
from collections import defaultdict

from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30
PCAPNG_EPB = 6
INBOUND, OUTBOUND = 1, 2
BBL_MAGIC = struct.pack("<Q", 0x5274427269636b21)
BBL_HEADER_LEN = 48
BBL_FLOW_ID_OFFSET = 24
BBL_FLOW_SEQ_OFFSET = 32
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_ARP = 0x0806
VLAN = 100


class Host:
    """Run the BNG Blaster on the host instead of a network namespace."""
    name = "host"

    def cmd(self, cmd):
        return cmd


def pcap_packets(filename):
    """Return (direction, packet) of all enhanced packet blocks."""
    packets = []
    with open(filename, "rb") as f:
        data = f.read()
    offset = 0
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack_from("<II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            break  # incomplete block at the end of a running capture
        if block_type == PCAPNG_EPB:
            caplen = struct.unpack_from("<I", data, offset + 20)[0]
            packet = data[offset + 28:offset + 28 + caplen]
            options = offset + 28 + caplen + (-caplen % 4)
            direction = 0
            while options + 4 <= offset + block_len - 4:
                code, length = struct.unpack_from("<HH", data, options)
                if code == 0:
                    break
                if code == 2:
                    direction = struct.unpack_from("<I", data, options + 4)[0] & 0x3
                options += 4 + length + (-length % 4)
            packets.append((direction, packet))
        offset += block_len
    return packets


def is_stream(packet):
    return len(packet) >= BBL_HEADER_LEN and \
        packet[-BBL_HEADER_LEN:-BBL_HEADER_LEN + 8] == BBL_MAGIC


def stream_packets(filename):
    """Count stream packets per direction."""
    count = {INBOUND: 0, OUTBOUND: 0}
    if os.path.exists(filename):
        for direction, packet in pcap_packets(filename):
            if is_stream(packet) and direction in count:
                count[direction] += 1
    return count


def check_stream_capture(filename):
    """Stream packets must be captured without gaps or duplicates per flow
    and direction, and identical on TX and RX (incl. restored VLAN)."""
    captured = {INBOUND: {}, OUTBOUND: {}}
    for direction, packet in pcap_packets(filename):
        if is_stream(packet) and direction in captured:
            bbl = len(packet) - BBL_HEADER_LEN
            key = (struct.unpack_from("<I", packet, bbl + BBL_FLOW_ID_OFFSET)[0],
                   struct.unpack_from("<Q", packet, bbl + BBL_FLOW_SEQ_OFFSET)[0])
            assert key not in captured[direction], ("duplicate", direction, key)
            captured[direction][key] = packet
    for direction, packets in captured.items():
        flows = defaultdict(list)
        for flow, seq in packets:
            flows[flow].append(seq)
        assert flows, "no stream packets in direction %d" % direction
        for flow, seqs in flows.items():
            assert max(seqs) - min(seqs) + 1 == len(seqs), ("gaps", direction, flow)
    tx, rx = captured[OUTBOUND], captured[INBOUND]
    # Packets in flight when the capture stops are only captured on TX.
    common = tx.keys() & rx.keys()
    assert len(common) > 0.9 * min(len(tx), len(rx)), (len(common), len(tx), len(rx))
    for key in common:
        assert tx[key] == rx[key], ("TX and RX differ", key)


def loopback_config():
    return {
        "interfaces": {
            "io-mode": "loopback",
            "capture-include-streams": True,
            "links": [
                {"interface": "locA", "loopback-peer": "locB", "tx-threads": 1, "rx-threads": 1},
                {"interface": "locB", "tx-threads": 1, "rx-threads": 1}
            ],
            "network": [
                {"interface": "locA", "address": "10.0.0.1/24", "gateway": "10.0.0.2"},
                {"interface": "locB", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}
            ]
        },
        "traffic": {"autostart": True},
        "streams": [
            {"name": "A", "type": "ipv4", "direction": "downstream", "network-interface": "locA",
             "destination-ipv4-address": "10.0.0.2", "pps": 1000},
            {"name": "B", "type": "ipv4", "direction": "downstream", "network-interface": "locB",
             "destination-ipv4-address": "10.0.0.1", "pps": 1000}
        ]
    }


def test_capture_streams_threads(tmp_path, processes):
    instance = BngBlaster(Host(), tmp_path, "bbl").start(loopback_config())
    processes.append(instance)
    pcap = instance.path("pcap")
    wait_until(lambda: min(stream_packets(pcap).values()) > 1000, 15,
               message="stream packets in both directions captured")

    # Stopping the capture must not crash the I/O threads or the main thread.
    assert instance.ctrl("pcap-stop")["code"] == 200
    time.sleep(1)
    assert instance.alive()

    # Restarted capture includes streams again.
    pcap2 = str(tmp_path / "restart.pcap")
    assert instance.ctrl("pcap-start", file=pcap2)["code"] == 200
    wait_until(lambda: min(stream_packets(pcap2).values()) > 1000, 15,
               message="stream packets captured after pcap-start")

    assert instance.terminate(EXIT_TIMEOUT) == 0
    for interface in instance.report()["report"]["network-interfaces"]:
        assert interface["rx-stream-packets-loss"] == 0, interface
    with open(instance.path("log")) as f:
        assert "Incomplete stream capture" not in f.read()
    check_stream_capture(pcap)
    check_stream_capture(pcap2)


def vlan_config(if1, if2):
    links = [{"interface": i, "rx-threads": 1, "tx-threads": 1} for i in (if1, if2)]
    return {
        "interfaces": {
            "io-mode": "packet_mmap_raw",
            "capture-include-streams": True,
            "links": links,
            "network": [
                {"interface": if1, "address": "10.0.0.1/24", "gateway": "10.0.0.2", "vlan": VLAN},
                {"interface": if2, "address": "10.0.0.2/24", "gateway": "10.0.0.1", "vlan": VLAN}
            ]
        },
        "traffic": {"autostart": True},
        "streams": [
            {"name": "A", "type": "ipv4", "direction": "downstream",
             "network-interface": "%s:%d" % (if1, VLAN),
             "destination-ipv4-address": "10.0.0.2", "pps": 100}
        ]
    }


def test_capture_vlan_packet_mmap(tmp_path, processes, local_veth):
    instance = BngBlaster(local_veth.ns, tmp_path, "bbl").start(
        vlan_config(local_veth.if1, local_veth.if2))
    processes.append(instance)
    pcap = instance.path("pcap")
    wait_until(lambda: stream_packets(pcap)[INBOUND] > 100, 15,
               message="received stream packets captured")
    assert instance.terminate(EXIT_TIMEOUT) == 0

    rx_stream = rx_arp = 0
    for direction, packet in pcap_packets(pcap):
        if direction != INBOUND:
            continue
        # Received packets are captured with the stripped VLAN.
        ethertype, tci = struct.unpack_from("!HH", packet, 12)
        assert (ethertype, tci & 0xfff) == (ETH_TYPE_VLAN, VLAN), packet[:18].hex()
        if is_stream(packet):
            rx_stream += 1
        elif struct.unpack_from("!H", packet, 16)[0] == ETH_TYPE_ARP:
            rx_arp += 1
    assert rx_stream > 100
    assert rx_arp > 0
    check_stream_capture(pcap)
