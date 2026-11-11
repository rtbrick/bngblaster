#!/usr/bin/env python3
"""
Relay between a BNG Blaster access interface and an A10NSP network
interface (Ethernet over MPLS with VLAN), emulating the L2BSA
pseudowire of the access node.

Frames received on the access side are sent to the network side with an
outer Ethernet header, the network interface VLAN and one MPLS label.
Frames received on the network side are forwarded to the access side
only with this VLAN, the outer header and labels are removed. Other
frames (ARP, ND of the network interface) are ignored.

Counters are printed as JSON on SIGTERM.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import json
import select
import signal
import socket
import struct
import sys

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 0x10
TP_STATUS_VLAN_TPID_VALID = 0x40


def open_socket(ifname):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    sock.bind((ifname, 0))
    return sock


def receive(sock):
    """Receive a frame with the VLAN tag stripped by the kernel restored."""
    data, ancdata, _, addr = sock.recvmsg(65535, socket.CMSG_SPACE(20))
    if addr[2] == socket.PACKET_OUTGOING:
        return None
    for level, kind, value in ancdata:
        if level == SOL_PACKET and kind == PACKET_AUXDATA:
            status, _, _, _, _, tci, tpid = struct.unpack("IIIHHHH", value[:20])
            if status & TP_STATUS_VLAN_VALID:
                if not status & TP_STATUS_VLAN_TPID_VALID:
                    tpid = 0x8100
                data = data[:12] + struct.pack("!HH", tpid, tci) + data[12:]
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("access")
    parser.add_argument("network")
    parser.add_argument("--vlan", type=int, required=True)
    parser.add_argument("--label", type=int, default=100)
    parser.add_argument("--peer-mac", required=True, help="MAC address of the A10NSP network interface")
    args = parser.parse_args()

    access, network = open_socket(args.access), open_socket(args.network)
    network_mac = open("/sys/class/net/%s/address" % args.network).read().strip()
    src = bytes.fromhex(network_mac.replace(":", ""))
    stats = {"upstream": 0, "downstream": 0, "untagged": 0}
    peer = bytes.fromhex(args.peer_mac.replace(":", ""))

    def stop(*_):
        print(json.dumps(stats))
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    while True:
        ready, _, _ = select.select([access, network], [], [])
        for sock in ready:
            frame = receive(sock)
            if not frame or len(frame) < 14:
                continue
            if sock is access:
                header = peer + src + struct.pack("!HHH", 0x8100, args.vlan, 0x8847)
                label = struct.pack("!I", (args.label << 12) | 0x100 | 64)
                network.send(header + label + frame)
                stats["upstream"] += 1
                continue
            # Network side: VLAN, MPLS label stack, inner Ethernet frame.
            if len(frame) < 18:
                continue
            tpid, tci, ethertype = struct.unpack("!HHH", frame[12:18])
            if tpid == 0x8847:
                # A10NSP traffic without the network interface VLAN.
                stats["untagged"] += 1
                continue
            if tpid != 0x8100 or tci & 0xfff != args.vlan or ethertype != 0x8847:
                continue
            offset = 18
            while offset + 4 <= len(frame):
                entry = struct.unpack("!I", frame[offset:offset + 4])[0]
                offset += 4
                if entry & 0x100:
                    break
            access.send(frame[offset:])
            stats["downstream"] += 1


if __name__ == "__main__":
    main()
