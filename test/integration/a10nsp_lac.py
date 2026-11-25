#!/usr/bin/env python3
"""
Relay between a BNG Blaster access interface and an A10NSP interface,
emulating a LAC that terminates the access PPPoE leg (e.g. tunneled via
L2TP) and originates a new PPPoE leg towards the A10NSP.

Upstream frames are sent with the LAC MAC address as source and the
PPPoE session-id of the A10NSP leg, downstream frames are sent to the
client MAC address with the PPPoE session-id of the access leg, which
is the A10NSP session-id plus an offset. Clients are mapped by Host-Uniq
during discovery and by PPPoE session-id afterwards. VLAN tags are kept,
other frames are dropped.

Counters are printed as JSON on SIGTERM.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import json
import select
import signal
import struct
import sys

from a10nsp_relay import open_socket, receive

ETH_P_PPPOE_DISC = 0x8863
ETH_P_PPPOE_SESS = 0x8864
VLAN_TPIDS = (0x8100, 0x88a8, 0x9100)
PPPOE_TAG_HOST_UNIQ = 0x0103
PPPOE_PADS = 0x65
SESSION_ID_OFFSET = 0x1000


def pppoe_offset(frame):
    """Return offset of the PPPoE header and the ethertype."""
    offset = 12
    while offset + 2 <= len(frame):
        ethertype = struct.unpack("!H", frame[offset:offset + 2])[0]
        if ethertype not in VLAN_TPIDS:
            return offset + 2, ethertype
        offset += 4
    return None, None


def host_uniq(frame, offset):
    length = struct.unpack("!H", frame[offset + 4:offset + 6])[0]
    tag, end = offset + 6, min(offset + 6 + length, len(frame))
    while tag + 4 <= end:
        kind, value_len = struct.unpack("!HH", frame[tag:tag + 4])
        if kind == PPPOE_TAG_HOST_UNIQ:
            return bytes(frame[tag + 4:tag + 4 + value_len])
        tag += 4 + value_len
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("access")
    parser.add_argument("a10nsp")
    parser.add_argument("--lac-mac", required=True)
    args = parser.parse_args()

    access, a10nsp = open_socket(args.access), open_socket(args.a10nsp)
    lac_mac = bytes.fromhex(args.lac_mac.replace(":", ""))
    clients_by_host_uniq = {}
    clients_by_session_id = {}
    stats = {"upstream": 0, "downstream": 0, "dropped": 0}

    def stop(*_):
        print(json.dumps(stats))
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    while True:
        ready, _, _ = select.select([access, a10nsp], [], [])
        for sock in ready:
            frame = receive(sock)
            if not frame:
                continue
            offset, ethertype = pppoe_offset(frame)
            if ethertype not in (ETH_P_PPPOE_DISC, ETH_P_PPPOE_SESS) or len(frame) < offset + 6:
                stats["dropped"] += 1
                continue
            frame = bytearray(frame)
            code = frame[offset + 1]
            session_id = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            if sock is access:
                if ethertype == ETH_P_PPPOE_DISC and not session_id:
                    clients_by_host_uniq[host_uniq(frame, offset)] = bytes(frame[6:12])
                if session_id:
                    session_id -= SESSION_ID_OFFSET
                frame[6:12] = lac_mac
                frame[offset + 2:offset + 4] = struct.pack("!H", session_id & 0xffff)
                a10nsp.send(bytes(frame))
                stats["upstream"] += 1
                continue
            if ethertype == ETH_P_PPPOE_DISC and (not session_id or code == PPPOE_PADS):
                client = clients_by_host_uniq.get(host_uniq(frame, offset))
                if client and session_id:
                    clients_by_session_id[session_id] = client
            else:
                client = clients_by_session_id.get(session_id)
            if not client:
                stats["dropped"] += 1
                continue
            frame[0:6] = client
            if session_id:
                frame[offset + 2:offset + 4] = struct.pack("!H", session_id + SESSION_ID_OFFSET)
            access.send(bytes(frame))
            stats["downstream"] += 1


if __name__ == "__main__":
    main()
