#!/usr/bin/env python3
"""
Scripted LACP partner (IEEE 802.1AX) for tests of the BNG Blaster LAG.

Every second, a LACPDU is sent on each interface with the actor
information of the peer and the last actor information received from
the BNG Blaster as partner information (in sync, collecting and
distributing). The actor system, key and port of each interface and
an overridden partner key can be changed at runtime with the JSON
control file, which is read before each PDU:

  {"<interface>": {"system": "02:00:00:00:00:01", "key": 1, "port": 1,
                   "partner_key": null}}

Each LACPDU received from the BNG Blaster is written as JSON line to
the log file.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import json
import select
import socket
import struct
import time

ETH_P_SLOW = 0x8809
LACP_MAC = bytes.fromhex("0180c2000002")
STATE = 0x01 | 0x04 | 0x08 | 0x10 | 0x20  # active, aggregation, sync, collecting, distributing


def tlv(tlv_type, system_priority, system, key, port_priority, port, state):
    return struct.pack("!BBH6sHHHB3x", tlv_type, 20, system_priority, system, key, port_priority, port, state)


def decode(data):
    """Decode actor and partner TLV of a LACPDU (after the Ethernet header)."""
    def info(buf):
        prio, system, key, port_prio, port, state = struct.unpack("!H6sHHHB", buf[2:17])
        return {"system_priority": prio, "system": system.hex(":"), "key": key,
                "port_priority": port_prio, "port": port, "state": state}
    return info(data[2:22]), info(data[22:42])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("control")
    parser.add_argument("log")
    parser.add_argument("interfaces", nargs="+")
    args = parser.parse_args()

    log = open(args.log, "a", buffering=1)
    socks = {}
    for ifname in args.interfaces:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_SLOW))
        sock.bind((ifname, 0))
        socks[ifname] = sock
    partner = {ifname: None for ifname in args.interfaces}
    start = time.time()
    next_tx = 0
    while True:
        now = time.time()
        if now >= next_tx:
            next_tx = now + 1
            control = json.load(open(args.control))
            for ifname, sock in socks.items():
                c = control.get(ifname)
                if not c:
                    continue
                mac = bytes.fromhex(open("/sys/class/net/%s/address" % ifname).read().strip().replace(":", ""))
                p = partner[ifname] or {"system_priority": 0, "system": "00:00:00:00:00:00", "key": 0,
                                        "port_priority": 0, "port": 0, "state": 0}
                partner_key = c.get("partner_key")
                pdu = struct.pack("!BB", 1, 1)
                pdu += tlv(1, 32768, bytes.fromhex(c["system"].replace(":", "")), c["key"], 32768, c["port"], STATE)
                pdu += tlv(2, p["system_priority"], bytes.fromhex(p["system"].replace(":", "")),
                           p["key"] if partner_key is None else partner_key, p["port_priority"], p["port"],
                           p["state"] & 0x3f)
                pdu += struct.pack("!BBH12x", 3, 16, 0) + b"\x00\x00" + bytes(50)
                sock.send(LACP_MAC + mac + struct.pack("!H", ETH_P_SLOW) + pdu)
        ready, _, _ = select.select(list(socks.values()), [], [], 0.05)
        for sock in ready:
            ifname = [i for i, s in socks.items() if s is sock][0]
            data, addr = sock.recvfrom(2048)
            if addr[2] == socket.PACKET_OUTGOING or len(data) < 14 + 42 or data[14] != 1:
                continue
            actor, partner_info = decode(data[14:])
            partner[ifname] = actor
            log.write(json.dumps({"time": round(time.time() - start, 3), "interface": ifname,
                                  "actor": actor, "partner": partner_info}) + "\n")


if __name__ == "__main__":
    main()
