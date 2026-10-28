#!/usr/bin/env python3
"""
Minimal passive BGP speaker accepting many sessions, used to test
raw update transfers of many BNG Blaster sessions in parallel.

Every accepted connection is answered with OPEN and KEEPALIVE, then all
received messages are counted per local address (the BNG Blaster peer
address). The receive buffer is small and reading is paused randomly,
so that the BNG Blaster sees zero windows (receiver backpressure) as
with a busy route reflector. The hold timer of the BNG Blaster is not
enforced, so a stalled sender stays visible instead of being closed.

With --connect, the sink does not listen but connects to the BNG Blaster
addresses instead, so that sessions can only come up passively.

Counters are written as JSON to the stats file once per second.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import asyncio
import ipaddress
import json
import os
import random
import socket
import struct

MARKER = b"\xff" * 16
MSG_OPEN = 1
MSG_UPDATE = 2
MSG_NOTIFICATION = 3
MSG_KEEPALIVE = 4


def message(msg_type, body=b""):
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def open_message(asn, hold_time, router_id):
    # Capabilities: multiprotocol IPv4/IPv6 unicast and 4-octet AS
    caps = b"".join([
        bytes([1, 4]) + struct.pack("!HBB", 1, 0, 1),
        bytes([1, 4]) + struct.pack("!HBB", 2, 0, 1),
        bytes([65, 4]) + struct.pack("!I", asn),
    ])
    params = bytes([2, len(caps)]) + caps
    body = struct.pack("!BHH4sB", 4, asn if asn < 65536 else 23456, hold_time,
                       socket.inet_aton(router_id), len(params)) + params
    return message(MSG_OPEN, body)


class Sink:

    def __init__(self, args):
        self.args = args
        self.peers = {}

    def peer(self, address):
        if address not in self.peers:
            self.peers[address] = {"connections": 0, "open": 0, "update": 0,
                                   "keepalive": 0, "notification": 0, "bytes": 0}
        return self.peers[address]

    async def keepalive(self, writer):
        while True:
            await asyncio.sleep(self.args.hold_time / 3)
            writer.write(message(MSG_KEEPALIVE))

    async def handle(self, reader, writer):
        # Counted per BNG Blaster address: the local address of accepted
        # connections, the remote address of connections made with --connect.
        if self.args.connect:
            stats = self.peer(writer.get_extra_info("peername")[0])
        else:
            stats = self.peer(writer.get_extra_info("sockname")[0])
        stats["connections"] += 1
        writer.write(open_message(self.args.asn, self.args.hold_time, self.args.router_id))
        writer.write(message(MSG_KEEPALIVE))
        keepalive = asyncio.ensure_future(self.keepalive(writer))
        try:
            while True:
                header = await reader.readexactly(19)
                length, msg_type = struct.unpack("!HB", header[16:])
                await reader.readexactly(length - 19)
                stats["bytes"] += length
                if msg_type == MSG_OPEN:
                    stats["open"] += 1
                elif msg_type == MSG_UPDATE:
                    stats["update"] += 1
                    if random.random() < self.args.pause_probability:
                        await asyncio.sleep(self.args.pause)
                elif msg_type == MSG_KEEPALIVE:
                    stats["keepalive"] += 1
                elif msg_type == MSG_NOTIFICATION:
                    stats["notification"] += 1
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            keepalive.cancel()
            writer.close()

    async def write_stats(self):
        while True:
            await asyncio.sleep(1)
            tmp = self.args.stats + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.peers, f)
            os.replace(tmp, self.args.stats)

    async def connect(self, address):
        """Connect actively to a BNG Blaster address until it accepts,
        and again whenever the connection is closed."""
        while True:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.args.rcvbuf)
            sock.setblocking(False)
            try:
                await asyncio.wait_for(
                    asyncio.get_running_loop().sock_connect(sock, (address, 179)), 5)
            except (OSError, asyncio.TimeoutError):
                sock.close()
                await asyncio.sleep(1)
                continue
            reader, writer = await asyncio.open_connection(sock=sock, limit=self.args.rcvbuf)
            await self.handle(reader, writer)
            await asyncio.sleep(1)

    async def run(self):
        asyncio.ensure_future(self.write_stats())
        if self.args.connect:
            first = ipaddress.ip_address(self.args.connect[0])
            await asyncio.gather(*[self.connect(str(first + i))
                                   for i in range(int(self.args.connect[1]))])
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Inherited by accepted sockets, limits the advertised window.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.args.rcvbuf)
        sock.bind(("0.0.0.0", 179))
        server = await asyncio.start_server(self.handle, sock=sock, backlog=4096,
                                            limit=self.args.rcvbuf)
        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--asn", type=int, default=65001)
    parser.add_argument("--router-id", default="10.0.0.2")
    parser.add_argument("--hold-time", type=int, default=90)
    parser.add_argument("--rcvbuf", type=int, default=8192)
    parser.add_argument("--pause", type=float, default=0.2)
    parser.add_argument("--pause-probability", type=float, default=0.01)
    parser.add_argument("--stats", required=True)
    parser.add_argument("--connect", nargs=2, metavar=("FIRST", "COUNT"),
                        help="connect to COUNT consecutive addresses from FIRST "
                             "instead of listening")
    args = parser.parse_args()
    asyncio.run(Sink(args).run())


if __name__ == "__main__":
    main()
