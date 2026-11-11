#!/usr/bin/env python3
"""
Scripted BGP peer for protocol tests, run in the peer namespace.

accept:    listen, accept the connection of the BNG Blaster, read its OPEN,
           send the steps and report all received messages and how the
           connection ended (fin, rst or timeout).
connect:   connect to the BNG Blaster and report if the connection was
           established, refused or timed out.
collision: accept the connection of the BNG Blaster, then connect as
           well. The OPEN is sent first on
           the connection expected to lose the collision resolution, which
           is reported, then the session is established on the other one.

Steps (JSON list):
  {"open": {"version": 4, "as": 65001, "hold": 90, "id": "10.0.0.2", "marker": "ff"}}
  {"keepalive": {"length": 19}}
  {"update": {}}             empty UPDATE (End-of-RIB)
  {"type": 9}                message with this type and no body
  {"sleep": 1}
  {"keepalive_for": 3}       KEEPALIVE every 0.5 seconds for 3 seconds

The result is printed as JSON.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import subprocess
import json
import select
import socket
import struct
import time

MSG_OPEN, MSG_UPDATE, MSG_NOTIFICATION, MSG_KEEPALIVE = 1, 2, 3, 4


def message(msg_type, body=b"", marker=b"\xff" * 16, length=None):
    if length is None:
        length = 19 + len(body)
    return marker + struct.pack("!HB", length, msg_type) + body


def open_message(version=4, asn=65001, hold=90, router_id="10.0.0.2", marker="ff"):
    caps = bytes([1, 4]) + struct.pack("!HBB", 1, 0, 1) + bytes([65, 4]) + struct.pack("!I", asn)
    params = bytes([2, len(caps)]) + caps
    body = struct.pack("!BHH4sB", version, asn if asn < 65536 else 23456, hold,
                       socket.inet_aton(router_id), len(params)) + params
    return message(MSG_OPEN, body, marker=bytes.fromhex(marker) * 16)


class Connection:

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""
        self.messages = []
        self.end = None

    def send(self, data):
        self.sock.sendall(data)

    def poll(self, timeout):
        """Receive for up to timeout seconds, return False once closed."""
        deadline = time.monotonic() + timeout
        while self.end is None:
            left = deadline - time.monotonic()
            if left <= 0:
                return True
            readable, _, _ = select.select([self.sock], [], [], left)
            if not readable:
                continue
            try:
                data = self.sock.recv(65535)
            except ConnectionResetError:
                self.end = "rst"
                break
            if not data:
                self.end = "fin"
                break
            self.buf += data
            self.parse()
        return False

    def parse(self):
        while len(self.buf) >= 19:
            length, msg_type = struct.unpack("!HB", self.buf[16:19])
            if len(self.buf) < length:
                return
            msg = {"type": msg_type}
            if self.buf[:16] != b"\xff" * 16:
                msg["marker"] = "invalid"
            if length < 19:
                self.messages.append({"type": msg_type, "length": length})
                self.buf = b""
                return
            if msg_type == MSG_NOTIFICATION and length >= 21:
                msg["code"], msg["subcode"] = self.buf[19], self.buf[20]
            self.messages.append(msg)
            self.buf = self.buf[length:]

    def wait_message(self, msg_type, timeout):
        deadline = time.monotonic() + timeout
        while not any(m["type"] == msg_type for m in self.messages):
            if not self.poll(min(0.2, max(0, deadline - time.monotonic()))) and self.end:
                return False
            if time.monotonic() > deadline:
                return False
        return True

    def run(self, steps):
        for step in steps:
            if self.end:
                break
            if "open" in step:
                self.send(open_message(**step["open"]))
            elif "keepalive" in step:
                length = step["keepalive"].get("length", 19)
                self.send(message(MSG_KEEPALIVE, b"\x00" * (length - 19)))
            elif "update" in step:
                self.send(message(MSG_UPDATE, b"\x00\x00\x00\x00"))
            elif "type" in step:
                self.send(message(step["type"]))
            elif "sleep" in step:
                self.poll(step["sleep"])
            elif "keepalive_for" in step:
                deadline = time.monotonic() + step["keepalive_for"]
                while time.monotonic() < deadline and not self.end:
                    try:
                        self.send(message(MSG_KEEPALIVE))
                    except OSError:
                        break
                    self.poll(0.5)

    def result(self):
        return {"messages": self.messages, "end": self.end or "timeout"}


def listen(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, 179))
    sock.listen(4)
    return sock


def connect(address, peer, timeout):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.bind((address, 0))
    sock.settimeout(timeout)
    sock.connect((peer, 179))
    sock.settimeout(None)
    return sock


def mode_accept(args):
    server = listen(args.local)
    server.settimeout(args.timeout)
    sock, _ = server.accept()
    conn = Connection(sock)
    if not conn.wait_message(MSG_OPEN, 10):
        return {"error": "no OPEN from BNG Blaster", **conn.result()}
    conn.messages = []
    conn.run(json.loads(args.steps))
    conn.poll(args.wait)
    return conn.result()


def mode_connect(args):
    try:
        sock = connect(args.local, args.peer, args.timeout)
    except ConnectionRefusedError:
        return {"connect": "refused"}
    except (socket.timeout, TimeoutError):
        return {"connect": "timeout"}
    conn = Connection(sock)
    conn.wait_message(MSG_OPEN, 5)
    return {"connect": "established", **conn.result()}


def mode_collision(args):
    # The BNG Blaster connects first (primary), the connection of the peer
    # is the second one (collision), as the BNG Blaster stops connecting
    # once a connection reached OpenSent.
    server = listen(args.local)
    server.settimeout(args.timeout)
    passive = Connection(server.accept()[0])
    if not passive.wait_message(MSG_OPEN, 10):
        return {"error": "no OPEN from BNG Blaster"}
    active = Connection(connect(args.local, args.peer, 5))
    for conn in (active, passive):
        if not conn.wait_message(MSG_OPEN, 10):
            return {"error": "no OPEN from BNG Blaster"}
        conn.messages = []
    # The connection initiated by the speaker with the higher BGP
    # identifier survives (RFC 4271 section 6.8).
    if args.lose == "passive":
        lose, win = passive, active
    else:
        lose, win = active, passive
    open_args = json.loads(args.steps)[0]["open"]
    lose.send(open_message(**open_args))
    lose.poll(args.wait)
    win.send(open_message(**open_args))
    win.send(message(MSG_KEEPALIVE))
    win.wait_message(MSG_KEEPALIVE, 5)
    win.poll(1)
    return {"lose": lose.result(), "win": win.result()}


def mode_collision_closing(args):
    # As collision, but the primary connection is closed by an invalid
    # OPEN (first step) before the OPEN of the collision connection
    # (second step, which would win) is sent, while the session closes.
    server = listen(args.local)
    server.settimeout(args.timeout)
    passive = Connection(server.accept()[0])
    if not passive.wait_message(MSG_OPEN, 10):
        return {"error": "no OPEN from BNG Blaster"}
    active = Connection(connect(args.local, args.peer, 5))
    if not active.wait_message(MSG_OPEN, 10):
        return {"error": "no OPEN from BNG Blaster"}
    active.messages = []
    passive.messages = []
    steps = json.loads(args.steps)
    passive.send(open_message(**steps[0]["open"]))
    passive.poll(0.5)
    try:
        active.send(open_message(**steps[1]["open"]))
        active.send(message(MSG_KEEPALIVE))
    except OSError:
        pass
    active.poll(args.wait)
    return {"collision": active.result(), "primary": passive.result()}


def mode_collision_pending(args):
    # The OPEN of the BNG Blaster on the primary connection is not acknowledged
    # (dropped by the test until --unblock is run), the collision connection
    # wins. Messages received on the primary connection afterwards are
    # returned, the unacknowledged OPEN must not be overwritten.
    server = listen(args.local)
    server.settimeout(args.timeout)
    passive = Connection(server.accept()[0])
    active = Connection(connect(args.local, args.peer, 5))
    if not active.wait_message(MSG_OPEN, 10):
        return {"error": "no OPEN from BNG Blaster"}
    active.messages = []
    active.send(open_message(**json.loads(args.steps)[0]["open"]))
    active.send(message(MSG_KEEPALIVE))
    if not active.wait_message(MSG_KEEPALIVE, 5):
        return {"error": "collision connection not promoted", "collision": active.result()}
    subprocess.run(args.unblock, shell=True, check=True)
    passive.poll(args.wait)
    return {"collision": active.result(), "primary": passive.result()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["accept", "connect", "collision", "collision-closing",
                                         "collision-pending"])
    parser.add_argument("--unblock", default="true")
    parser.add_argument("--local", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--steps", default="[]")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--wait", type=float, default=5, help="receive time after the steps")
    parser.add_argument("--lose", choices=["active", "passive"], default="passive")
    args = parser.parse_args()
    result = {"accept": mode_accept, "connect": mode_connect, "collision": mode_collision,
              "collision-closing": mode_collision_closing,
              "collision-pending": mode_collision_pending}[args.mode](args)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
