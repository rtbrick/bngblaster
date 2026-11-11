#!/usr/bin/env python3
"""
Scripted PPPoE server for one session, used to test the PPP negotiation
of the BNG Blaster PPPoE client with server behavior which can not be
configured in a real server (rejected options, ignored or terminated NCPs,
renegotiation, invalid offers).

The server answers PADI and PADR, negotiates LCP (with PAP, CHAP or no
authentication), IPCP (address 10.0.0.100 assigned with configure-nak)
and IP6CP, answers echo requests and runs timed actions once the session
is established. Every packet received from the client is written as JSON
line to the log file.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import json
import select
import socket
import struct
import time

ETH_P_ALL = 0x0003
ETH_DISCOVERY, ETH_SESSION = 0x8863, 0x8864
PADI, PADO, PADR, PADS, PADT = 0x09, 0x07, 0x19, 0x65, 0xa7
TAG_SERVICE_NAME, TAG_AC_NAME, TAG_HOST_UNIQ, TAG_AC_COOKIE = 0x0101, 0x0102, 0x0103, 0x0104
TAG_RELAY_SESSION_ID = 0x0110
RELAY_SESSION_ID = b"relay-012345"
LCP, PAP, CHAP, IPCP, IP6CP = 0xc021, 0xc023, 0xc223, 0x8021, 0x8057
PPP_IPV4 = 0x0021
CONF_REQ, CONF_ACK, CONF_NAK, CONF_REJ, TERM_REQ, TERM_ACK, CODE_REJ, PROT_REJ = 1, 2, 3, 4, 5, 6, 7, 8
ECHO_REQ, ECHO_REP, DISCARD_REQ = 9, 10, 11
LCP_MRU, LCP_AUTH, LCP_MAGIC = 1, 3, 5
IPCP_ADDRESS = 3
SESSION_ID = 1
MAC = bytes.fromhex("020000000101")
MAC_BAD = bytes.fromhex("020000000102")
BROADCAST = b"\xff" * 6
CLIENT_ADDRESS = socket.inet_aton("10.0.0.100")
SERVER_ADDRESS = socket.inet_aton("10.0.0.1")


def options(data):
    """Return list of (type, value) of PPP configuration options."""
    result = []
    while len(data) >= 2:
        kind, length = data[0], data[1]
        if length < 2 or length > len(data):
            break
        result.append((kind, data[2:length]))
        data = data[length:]
    return result


def encode_options(opts):
    return b"".join(bytes([kind, len(value) + 2]) + value for kind, value in opts)


def control(code, identifier, data=b""):
    return struct.pack("!BBH", code, identifier, 4 + len(data)) + data


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def icmp_echo_request(src, dst, identifier, sequence):
    icmp = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence) + b"bngblaster"
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + icmp


class Server:

    def __init__(self, args):
        self.args = args
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((args.interface, 0))
        self.log = open(args.log, "w", buffering=1)
        self.client = None
        self.ident = 0
        self.padi_count = 0
        self.lcp_acked = False      # own LCP request acked by the client
        self.lcp_peer_acked = False # client LCP request acked
        self.lcp_opened_at = None
        self.auth_done = False
        self.ipcp_acked = False
        self.ip6cp_acked = False
        self.ipcp_term_ignored = False
        self.ipcp_closed = False
        self.established_at = None
        self.lcp_hold_until = 0
        self.lcp_rejected = set()   # own LCP options rejected by the client
        self.ip6cp_rejected = set() # own IP6CP options rejected by the client
        self.timers = []
        self.actions = []
        for item in filter(None, args.actions.split(",")):
            delay, action = item.split(":")
            self.actions.append((float(delay), action))

    def next_id(self):
        self.ident = (self.ident + 1) % 256
        return self.ident

    def record(self, **entry):
        entry["time"] = round(time.monotonic(), 3)
        self.log.write(json.dumps(entry) + "\n")

    def send_eth(self, ethertype, payload, src=MAC):
        self.sock.send(self.client + src + struct.pack("!H", ethertype) + payload)

    def send_discovery(self, code, session_id, tags, src=MAC):
        body = b"".join(struct.pack("!HH", t, len(v)) + v for t, v in tags)
        self.send_eth(ETH_DISCOVERY, struct.pack("!BBHH", 0x11, code, session_id, len(body)) + body, src)

    def send_ppp(self, protocol, payload):
        body = struct.pack("!H", protocol) + payload
        self.send_eth(ETH_SESSION, struct.pack("!BBHH", 0x11, 0, SESSION_ID, len(body)) + body)

    # Discovery

    def discovery(self, dst, code, tags):
        names = [v.decode(errors="replace") for t, v in tags if t == TAG_SERVICE_NAME]
        self.record(kind={PADI: "padi", PADR: "padr", PADT: "padt"}.get(code, "disc-%d" % code),
                    dst=dst.hex(":"), service_names=names,
                    cookie=[v.hex() for t, v in tags if t == TAG_AC_COOKIE],
                    relay_session_id=[v.decode(errors="replace") for t, v in tags if t == TAG_RELAY_SESSION_ID])
        host_uniq = [(t, v) for t, v in tags if t == TAG_HOST_UNIQ]
        if code == PADI:
            self.padi_count += 1
            if self.args.bad_pado_first and self.padi_count == 1:
                # Offer of another AC with wrong host-uniq.
                bad = [(TAG_AC_NAME, b"bad-ac"), (TAG_SERVICE_NAME, b""),
                       (TAG_HOST_UNIQ, b"\x00" * 8), (TAG_AC_COOKIE, b"bad-cookie")]
                self.send_discovery(PADO, 0, bad, src=MAC_BAD)
                return
            offered = [(TAG_SERVICE_NAME, n.encode()) for n in self.args.service_names.split(",")] \
                if self.args.service_names else [(TAG_SERVICE_NAME, b"")]
            relay = [(TAG_RELAY_SESSION_ID, RELAY_SESSION_ID)] if self.args.relay_session_id else []
            self.send_discovery(PADO, 0, [(TAG_AC_NAME, b"ppp-peer")] + offered + host_uniq +
                                [(TAG_AC_COOKIE, b"c" * self.args.ac_cookie_len if self.args.ac_cookie_len
                                  else b"good-cookie")] + relay)
        elif code == PADR:
            requested = [(t, v) for t, v in tags if t == TAG_SERVICE_NAME][:1]
            self.send_discovery(PADS, SESSION_ID, requested + host_uniq)
            self.lcp_request()

    # LCP

    def lcp_request(self):
        opts = [(LCP_MRU, struct.pack("!H", 1492)), (LCP_MAGIC, b"\x11\x22\x33\x44")]
        if self.args.auth == "pap":
            opts.insert(1, (LCP_AUTH, struct.pack("!H", PAP)))
        elif self.args.auth == "chap":
            opts.insert(1, (LCP_AUTH, struct.pack("!HB", CHAP, 5)))
        if self.args.lcp_extra:
            # Repeated MRU options, then an unknown option after the 8th option.
            opts += [(LCP_MRU, struct.pack("!H", 1492))] * 6 + [(0x88, b"\x01\x02")]
        opts = [(k, v) for k, v in opts if k not in self.lcp_rejected]
        self.send_ppp(LCP, control(CONF_REQ, self.next_id(), encode_options(opts)))
        self.timer(2, self.lcp_retransmit)

    def lcp_retransmit(self):
        if not self.lcp_acked:
            self.lcp_request()

    def lcp(self, code, identifier, data):
        entry = {"kind": "lcp", "code": code, "id": identifier}
        if code in (CONF_REQ, CONF_REJ, CONF_NAK, CONF_ACK):
            opts = options(data)
            entry["options"] = [k for k, _ in opts]
            for kind, value in opts:
                if kind == LCP_MRU and len(value) == 2:
                    entry["mru"] = struct.unpack("!H", value)[0]
        if code == PROT_REJ and len(data) >= 2:
            entry["protocol"] = struct.unpack("!H", data[:2])[0]
        self.record(**entry)
        if code == CONF_REQ:
            if time.monotonic() < self.lcp_hold_until:
                return
            rejected = [(k, v) for k, v in options(data) if
                        (k == LCP_MRU and "mru" in self.args.lcp_reject) or
                        (k == LCP_MAGIC and "magic" in self.args.lcp_reject)]
            if rejected:
                self.send_ppp(LCP, control(CONF_REJ, identifier, encode_options(rejected)))
                return
            if self.lcp_opened_at and self.lcp_peer_acked and self.lcp_acked:
                # Client restarted LCP (opened + RCR): renegotiate.
                self.lcp_acked = self.auth_done = self.ipcp_acked = self.ip6cp_acked = False
                self.lcp_request()
            self.send_ppp(LCP, control(CONF_ACK, identifier, data))
            self.lcp_peer_acked = True
            self.lcp_check()
        elif code == CONF_ACK:
            self.lcp_acked = True
            self.lcp_check()
        elif code == CONF_REJ:
            self.lcp_rejected |= {k for k, _ in options(data)}
            self.lcp_request()
        elif code == ECHO_REQ:
            self.send_ppp(LCP, control(ECHO_REP, identifier, b"\x11\x22\x33\x44" + data[4:]))
        elif code == TERM_REQ:
            self.send_ppp(LCP, control(TERM_ACK, identifier))

    def lcp_check(self):
        if not (self.lcp_acked and self.lcp_peer_acked) or self.auth_done:
            return
        if self.lcp_opened_at is None:
            self.lcp_opened_at = time.monotonic()
        if self.args.prot_reject_ipcp_in_auth:
            self.send_ppp(LCP, control(PROT_REJ, self.next_id(), struct.pack("!H", IPCP)))
        if self.args.auth == "chap" and not self.args.chap_no_challenge:
            self.send_ppp(CHAP, control(1, self.next_id(), bytes([16]) + b"\x01" * 16 + b"ppp-peer"))
        elif self.args.auth == "none":
            self.network()

    # Authentication

    def pap(self, code, identifier, data):
        self.record(kind="pap", code=code, id=identifier)
        if code == 1:
            self.timer(self.args.pap_delay, lambda: self.pap_ack(identifier))

    def pap_ack(self, identifier):
        self.send_ppp(PAP, control(2, identifier, b"\x00"))
        self.network()

    def chap(self, code, identifier, data):
        self.record(kind="chap", code=code, id=identifier)
        if code == 2 and not self.auth_done:
            self.send_ppp(CHAP, control(3, identifier, b"ok"))
            self.network()

    # NCP

    def network(self):
        self.auth_done = True
        if self.args.ipcp == "normal" or self.args.ipcp == "nak-always":
            self.ipcp_request()
        if self.args.ip6cp == "normal":
            self.ip6cp_request()

    def ipcp_request(self):
        if not self.ipcp_acked and self.auth_done:
            # Oversized: more than 64 bytes of (repeated) address options.
            count = 12 if self.args.ipcp_oversized else 1
            self.send_ppp(IPCP, control(CONF_REQ, self.next_id(),
                                        encode_options([(IPCP_ADDRESS, SERVER_ADDRESS)] * count)))
            self.timer(2, self.ipcp_request)

    def ip6cp_request(self):
        if not self.ip6cp_acked and self.auth_done:
            opts = [(1, b"\x00" * 7 + b"\x01")]
            if self.args.ip6cp_compression:
                # IPv6-Compression-Protocol (RFC 5072 section 4.2)
                opts.append((2, b"\x00\x4f"))
            opts = [(k, v) for k, v in opts if k not in self.ip6cp_rejected]
            self.send_ppp(IP6CP, control(CONF_REQ, self.next_id(), encode_options(opts)))
            self.timer(2, self.ip6cp_request)

    def ipcp(self, code, identifier, data):
        opts = options(data)
        entry = {"kind": "ipcp", "code": code, "id": identifier}
        for kind, value in opts:
            if kind == IPCP_ADDRESS:
                entry["address"] = socket.inet_ntoa(value)
        self.record(**entry)
        if self.args.ipcp == "ignore":
            return
        if code == CONF_REQ:
            if self.ipcp_closed:
                # Reopened by the client.
                self.ipcp_closed = False
                self.ipcp_request()
            other = [(k, v) for k, v in opts if k != IPCP_ADDRESS]
            if other:
                self.send_ppp(IPCP, control(CONF_REJ, identifier, encode_options(other)))
            elif self.args.ipcp == "nak-always" or entry.get("address") != "10.0.0.100":
                self.send_ppp(IPCP, control(CONF_NAK, identifier,
                                            encode_options([(IPCP_ADDRESS, CLIENT_ADDRESS)])))
            else:
                self.send_ppp(IPCP, control(CONF_ACK, identifier, data))
                self.check_established()
        elif code == CONF_ACK:
            self.ipcp_acked = True
            self.check_established()
        elif code == TERM_REQ:
            if self.args.ipcp_ignore_first_term and not self.ipcp_term_ignored:
                self.ipcp_term_ignored = True
                return
            self.send_ppp(IPCP, control(TERM_ACK, identifier))
            self.ipcp_acked = False
            self.ipcp_closed = True

    def ip6cp(self, code, identifier, data):
        self.record(kind="ip6cp", code=code, id=identifier,
                    options=[k for k, _ in options(data)] if code in (CONF_REQ, CONF_ACK, CONF_NAK, CONF_REJ) else [])
        if self.args.ip6cp != "normal":
            return
        if code == CONF_REQ:
            self.send_ppp(IP6CP, control(CONF_ACK, identifier, data))
            self.check_established()
        elif code == CONF_ACK:
            self.ip6cp_acked = True
            self.check_established()
        elif code == CONF_REJ:
            self.ip6cp_rejected |= {k for k, _ in options(data)}
            self.ip6cp_request()
        elif code == TERM_REQ:
            self.send_ppp(IP6CP, control(TERM_ACK, identifier))

    def check_established(self):
        if self.established_at is None and (self.ipcp_acked or self.ip6cp_acked):
            self.established_at = time.monotonic()
            self.record(kind="established")
            for delay, action in self.actions:
                self.timer(delay, lambda a=action: self.action(a))

    # Actions once established

    def action(self, action):
        self.record(kind="action", action=action)
        if action == "ipcp-term":
            self.send_ppp(IPCP, control(TERM_REQ, self.next_id()))
        elif action == "ip6cp-term":
            self.send_ppp(IP6CP, control(TERM_REQ, self.next_id()))
        elif action == "ipcp-reneg":
            self.ipcp_acked = False
            self.ipcp_request()
        elif action == "lcp-term-ack":
            self.send_ppp(LCP, control(TERM_ACK, self.next_id()))
        elif action == "lcp-code-reject":
            self.send_ppp(LCP, control(CODE_REJ, self.next_id(), control(12, 1)))
        elif action == "lcp-discard":
            self.send_ppp(LCP, control(DISCARD_REQ, self.next_id(), b"\x11\x22\x33\x44"))
        elif action == "unknown-protocol":
            self.send_ppp(0x80fd, control(CONF_REQ, self.next_id(), b"\x1a\x04\x78\x00"))
        elif action == "ipcp-unknown-code":
            self.send_ppp(IPCP, control(15, self.next_id(), b"\x01\x02"))
        elif action == "icmp-echo":
            self.send_ppp(PPP_IPV4, icmp_echo_request(SERVER_ADDRESS, CLIENT_ADDRESS, 0x1234, 1))
        elif action == "lcp-hold":
            # Ignore configure-requests of the client for some time.
            self.lcp_hold_until = time.monotonic() + 3

    # Main loop

    def timer(self, delay, callback):
        self.timers.append((time.monotonic() + delay, callback))

    def receive(self, frame):
        dst, src, ethertype = frame[:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
        if src in (MAC, MAC_BAD) or ethertype not in (ETH_DISCOVERY, ETH_SESSION):
            return
        self.client = src
        code, session_id, length = frame[15], *struct.unpack("!HH", frame[16:20])
        body = frame[20:20 + length]
        if ethertype == ETH_DISCOVERY:
            tags = []
            while len(body) >= 4:
                tag, tag_len = struct.unpack("!HH", body[:4])
                tags.append((tag, body[4:4 + tag_len]))
                body = body[4 + tag_len:]
            self.discovery(dst, code, tags)
            return
        if len(body) < 6:
            return
        protocol = struct.unpack("!H", body[:2])[0]
        if protocol == PPP_IPV4:
            ip = body[2:]
            if len(ip) >= 28 and ip[9] == 1:
                self.record(kind="icmp", type=ip[20], src=socket.inet_ntoa(ip[12:16]),
                            dst=socket.inet_ntoa(ip[16:20]))
            return
        ccode, cid, clen = struct.unpack("!BBH", body[2:6])
        data = body[6:2 + clen]
        handler = {LCP: self.lcp, PAP: self.pap, CHAP: self.chap, IPCP: self.ipcp, IP6CP: self.ip6cp}.get(protocol)
        if handler:
            handler(ccode, cid, data)
        else:
            self.record(kind="protocol-%04x" % protocol, code=ccode)

    def run(self):
        while True:
            now = time.monotonic()
            due = [t for t in self.timers if t[0] <= now]
            self.timers = [t for t in self.timers if t[0] > now]
            for _, callback in due:
                callback()
            readable, _, _ = select.select([self.sock], [], [], 0.05)
            if readable:
                self.receive(self.sock.recv(9000))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("interface")
    parser.add_argument("log")
    parser.add_argument("--auth", choices=["pap", "chap", "none"], default="pap")
    parser.add_argument("--chap-no-challenge", action="store_true")
    parser.add_argument("--pap-delay", type=float, default=0)
    parser.add_argument("--prot-reject-ipcp-in-auth", action="store_true")
    parser.add_argument("--lcp-reject", default="", help="comma separated: mru, magic")
    parser.add_argument("--service-names", default="")
    parser.add_argument("--bad-pado-first", action="store_true")
    parser.add_argument("--ipcp", choices=["normal", "ignore", "nak-always"], default="normal")
    parser.add_argument("--ipcp-ignore-first-term", action="store_true")
    parser.add_argument("--ip6cp", choices=["normal", "ignore"], default="normal")
    parser.add_argument("--lcp-extra", action="store_true", help="unknown LCP option after the 8th option")
    parser.add_argument("--ip6cp-compression", action="store_true", help="IP6CP compression option")
    parser.add_argument("--ipcp-oversized", action="store_true", help="IPCP request above 64 byte options")
    parser.add_argument("--relay-session-id", action="store_true", help="PADO with Relay-Session-Id")
    parser.add_argument("--ac-cookie-len", type=int, default=0, help="PADO with AC-Cookie of this length")
    parser.add_argument("--actions", default="", help="comma separated delay:action after established")
    Server(parser.parse_args()).run()


if __name__ == "__main__":
    main()
