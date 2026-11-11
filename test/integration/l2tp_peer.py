#!/usr/bin/env python3
"""
Scripted L2TPv2 peer (RFC 2661) for protocol tests of the BNG Blaster
LNS (lac mode) and LAC (lns mode), using the LAC of l2tp_proxy_lac.py.

lac scenarios (against the BNG Blaster LNS):
  private-group-id  ICCN with a 6 byte Private Group ID
  sequencing        ICCN with Sequencing Required
  no-session-id     ICRQ without Assigned Session ID
  no-iccn           ICRQ answered with ICRP, but no ICCN
  hidden-avp        SCCRQ with a hidden Vendor Name (--secret)
  lcp               LCP configure-request, echo-request with own magic,
                    terminate-request (echo reply magic, terminate-ack, CDN)
  binary-strings    host name, called number and ARI with invalid UTF-8
  sccrq-retry       the SCCRQ is retransmitted before the SCCRP is acknowledged
  bogus-nr          ZLB acknowledging messages never sent (Nr far ahead), then ICRQ
  control-host-name host name with newline and terminal escape sequence

lns scenarios (against the BNG Blaster LAC):
  no-tunnel-id      SCCRP without Assigned Tunnel ID
  no-session-id     ICRP without Assigned Session ID
  rws0              SCCRP with Receive Window Size 0
  rws65535          SCCRP with Receive Window Size 65535
  no-icrp           ICRQ acknowledged with ZLB, but no ICRP
  silent            SCCRP, then no further message (no acknowledgement)

The result is printed as JSON.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import hashlib
import json
import socket
import struct
import time

from l2tp_proxy_lac import (AVP_ASSIGNED_SESSION_ID, AVP_ASSIGNED_TUNNEL_ID, AVP_CALL_SERIAL_NUMBER,
                            AVP_FRAMING_CAPABILITIES, AVP_FRAMING_TYPE, AVP_HOST_NAME, AVP_MESSAGE_TYPE,
                            AVP_PROTOCOL_VERSION, AVP_RESULT_CODE, AVP_TX_CONNECT_SPEED, BROADBAND_FORUM,
                            ACCESS_LINE_ARI, CDN, ICCN, ICRP, ICRQ, L2TP_PORT, LOCAL_SESSION_ID,
                            LOCAL_TUNNEL_ID, SCCCN, SCCRP, SCCRQ, STOPCCN, Lac, avp, avp16, avp32,
                            decode_avps)

AVP_VENDOR_NAME = 8
AVP_CHALLENGE = 11
AVP_RANDOM_VECTOR = 36
AVP_CALLED_NUMBER = 21
AVP_PRIVATE_GROUP_ID = 37
AVP_RECEIVE_WINDOW_SIZE = 10
AVP_SEQUENCING_REQUIRED = 39
CONTROL_HOST_NAME = b"LAC\nFAKE LOG LINE\x1b[2J"
LCP = 0xc021
CONF_REQ, CONF_ACK, TERM_REQ, TERM_ACK, ECHO_REQ, ECHO_REP = 1, 2, 5, 6, 9, 10
MAGIC = 0x11223344


def hidden_avp(avp_type, value, secret, random_vector):
    """Mandatory AVP with value hidden as in RFC 2661 section 4.3."""
    data = struct.pack("!H", len(value)) + value
    out, block = b"", hashlib.md5(struct.pack("!H", avp_type) + secret + random_vector).digest()
    for i in range(0, len(data), 16):
        chunk = bytes(a ^ b for a, b in zip(data[i:i + 16], block))
        out += chunk
        block = hashlib.md5(secret + chunk).digest()
    return struct.pack("!HHH", 0x8000 | 0x4000 | (6 + len(out)), 0, avp_type) + out


def message_type(avps):
    return struct.unpack("!H", avps[AVP_MESSAGE_TYPE])[0] if AVP_MESSAGE_TYPE in avps else None


def result_code(avps):
    return struct.unpack("!H", avps[AVP_RESULT_CODE][:2])[0] if AVP_RESULT_CODE in avps else None


class Peer(Lac):

    def zlb(self, nr=None):
        header = struct.pack("!HHHHHH", 0xc802, 12, self.peer_tunnel_id, 0, self.ns,
                             self.nr if nr is None else nr)
        self.sock.sendto(header, self.server)

    def send_ppp(self, protocol, code, identifier, data=b""):
        payload = b"\xff\x03" + struct.pack("!HBBH", protocol, code, identifier, 4 + len(data)) + data
        header = struct.pack("!HHH", 0x0002, self.peer_tunnel_id, self.peer_session_id)
        self.sock.sendto(header + payload, self.server)

    def collect(self, duration):
        """Return control messages and PPP packets received within duration."""
        control, ppp = [], []
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                is_control, payload = self.recv(max(0.01, deadline - time.time()))
            except socket.timeout:
                break
            if is_control and payload:
                control.append({"type": message_type(payload), "result-code": result_code(payload),
                                "session-id": self.last_session_id})
            elif not is_control and len(payload) >= 4:
                protocol, code, identifier = struct.unpack("!HBB", payload[:4])
                entry = {"protocol": protocol, "code": code, "id": identifier}
                if protocol == LCP and code in (ECHO_REQ, ECHO_REP) and len(payload) >= 10:
                    entry["magic"] = struct.unpack("!I", payload[6:10])[0]
                if protocol == LCP and code == CONF_REQ:
                    opts, data = {}, payload[6:]
                    while len(data) >= 2 and data[1] >= 2:
                        opts[data[0]] = data[2:data[1]]
                        data = data[data[1]:]
                    if 5 in opts:
                        entry["magic"] = struct.unpack("!I", opts[5])[0]
                ppp.append(entry)
        return control, ppp

    def tunnel(self, host_name=b"SCRIPT-LAC", retry=False, extra=b""):
        sccrq = (avp16(AVP_MESSAGE_TYPE, SCCRQ) + avp16(AVP_PROTOCOL_VERSION, 0x0100) +
                 avp(AVP_HOST_NAME, host_name) + avp32(AVP_FRAMING_CAPABILITIES, 3) +
                 avp16(AVP_ASSIGNED_TUNNEL_ID, LOCAL_TUNNEL_ID) + extra)
        self.send_ctrl(0, sccrq)
        if retry:
            # Retransmission with the same Ns before the SCCRP is acknowledged.
            self.ns = 0
            time.sleep(0.2)
            self.send_ctrl(0, sccrq)
        avps = self.wait_ctrl(SCCRP)
        self.peer_tunnel_id = struct.unpack("!H", avps[AVP_ASSIGNED_TUNNEL_ID])[0]
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, SCCCN))

    def call(self, iccn_avps=b"", icrq_avps=None):
        if icrq_avps is None:
            icrq_avps = avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID)
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, ICRQ) + icrq_avps + avp32(AVP_CALL_SERIAL_NUMBER, 1))
        avps = self.wait_ctrl(ICRP)
        self.peer_session_id = struct.unpack("!H", avps[AVP_ASSIGNED_SESSION_ID])[0]
        self.send_ctrl(self.peer_session_id, avp16(AVP_MESSAGE_TYPE, ICCN) +
                       avp32(AVP_TX_CONNECT_SPEED, 100000000) + avp32(AVP_FRAMING_TYPE, 1) + iccn_avps)


def scenario_lac(args):
    peer = Peer(args.local, args.server)
    result = {}
    if args.scenario == "hidden-avp":
        random_vector = b"0123456789abcdef"
        peer.tunnel(extra=avp(AVP_CHALLENGE, b"challenge-012345") + avp(AVP_RANDOM_VECTOR, random_vector) +
                    hidden_avp(AVP_VENDOR_NAME, b"hidden-vendor", args.secret.encode(), random_vector))
        result["control"] = [{"type": SCCRP, "result-code": None, "session-id": 0}]
        return result
    if args.scenario == "control-host-name":
        peer.tunnel(host_name=CONTROL_HOST_NAME)
        result["control"], _ = peer.collect(args.duration)
        return result
    if args.scenario == "binary-strings":
        peer.tunnel(host_name=b"LAC-\xff\xfe")
        peer.call(avp(AVP_CALLED_NUMBER, b"\xc3\x28") +
                  avp(ACCESS_LINE_ARI, b"ari-\xff", mandatory=False, vendor=BROADBAND_FORUM))
        result["control"], _ = peer.collect(args.duration)
        return result
    peer.tunnel(retry=args.scenario == "sccrq-retry")
    if args.scenario == "sccrq-retry":
        result["control"], _ = peer.collect(args.duration)
        return result
    if args.scenario == "bogus-nr":
        peer.zlb(nr=1000)
        peer.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, ICRQ) + avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID) +
                       avp32(AVP_CALL_SERIAL_NUMBER, 1))
        result["control"], _ = peer.collect(args.duration)
        return result
    if args.scenario == "no-session-id":
        peer.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, ICRQ) + avp32(AVP_CALL_SERIAL_NUMBER, 1))
        result["control"], _ = peer.collect(args.duration)
        return result
    if args.scenario == "no-iccn":
        peer.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, ICRQ) + avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID) +
                       avp32(AVP_CALL_SERIAL_NUMBER, 1))
        peer.wait_ctrl(ICRP)
        # Acknowledge the ICRP with a ZLB, which does not consume an Ns.
        peer.sock.sendto(struct.pack("!HHHHHH", 0xc802, 12, peer.peer_tunnel_id, 0, peer.ns, peer.nr),
                         peer.server)
        result["control"], _ = peer.collect(args.duration)
        result["control"].insert(0, {"type": ICRP, "result-code": None, "session-id": 0})
        return result
    if args.scenario == "private-group-id":
        peer.call(avp(AVP_PRIVATE_GROUP_ID, b"group6"))
    elif args.scenario == "sequencing":
        peer.call(avp(AVP_SEQUENCING_REQUIRED, b""))
    elif args.scenario == "lcp":
        peer.call()
        time.sleep(0.2)
        peer.send_ppp(LCP, CONF_REQ, 1, bytes([5, 6]) + struct.pack("!I", MAGIC))
        time.sleep(0.5)
        peer.send_ppp(LCP, ECHO_REQ, 2, struct.pack("!I", MAGIC))
        time.sleep(0.5)
        peer.send_ppp(LCP, TERM_REQ, 3)
    result["control"], result["ppp"] = peer.collect(args.duration)
    return result


class Lns:
    """Answers SCCRQ and ICRQ of the BNG Blaster LAC."""

    def __init__(self, local):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((local, L2TP_PORT))
        self.lac = Lac.__new__(Lac)
        self.lac.sock = self.sock
        self.lac.ns = 0
        self.lac.nr = 0
        self.lac.peer_tunnel_id = 0

    def zlb(self):
        header = struct.pack("!HHHHHH", 0xc802, 12, self.lac.peer_tunnel_id, 0,
                             self.lac.ns, self.lac.nr)
        self.sock.sendto(header, self.lac.server)

    def run(self, scenario, duration):
        received = []
        silent = False
        start = time.time()
        deadline = time.time() + duration
        while time.time() < deadline:
            self.sock.settimeout(max(0.01, deadline - time.time()))
            try:
                data, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                break
            self.lac.server = peer
            flags = struct.unpack("!H", data[:2])[0]
            if not flags & 0x8000:
                continue
            ns = struct.unpack("!H", data[8:10])[0]
            avps = decode_avps(data[12:])
            if not avps:
                continue
            self.lac.nr = (ns + 1) & 0xffff
            mtype = message_type(avps)
            received.append({"type": mtype, "result-code": result_code(avps),
                             "time": round(time.time() - start, 3)})
            if silent:
                continue
            if mtype == SCCRQ:
                self.lac.peer_tunnel_id = struct.unpack("!H", avps[AVP_ASSIGNED_TUNNEL_ID])[0]
                reply = avp16(AVP_MESSAGE_TYPE, SCCRP) + avp16(AVP_PROTOCOL_VERSION, 0x0100) + \
                    avp(AVP_HOST_NAME, b"SCRIPT-LNS") + avp32(AVP_FRAMING_CAPABILITIES, 3)
                if scenario != "no-tunnel-id":
                    reply += avp16(AVP_ASSIGNED_TUNNEL_ID, LOCAL_TUNNEL_ID)
                if scenario == "rws0":
                    reply += avp16(AVP_RECEIVE_WINDOW_SIZE, 0)
                elif scenario == "rws65535":
                    reply += avp16(AVP_RECEIVE_WINDOW_SIZE, 65535)
                self.lac.send_ctrl(0, reply)
                silent = scenario == "silent"
            elif mtype == ICRQ and scenario == "no-icrp":
                self.zlb()
            elif mtype == ICRQ:
                reply = avp16(AVP_MESSAGE_TYPE, ICRP)
                if scenario != "no-session-id":
                    reply += avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID)
                session_id = struct.unpack("!H", avps[AVP_ASSIGNED_SESSION_ID])[0]
                self.lac.send_ctrl(session_id, reply)
            elif mtype in (STOPCCN, CDN):
                # Acknowledge with ZLB.
                self.zlb()
        return {"control": received}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["lac", "lns"])
    parser.add_argument("scenario")
    parser.add_argument("--local", required=True)
    parser.add_argument("--server", default="")
    parser.add_argument("--duration", type=float, default=3)
    parser.add_argument("--secret", default="")
    args = parser.parse_args()
    if args.mode == "lac":
        result = scenario_lac(args)
    else:
        result = Lns(args.local).run(args.scenario, args.duration)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
