#!/usr/bin/env python3
"""
Minimal L2TPv2 LAC (RFC 2661) with proxy authentication, used to test
that the BNG Blaster LNS accepts the authentication done by the LAC.

The LAC sets up one tunnel without tunnel authentication and one
session, whose ICCN carries the Proxy Authen AVPs. It never sends any
PPP packet itself, but writes every PPP packet received from the LNS
within the given time as JSON list of (protocol, code, identifier) to
stdout.

With --icrq, the LAC sends an invalid ICRQ (call serial number of 3
bytes) and a valid ICRQ with the Broadband Forum ACI and ARI AVPs, which
it clears with a CDN, and a third ICRQ which it clears with a CDN with
session ID 0 (as before the ICRP is received), and writes the replies of
the LNS as JSON.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import json
import socket
import struct
import time

L2TP_PORT = 1701
CTRL_FLAGS = 0xc802  # T, L and S bit, version 2
T_BIT, L_BIT, S_BIT, O_BIT = 0x8000, 0x4000, 0x0800, 0x0200

SCCRQ, SCCRP, SCCCN, STOPCCN, ICRQ, ICRP, ICCN, CDN = 1, 2, 3, 4, 10, 11, 12, 14

AVP_RESULT_CODE = 1
BROADBAND_FORUM = 3561
ACCESS_LINE_ACI, ACCESS_LINE_ARI = 1, 2

AVP_MESSAGE_TYPE = 0
AVP_PROTOCOL_VERSION = 2
AVP_FRAMING_CAPABILITIES = 3
AVP_HOST_NAME = 7
AVP_ASSIGNED_TUNNEL_ID = 9
AVP_ASSIGNED_SESSION_ID = 14
AVP_CALL_SERIAL_NUMBER = 15
AVP_FRAMING_TYPE = 19
AVP_TX_CONNECT_SPEED = 24
AVP_PROXY_AUTHEN_TYPE = 29
AVP_PROXY_AUTHEN_NAME = 30
AVP_PROXY_AUTHEN_CHALLENGE = 31
AVP_PROXY_AUTHEN_ID = 32
AVP_PROXY_AUTHEN_RESPONSE = 33

PROXY_AUTH_TYPE = {"chap": 2, "pap": 3}

LOCAL_TUNNEL_ID = 100
LOCAL_SESSION_ID = 200


def avp(avp_type, value, mandatory=True, vendor=0):
    return struct.pack("!HHH", (0x8000 if mandatory else 0) | (6 + len(value)),
                       vendor, avp_type) + value


def avp16(avp_type, value):
    return avp(avp_type, struct.pack("!H", value))


def avp32(avp_type, value):
    return avp(avp_type, struct.pack("!I", value))


def decode_avps(data):
    avps = {}
    while len(data) >= 6:
        flags_len, _, avp_type = struct.unpack("!HHH", data[:6])
        length = flags_len & 0x03ff
        if length < 6:
            break
        avps[avp_type] = data[6:length]
        data = data[length:]
    return avps


class Lac:
    def __init__(self, local, server):
        self.server = (server, L2TP_PORT)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((local, L2TP_PORT))
        self.ns = 0
        self.nr = 0
        self.peer_tunnel_id = 0
        self.peer_session_id = 0

    def send_ctrl(self, session_id, avps):
        length = 12 + len(avps)
        header = struct.pack("!HHHHHH", CTRL_FLAGS, length, self.peer_tunnel_id,
                             session_id, self.ns, self.nr)
        self.sock.sendto(header + avps, self.server)
        self.ns = (self.ns + 1) & 0xffff

    def recv(self, timeout):
        """Return (control, payload) with the AVPs of control messages
        or the PPP packet of data messages."""
        self.sock.settimeout(timeout)
        data, _ = self.sock.recvfrom(2048)
        flags = struct.unpack("!H", data[:2])[0]
        offset = 2
        if flags & L_BIT:
            offset += 2
        self.last_session_id = struct.unpack("!H", data[offset+2:offset+4])[0]
        offset += 4  # tunnel and session id
        if flags & T_BIT:
            ns = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 4
            avps = decode_avps(data[offset:])
            if avps:
                self.nr = (ns + 1) & 0xffff
            return True, avps
        if flags & S_BIT:
            offset += 4
        if flags & O_BIT:
            offset += 2 + struct.unpack("!H", data[offset:offset+2])[0]
        payload = data[offset:]
        if payload[:2] == b"\xff\x03":
            payload = payload[2:]
        return False, payload

    def wait_ctrl(self, message_type, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            control, avps = self.recv(deadline - time.time())
            if control and AVP_MESSAGE_TYPE in avps and \
               struct.unpack("!H", avps[AVP_MESSAGE_TYPE])[0] == message_type:
                return avps
        raise TimeoutError("L2TP message type %d" % message_type)

    def connect_tunnel(self):
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, SCCRQ) +
                       avp16(AVP_PROTOCOL_VERSION, 0x0100) +
                       avp(AVP_HOST_NAME, b"PROXY-LAC") +
                       avp32(AVP_FRAMING_CAPABILITIES, 3) +
                       avp16(AVP_ASSIGNED_TUNNEL_ID, LOCAL_TUNNEL_ID))
        avps = self.wait_ctrl(SCCRP)
        self.peer_tunnel_id = struct.unpack("!H", avps[AVP_ASSIGNED_TUNNEL_ID])[0]
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, SCCCN))

    def icrq(self):
        """Invalid ICRQ answered with CDN, valid ICRQ with ACI and ARI
        answered with ICRP and cleared by the LAC."""
        self.connect_tunnel()
        result = {}
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, ICRQ) +
                       avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID + 1) +
                       avp(AVP_CALL_SERIAL_NUMBER, b"\x00\x00\x01"))
        try:
            avps = self.wait_ctrl(CDN)
            result["cdn-session-id"] = self.last_session_id
            result["cdn-result-code"] = struct.unpack("!H", avps[AVP_RESULT_CODE][:2])[0]
        except TimeoutError:
            result["cdn-session-id"] = None
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, ICRQ) +
                       avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID + 2) +
                       avp32(AVP_CALL_SERIAL_NUMBER, 2) +
                       avp(ACCESS_LINE_ACI, b"circuit-1", mandatory=False, vendor=BROADBAND_FORUM) +
                       avp(ACCESS_LINE_ARI, b"remote-1", mandatory=False, vendor=BROADBAND_FORUM))
        avps = self.wait_ctrl(ICRP)
        result["icrp"] = True
        session_id = struct.unpack("!H", avps[AVP_ASSIGNED_SESSION_ID])[0]
        self.send_ctrl(session_id, avp16(AVP_MESSAGE_TYPE, CDN) +
                       avp(AVP_RESULT_CODE, struct.pack("!H", 3)) +
                       avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID + 2))
        # The call is cleared before the LNS session ID is known, the CDN
        # has session ID 0 and the Assigned Session ID of the LAC.
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, ICRQ) +
                       avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID + 3) +
                       avp32(AVP_CALL_SERIAL_NUMBER, 3))
        self.wait_ctrl(ICRP)
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, CDN) +
                       avp(AVP_RESULT_CODE, struct.pack("!H", 3)) +
                       avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID + 3))
        time.sleep(1)
        # Close the tunnel, which acknowledges all messages of the LNS.
        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, STOPCCN) +
                       avp(AVP_RESULT_CODE, struct.pack("!H", 1)) +
                       avp16(AVP_ASSIGNED_TUNNEL_ID, LOCAL_TUNNEL_ID))
        time.sleep(1)
        return result

    def connect(self, auth, auth_id):
        self.connect_tunnel()

        self.send_ctrl(0, avp16(AVP_MESSAGE_TYPE, ICRQ) +
                       avp16(AVP_ASSIGNED_SESSION_ID, LOCAL_SESSION_ID) +
                       avp32(AVP_CALL_SERIAL_NUMBER, 1))
        avps = self.wait_ctrl(ICRP)
        self.peer_session_id = struct.unpack("!H", avps[AVP_ASSIGNED_SESSION_ID])[0]

        iccn = (avp16(AVP_MESSAGE_TYPE, ICCN) +
                avp32(AVP_TX_CONNECT_SPEED, 100000000) +
                avp32(AVP_FRAMING_TYPE, 1) +
                avp16(AVP_PROXY_AUTHEN_TYPE, PROXY_AUTH_TYPE[auth]) +
                avp(AVP_PROXY_AUTHEN_NAME, b"user@proxy"))
        if auth == "chap":
            iccn += avp(AVP_PROXY_AUTHEN_CHALLENGE, bytes(range(16)))
            iccn += avp(AVP_PROXY_AUTHEN_RESPONSE, bytes(16))
        else:
            iccn += avp(AVP_PROXY_AUTHEN_RESPONSE, b"secret")
        if auth_id is not None:
            iccn += avp16(AVP_PROXY_AUTHEN_ID, auth_id)
        self.send_ctrl(self.peer_session_id, iccn)

    def ppp_received(self, duration):
        """Collect PPP packets (protocol, code, identifier) received
        within duration seconds."""
        packets = []
        deadline = time.time() + duration
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                control, payload = self.recv(remaining)
            except socket.timeout:
                break
            if not control and len(payload) >= 4:
                packets.append(struct.unpack("!HBB", payload[:4]))
        return packets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--auth", choices=sorted(PROXY_AUTH_TYPE), default="pap")
    parser.add_argument("--auth-id", type=int, help="Proxy Authen ID (AVP omitted if not set)")
    parser.add_argument("--duration", type=float, default=2)
    parser.add_argument("--icrq", action="store_true", help="invalid and valid ICRQ (see above)")
    args = parser.parse_args()

    lac = Lac(args.local, args.server)
    if args.icrq:
        print(json.dumps(lac.icrq()))
        return
    lac.connect(args.auth, args.auth_id)
    print(json.dumps(lac.ppp_received(args.duration)))


if __name__ == "__main__":
    main()
