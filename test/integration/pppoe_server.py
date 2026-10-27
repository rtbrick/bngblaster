#!/usr/bin/env python3
"""
Minimal PPPoE server (scapy) for one session, used to test the LCP MRU
negotiation of the BNG Blaster PPPoE client against servers which behave
correctly or not with respect to PPP-Max-Payload (RFC 4638).

The server answers PADI and PADR (optionally echoing PPP-Max-Payload),
sends an LCP configure-request with the given MRU and acks every
configure-request of the client, optionally after a configure-nak with
the given MRU. A configure-nak of the client is followed by a new
configure-request with the suggested MRU, as required by RFC 1661.

Every LCP packet received from the client is written as JSON line
(code, identifier, MRU) to the log file.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import json
import socket

from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.ppp import (PPP, PPP_LCP_Auth_Protocol_Option, PPP_LCP_Configure,
                              PPP_LCP_Magic_Number_Option, PPP_LCP_MRU_Option, PPPoE,
                              PPPoED, PPPoED_Tags, PPPoETag)

ETH_P_ALL = 0x0003
PADI, PADO, PADR, PADS = 0x09, 0x07, 0x19, 0x65
CONF_REQUEST, CONF_ACK, CONF_NAK = 1, 2, 3
TAG_SERVICE_NAME, TAG_AC_NAME, TAG_HOST_UNIQ, TAG_MAX_PAYLOAD = 0x0101, 0x0102, 0x0103, 0x0120
SESSION_ID = 1
MAC = "02:00:00:00:01:01"


def lcp_mru(lcp):
    for option in lcp.options:
        if isinstance(option, PPP_LCP_MRU_Option):
            return option.max_recv_unit
    return None


class Server:
    def __init__(self, args):
        self.args = args
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((args.interface, 0))
        self.mru = args.mru
        self.identifier = 0
        self.nak_sent = False
        self.log = open(args.log, "w", buffering=1)

    def send(self, request, payload):
        reply = Ether(dst=request[Ether].src, src=MAC)
        if Dot1Q in request:
            reply /= Dot1Q(vlan=request[Dot1Q].vlan)
            if Dot1Q in request[Dot1Q].payload:
                reply /= Dot1Q(vlan=request[Dot1Q].payload[Dot1Q].vlan)
        self.sock.send(bytes(reply / payload))

    def discovery(self, packet, code):
        tags = [PPPoETag(tag_type=TAG_AC_NAME, tag_value=b"pppoe-server")]
        for tag in packet[PPPoED_Tags].tag_list:
            if tag.tag_type in (TAG_SERVICE_NAME, TAG_HOST_UNIQ):
                tags.append(tag)
            elif tag.tag_type == TAG_MAX_PAYLOAD and self.args.echo_max_payload:
                tags.append(tag)
        session_id = SESSION_ID if code == PADS else 0
        self.send(packet, PPPoED(code=code, sessionid=session_id) / PPPoED_Tags(tag_list=tags))

    def lcp(self, request, lcp):
        self.send(request, PPPoE(sessionid=SESSION_ID) / PPP(proto=0xc021) / lcp)

    def conf_request(self, packet):
        self.identifier += 1
        self.lcp(packet, PPP_LCP_Configure(code=CONF_REQUEST, id=self.identifier, options=[
            PPP_LCP_MRU_Option(max_recv_unit=self.mru),
            PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc023),
            PPP_LCP_Magic_Number_Option(magic_number=0x11223344)]))

    def receive(self, packet):
        if PPPoED in packet:
            if packet[PPPoED].code == PADI:
                self.discovery(packet, PADO)
            elif packet[PPPoED].code == PADR:
                self.discovery(packet, PADS)
                self.conf_request(packet)
            return
        if PPPoE not in packet or packet[PPP].proto != 0xc021:
            return
        lcp = packet[PPP].payload
        if not isinstance(lcp, PPP_LCP_Configure):
            return
        mru = lcp_mru(lcp)
        self.log.write(json.dumps({"code": lcp.code, "id": lcp.id, "mru": mru}) + "\n")
        if lcp.code == CONF_REQUEST:
            if self.args.nak_mru and not self.nak_sent:
                self.nak_sent = True
                self.lcp(packet, PPP_LCP_Configure(code=CONF_NAK, id=lcp.id, options=[
                    PPP_LCP_MRU_Option(max_recv_unit=self.args.nak_mru)]))
            else:
                self.lcp(packet, PPP_LCP_Configure(code=CONF_ACK, id=lcp.id, options=lcp.options))
        elif lcp.code == CONF_NAK and lcp.id == self.identifier:
            if mru:
                self.mru = mru
            self.conf_request(packet)

    def run(self):
        while True:
            data = self.sock.recv(65535)
            packet = Ether(data)
            if packet.src == MAC:
                continue
            self.receive(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--interface", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--mru", type=int, default=1492, help="MRU of LCP configure-request")
    parser.add_argument("--echo-max-payload", action="store_true",
                        help="echo PPP-Max-Payload in PADO and PADS")
    parser.add_argument("--nak-mru", type=int, default=0,
                        help="nak first configure-request of the client with this MRU")
    Server(parser.parse_args()).run()


if __name__ == "__main__":
    main()
