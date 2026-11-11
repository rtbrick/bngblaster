#!/usr/bin/env python3
"""
Scripted IPoE peer (scapy) for access protocol tests of the BNG Blaster:
DHCPv4 and DHCPv6 server, router advertisements and IGMP querier.

Received DHCP, DHCPv6 and IGMP packets are written as JSON lines to the
log file. The peer runs on the (VLAN) interface given, the kernel of the
namespace answers ARP and ND for the gateway addresses.

scenarios:
  dhcp-rebind        DHCPv4 server (lease 30s, T1 3s, T2 6s) with host and
                     domain name, which ignores unicast renew requests and
                     answers broadcast rebind requests
  dhcpv6-long-duid   DHCPv6 server with a 100 byte server DUID, Request must
                     carry it, periodic RA
  dhcpv6-release-ra  DHCPv6 server which ignores Release, first RA is sent
                     --ra-delay seconds after the first Reply
  ra                 one RA to all nodes after --ra-delay seconds
  igmp               IGMP log only
  igmp-query         IGMPv3 general query (max resp 2s) after --query-delay
                     seconds, IGMPv2 general query 4 seconds later

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import argparse
import json
import socket
import time

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import (DHCP6_Advertise, DHCP6_Release, DHCP6_Reply, DHCP6_Request, DHCP6_Solicit,
                                DHCP6OptClientId, DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6OptServerId)
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import (ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, IPv6)
from scapy.layers.l2 import Ether
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mq, IGMPv3mr
from scapy.packet import Raw

ETH_P_ALL = 0x0003
SERVER4 = "10.0.0.1"
SERVER6_LL = "fe80::1"
PREFIX6 = "fc00:1::"
LEASE_ADDRESS = "10.0.0.%d"


class Peer:

    def __init__(self, args):
        self.args = args
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.sock.bind((args.iface, 0))
        self.sock.settimeout(0.1)
        self.mac = open("/sys/class/net/%s/address" % args.iface).read().strip()
        self.log = open(args.log, "a", buffering=1)
        self.start = time.time()
        self.leases = {}
        self.duid = b"\x00\x02\x00\x00\x8a\xc3" + bytes(range(94)) if args.scenario == "dhcpv6-long-duid" \
            else b"\x00\x02\x00\x00\x8a\xc3\x01\x01"
        self.first_reply = None
        self.ra_sent = False
        self.next_ra = 0
        self.queries = []
        if args.scenario == "igmp-query":
            self.queries = [(self.start + args.query_delay, 3), (self.start + args.query_delay + 4, 2)]

    def write(self, **entry):
        entry["time"] = round(time.time() - self.start, 3)
        self.log.write(json.dumps(entry) + "\n")

    def send(self, pkt):
        self.sock.send(bytes(pkt))

    # DHCPv4

    def dhcp(self, pkt):
        options = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
        mtype = options.get("message-type")
        ciaddr = pkt[BOOTP].ciaddr
        dst = pkt[IP].dst
        self.write(proto="dhcp", type=mtype, xid=pkt[BOOTP].xid, ciaddr=ciaddr, dst=dst)
        mac = pkt[Ether].src
        address = self.leases.setdefault(mac, LEASE_ADDRESS % (10 + len(self.leases)))
        if mtype == 1:
            reply = "offer"
        elif mtype == 3:
            if ciaddr != "0.0.0.0" and dst != "255.255.255.255":
                return  # ignore renew
            reply = "ack"
        else:
            return
        self.send(Ether(src=self.mac, dst=mac) /
                  IP(src=SERVER4, dst="255.255.255.255") / UDP(sport=67, dport=68) /
                  BOOTP(op=2, xid=pkt[BOOTP].xid, yiaddr=address, siaddr=SERVER4, chaddr=pkt[BOOTP].chaddr,
                        flags=pkt[BOOTP].flags) /
                  DHCP(options=[("message-type", reply), ("server_id", SERVER4), ("lease_time", 30),
                                ("renewal_time", 3), ("rebinding_time", 6), ("subnet_mask", "255.255.255.0"),
                                ("router", SERVER4), ("hostname", b"bbl-host"), ("domain", b"bbl.test"), "end"]))

    # DHCPv6

    def dhcpv6(self, pkt):
        msg = pkt[UDP].payload
        client = msg[DHCP6OptClientId] if DHCP6OptClientId in msg else None
        server = msg[DHCP6OptServerId] if DHCP6OptServerId in msg else None
        server_ok = server is not None and bytes(server.duid) == self.duid
        self.write(proto="dhcpv6", type=msg.msgtype, xid=msg.trid, server_id=server is not None,
                   server_id_ok=server_ok)
        if isinstance(msg, DHCP6_Solicit):
            reply = DHCP6_Advertise(trid=msg.trid)
        elif isinstance(msg, DHCP6_Request):
            if not server_ok:
                return
            reply = DHCP6_Reply(trid=msg.trid)
        elif isinstance(msg, DHCP6_Release):
            if self.args.scenario == "dhcpv6-release-ra":
                return
            reply = DHCP6_Reply(trid=msg.trid)
        else:
            reply = DHCP6_Reply(trid=msg.trid)
        reply /= DHCP6OptServerId(duid=Raw(self.duid))
        if client is not None:
            reply /= DHCP6OptClientId(duid=client.duid)
        if DHCP6OptIA_NA in msg:
            reply /= DHCP6OptIA_NA(iaid=msg[DHCP6OptIA_NA].iaid, T1=300, T2=600,
                                   ianaopts=[DHCP6OptIAAddress(addr=PREFIX6 + "%x" % (0x10 + msg.trid % 200),
                                                               preflft=900, validlft=1800)])
        self.send(Ether(src=self.mac, dst=pkt[Ether].src) /
                  IPv6(src=SERVER6_LL, dst=pkt[IPv6].src) / UDP(sport=547, dport=546) / reply)
        if isinstance(reply, DHCP6_Reply) and self.first_reply is None:
            self.first_reply = time.time()

    def ra(self):
        self.send(Ether(src=self.mac, dst="33:33:00:00:00:01") /
                  IPv6(src=SERVER6_LL, dst="ff02::1") /
                  ICMPv6ND_RA(M=1, O=1, routerlifetime=1800) /
                  ICMPv6NDOptSrcLLAddr(lladdr=self.mac) /
                  ICMPv6NDOptPrefixInfo(prefix=PREFIX6, prefixlen=64, L=1, A=1))
        self.write(proto="ra")

    # IGMP

    def igmp(self, pkt):
        data = bytes(pkt[IP].payload)
        mtype = data[0]
        entry = {"proto": "igmp", "type": mtype, "dst": pkt[IP].dst, "src": pkt[IP].src}
        if mtype == 0x22:
            report = IGMPv3(data)
            entry["records"] = [{"type": r.rtype, "group": r.maddr} for r in report[IGMPv3mr].records]
        else:
            entry["group"] = socket.inet_ntoa(data[4:8])
        self.write(**entry)

    def query(self, version):
        if version == 3:
            payload = IGMPv3(type=0x11, mrcode=20) / IGMPv3mq(gaddr="0.0.0.0", qrv=2, qqic=125)
        else:
            payload = IGMP(type=0x11, mrcode=10, gaddr="0.0.0.0")
        self.send(Ether(src=self.mac, dst="01:00:5e:00:00:01") /
                  IP(src=SERVER4, dst="224.0.0.1", ttl=1, options=[b"\x94\x04\x00\x00"]) / payload)
        self.write(proto="query", version=version)

    def timers(self):
        now = time.time()
        scenario = self.args.scenario
        if scenario == "dhcpv6-long-duid" and now >= self.next_ra:
            self.next_ra = now + 1
            self.ra()
        elif scenario == "dhcpv6-release-ra" and not self.ra_sent and self.first_reply and \
                now >= self.first_reply + self.args.ra_delay:
            self.ra_sent = True
            self.ra()
        elif scenario == "ra" and not self.ra_sent and now >= self.start + self.args.ra_delay:
            self.ra_sent = True
            self.ra()
        while self.queries and now >= self.queries[0][0]:
            self.query(self.queries.pop(0)[1])

    def run(self):
        while True:
            self.timers()
            try:
                data = self.sock.recv(65535)
            except socket.timeout:
                continue
            pkt = Ether(data)
            if pkt.src == self.mac:
                continue
            if IP in pkt and UDP in pkt and pkt[UDP].dport == 67 and DHCP in pkt:
                self.dhcp(pkt)
            elif IPv6 in pkt and UDP in pkt and pkt[UDP].dport == 547:
                self.dhcpv6(pkt)
            elif IP in pkt and pkt[IP].proto == 2:
                self.igmp(pkt)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("iface")
    parser.add_argument("log")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--ra-delay", type=float, default=2)
    parser.add_argument("--query-delay", type=float, default=2)
    Peer(parser.parse_args()).run()


if __name__ == "__main__":
    main()
