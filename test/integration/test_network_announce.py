"""
BNG Blaster gratuitous ARP and unsolicited NA on network interfaces

The BNG Blaster announces the primary and all secondary addresses
(here stream network addresses) of a network interface, which must
override stale neighbor entries of the Linux peer pointing to an old MAC.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import time

from scapy.all import ARP, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6, rdpcap

from helpers import BngBlaster, kernel_address, wait_until

OLD_MAC = "02:00:00:00:00:99"
SECONDARIES = 40  # more than one chunk of 32 announcements
BURST = 3


def addresses():
    ipv4 = ["192.0.2.10"] + ["192.0.2.%d" % (100 + i) for i in range(SECONDARIES)]
    ipv6 = ["2001:db8::10"] + ["2001:db8::%x" % (0x100 + i) for i in range(SECONDARIES)]
    return ipv4, ipv6


def config(ifname, **announce):
    ipv4, ipv6 = addresses()
    network = {
        "interface": ifname,
        "address": "192.0.2.10/24",
        "gateway": "192.0.2.1",
        "address-ipv6": "2001:db8::10/64",
        "gateway-ipv6": "2001:db8::1"
    }
    network.update(announce)
    # Network addresses of (unused) session streams are added as secondary addresses.
    streams = [{"name": "s%d" % i, "stream-group-id": 1, "type": "ipv4", "direction": "downstream",
                "network-ipv4-address": ipv4[i + 1]} for i in range(SECONDARIES)]
    streams += [{"name": "s6-%d" % i, "stream-group-id": 1, "type": "ipv6", "direction": "downstream",
                 "network-ipv6-address": ipv6[i + 1]} for i in range(SECONDARIES)]
    return {
        "interfaces": {
            "links": [{"interface": ifname}],
            "network": [network]
        },
        "streams": streams
    }


def setup_peer(topology):
    kernel_address(topology.b, topology.if_b, "192.0.2.1/24", "2001:db8::1/64")
    ipv4, ipv6 = addresses()
    for address in ipv4 + ipv6:
        topology.b.exec(["ip", "neigh", "replace", address, "lladdr", OLD_MAC,
                         "dev", topology.if_b, "nud", "stale"])
    return topology.a.exec(["cat", "/sys/class/net/%s/address" % topology.if_a]).strip()


def neighbors(topology):
    entries = json.loads(topology.b.exec(["ip", "-j", "neigh", "show", "dev", topology.if_b]))
    return {e["dst"]: e.get("lladdr") for e in entries}


def network_interface(instance):
    return instance.ctrl("network-interfaces")["network-interfaces"][0]


def counters(instance):
    interface = network_interface(instance)
    return interface["tx-garp"], interface["tx-unsolicited-na"]


def test_announce(topology, processes, tmp_path):
    mac = setup_peer(topology)
    ipv4, ipv6 = addresses()
    count = len(ipv4)

    instance = BngBlaster(topology.a, tmp_path, "bbl")
    processes.append(instance)
    instance.start(config(topology.if_a, **{"gratuitous-arp": True, "unsolicited-na": True}))

    wait_until(lambda: all(neighbors(topology).get(a) == mac for a in ipv4 + ipv6), 10,
               message="neighbor entries overridden")
    wait_until(lambda: counters(instance) == (BURST * count, BURST * count), 10,
               message="initial announcements")
    time.sleep(2)
    assert counters(instance) == (BURST * count, BURST * count)

    # Restart announcements for all network interfaces.
    assert instance.ctrl("network-announce")["code"] == 200
    wait_until(lambda: counters(instance) == (2 * BURST * count, 2 * BURST * count), 10,
               message="announcements triggered by network-announce")
    assert instance.ctrl("network-announce", interface="unknown")["code"] == 404

    assert instance.terminate() == 0
    report = instance.report()["report"]["network-interfaces"][0]
    assert report["tx-garp-packets"] == 2 * BURST * count
    assert report["tx-unsolicited-na-packets"] == 2 * BURST * count

    garp = {}
    na = {}
    for packet in rdpcap(instance.path("pcap")):
        if ARP in packet and packet[ARP].op == 1 and packet[ARP].psrc == packet[ARP].pdst:
            assert packet.dst == "ff:ff:ff:ff:ff:ff"
            assert packet[ARP].hwsrc == mac
            assert packet[ARP].hwdst == "00:00:00:00:00:00"
            garp[packet[ARP].psrc] = garp.get(packet[ARP].psrc, 0) + 1
        elif ICMPv6ND_NA in packet and packet[IPv6].dst == "ff02::1":
            assert packet.dst == "33:33:00:00:00:01"
            assert packet[IPv6].hlim == 255
            assert packet[IPv6].src == packet[ICMPv6ND_NA].tgt
            assert (packet[ICMPv6ND_NA].R, packet[ICMPv6ND_NA].S, packet[ICMPv6ND_NA].O) == (0, 0, 1)
            assert packet[ICMPv6NDOptDstLLAddr].lladdr == mac
            na[packet[ICMPv6ND_NA].tgt] = na.get(packet[ICMPv6ND_NA].tgt, 0) + 1
    assert garp == {a: 2 * BURST for a in ipv4}
    assert na == {a: 2 * BURST for a in ipv6}


def test_announce_interval(topology, processes, tmp_path):
    setup_peer(topology)
    count = len(addresses()[0])

    instance = BngBlaster(topology.a, tmp_path, "bbl")
    processes.append(instance)
    instance.start(config(topology.if_a, **{"gratuitous-arp": True, "unsolicited-na": True,
                                            "announce-interval": 2}))
    wait_until(lambda: counters(instance) == (BURST * count, BURST * count), 10,
               message="initial announcements")
    wait_until(lambda: counters(instance) == ((BURST + 2) * count, (BURST + 2) * count), 10,
               message="periodic announcements")
    assert instance.terminate() == 0


def test_announce_disabled(topology, processes, tmp_path):
    setup_peer(topology)
    ipv4, ipv6 = addresses()

    instance = BngBlaster(topology.a, tmp_path, "bbl")
    processes.append(instance)
    instance.start(config(topology.if_a))
    time.sleep(3)
    assert counters(instance) == (0, 0)
    # Without announcements the stale entries of secondary addresses remain.
    entries = neighbors(topology)
    assert all(entries.get(a) == OLD_MAC for a in ipv4[1:] + ipv6[1:])
    assert instance.ctrl("network-announce")["code"] == 200
    time.sleep(1)
    assert counters(instance) == (0, 0)
    assert instance.terminate() == 0
