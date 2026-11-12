"""
BNG Blaster IO, network interface and LAG behavior

Namespace A runs the BNG Blaster, namespace B the Linux kernel, scapy
helpers or the scripted LACP partner lacp_peer.py.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

import helpers
from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30
BBL4, PEER4 = "192.0.2.10", "192.0.2.1"
BBL6, PEER6 = "fc00::10", "fc00::1"
LACP_PEER = str(Path(__file__).parent / "lacp_peer.py")


def network(ifname, **extra):
    return dict({"interface": ifname, "address": BBL4 + "/24", "gateway": PEER4,
                 "address-ipv6": BBL6 + "/64", "gateway-ipv6": PEER6}, **extra)


def start(topology, processes, tmp_path, config, logging=("info",)):
    instance = BngBlaster(topology.a, tmp_path, "bbl").start(config, logging=logging)
    processes.append(instance)
    return instance


def ping(ns, address, count=3, extra=()):
    out = helpers.run(ns.cmd(["ping", "-n", "-c", str(count), "-i", "0.2", "-W", "1"] + list(extra) + [address]),
                      check=False)
    for part in out.split(","):
        if "received" in part:
            return int(part.split()[0]), out
    return 0, out


def mac(ns, ifname):
    return helpers.run(ns.cmd(["cat", "/sys/class/net/%s/address" % ifname])).strip()


def scapy(ns, script, *args, timeout=30):
    return helpers.run(ns.cmd([sys.executable, "-c", script] + [str(a) for a in args]), timeout=timeout)


@pytest.mark.parametrize("rx_threads", [0, 1])
def test_raw_vlan(topology, processes, tmp_path, rx_threads):
    """io-mode raw restores the VLAN tag stripped by the kernel."""
    vlan_if = topology.if_b + ".10"
    topology.b.exec(["ip", "link", "add", "link", topology.if_b, "name", vlan_if, "type", "vlan", "id", "10"])
    topology.b.exec(["ip", "link", "set", vlan_if, "up"])
    helpers.kernel_address(topology.b, vlan_if, PEER4 + "/24")
    link = {"interface": topology.if_a, "io-mode": "raw"}
    if rx_threads:
        link["rx-threads"] = rx_threads
    instance = start(topology, processes, tmp_path, {
        "interfaces": {"links": [link],
                       "network": [{"interface": topology.if_a, "address": BBL4 + "/24", "gateway": PEER4,
                                    "vlan": 10}]}})
    received, out = ping(topology.b, BBL4)
    assert received == 3, out
    assert instance.terminate(EXIT_TIMEOUT) == 0


VLAN_FLOOD = """
import sys
from scapy.all import Ether, Dot1Q, IP, UDP, Raw, sendp
p = Ether(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:99") / Dot1Q(vlan=10) / \\
    IP(src="192.0.2.99", dst="192.0.2.98") / UDP(sport=1, dport=2) / Raw(b"x" * 100)
sendp(p, iface=sys.argv[1], count=int(sys.argv[2]), verbose=False)
"""


def test_vlan_rx_bytes_rx_queue_full(topology, processes, tmp_path):
    """packet_mmap RX thread: a VLAN frame retried while the queue towards
    the main thread is full is counted once with the stripped tag."""
    instance = start(topology, processes, tmp_path, {
        "interfaces": {"links": [{"interface": topology.if_a, "io-mode": "packet_mmap", "rx-threads": 1,
                                  "io-slots-rx": 32, "rx-interval": 500}],
                       "network": [{"interface": topology.if_a, "address": BBL4 + "/24", "gateway": PEER4,
                                    "vlan": 10}]}})
    scapy(topology.b, VLAN_FLOOD, topology.if_b, 200)
    time.sleep(2)
    link = [i for i in instance.ctrl("interfaces")["interfaces"] if i["name"] == topology.if_a][0]
    # Frames are dropped by the kernel while the RX thread waits.
    assert link["rx-packets"] > 32
    # 146 byte frames plus a few ARP requests.
    assert link["rx-bytes"] <= link["rx-packets"] * 146, link
    assert instance.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.parametrize("link", [
    {"io-mode": "raw", "tx-threads": 1},
    {"io-mode": "packet_mmap"},
    {"io-mode": "packet_mmap", "tx-threads": 1},
], ids=["raw-tx-thread", "packet_mmap", "packet_mmap-tx-thread"])
def test_oversized_control_packet(topology, processes, tmp_path, link):
    """A control packet above the kernel MTU (ICMP client with 2500 bytes and
    network mtu 4000) is dropped, further packets are sent."""
    helpers.kernel_address(topology.b, topology.if_b, PEER4 + "/24")
    instance = start(topology, processes, tmp_path, {
        "interfaces": {"links": [dict({"interface": topology.if_a}, **link)],
                       "network": [{"interface": topology.if_a, "address": BBL4 + "/24", "gateway": PEER4,
                                    "mtu": 4000}]},
        "icmp-client": [{"network-interface": topology.if_a, "destination-address": PEER4,
                         "size": 2500, "interval": 0.2, "count": 3}]})
    time.sleep(2)
    received, out = ping(topology.b, BBL4)
    assert received == 3, out
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_icmpv6_echo_destination(topology, processes, tmp_path):
    """ICMPv6 echo requests are only answered for local destinations, a
    request to all nodes with a unicast source (RFC 4443 section 4.2)."""
    helpers.kernel_address(topology.b, topology.if_b, PEER4 + "/24", PEER6 + "/64")
    instance = start(topology, processes, tmp_path, {"interfaces": {"network": [network(topology.if_a)]}})
    received, out = ping(topology.b, BBL6)
    assert received == 3, out
    out = helpers.run(topology.b.cmd(["ping", "-n", "-c", "2", "-i", "0.5", "-W", "1",
                                      "ff02::1%" + topology.if_b]), check=False)
    assert "from " + BBL6 in out, out
    topology.b.exec(["ip", "-6", "neigh", "add", "fc00::99", "lladdr", mac(topology.a, topology.if_a),
                     "dev", topology.if_b])
    received, out = ping(topology.b, "fc00::99", count=2)
    assert received == 0, out
    assert instance.terminate(EXIT_TIMEOUT) == 0


DAD_SCRIPT = """
import sys
from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, sendp, AsyncSniffer
import time
iface, target, src, hlim = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
sniffer = AsyncSniffer(iface=iface, lfilter=lambda p: ICMPv6ND_NA in p)
sniffer.start()
time.sleep(0.5)
sendp(Ether(dst="33:33:ff:00:00:10") / IPv6(src=src, dst="ff02::1:ff00:10", hlim=hlim) /
      ICMPv6ND_NS(tgt=target), iface=iface, verbose=False)
time.sleep(1.5)
for p in sniffer.stop():
    print(p[IPv6].dst, p[ICMPv6ND_NA].S, p[ICMPv6ND_NA].O)
"""


@pytest.mark.full
def test_dad_ns(topology, processes, tmp_path):
    """A DAD NS (source ::) is answered with NA to all nodes without the
    solicited flag, NS with a hop limit other than 255 are ignored
    (RFC 4861 sections 7.1.1 and 7.2.4)."""
    instance = start(topology, processes, tmp_path, {"interfaces": {"network": [network(topology.if_a)]}})
    out = scapy(topology.b, DAD_SCRIPT, topology.if_b, BBL6, "::", 255)
    assert out.split() == ["ff02::1", "0", "1"], out
    out = scapy(topology.b, DAD_SCRIPT, topology.if_b, BBL6, "fe80::99", 64)
    assert out.strip() == "", out
    assert instance.terminate(EXIT_TIMEOUT) == 0


COUNT_SCRIPT = """
import socket, sys, time
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sock.bind((sys.argv[1], 0))
sock.settimeout(0.2)
dst = bytes.fromhex(sys.argv[2].replace(":", ""))
count, deadline = 0, time.time() + 2
while time.time() < deadline:
    try:
        data = sock.recv(2048)
    except socket.timeout:
        continue
    if data[:6] == dst and data[23] == 17:
        count += 1
print(count)
"""


def test_gateway_mac_change(topology, processes, tmp_path):
    """A changed MAC address of the gateway is learned from ARP and the
    streams are sent to the new MAC address."""
    helpers.kernel_address(topology.b, topology.if_b, PEER4 + "/24")
    instance = start(topology, processes, tmp_path, {
        "interfaces": {"network": [{"interface": topology.if_a, "address": BBL4 + "/24", "gateway": PEER4}]},
        "streams": [{"name": "S1", "type": "ipv4", "direction": "downstream", "pps": 20,
                     "network-interface": topology.if_a, "destination-ipv4-address": PEER4}]})
    wait_until(lambda: int(scapy(topology.b, COUNT_SCRIPT, topology.if_b, mac(topology.b, topology.if_b))) > 0,
               10, message="stream to gateway")
    new_mac = "02:00:00:00:99:99"
    topology.b.exec(["ip", "link", "set", "dev", topology.if_b, "address", new_mac])
    topology.b.exec(["ip", "neigh", "flush", "dev", topology.if_b])
    ping(topology.b, BBL4, count=1)
    wait_until(lambda: int(scapy(topology.b, COUNT_SCRIPT, topology.if_b, new_mac)) > 0, 10,
               message="stream to new gateway MAC")
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_tun_link(topology, processes, tmp_path):
    """A link without link-layer address (tun, getifaddrs entry without
    address) does not crash the BNG Blaster."""
    topology.a.exec(["ip", "tuntap", "add", "dev", "bbltun0", "mode", "tun"])
    topology.a.exec(["ip", "link", "set", "bbltun0", "up"])
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    processes.append(instance)
    try:
        instance.start({"interfaces": {"network": [{"interface": "bbltun0", "address": BBL4 + "/24",
                                                    "gateway": PEER4}]}})
    except RuntimeError:
        assert instance.proc.returncode > 0, instance.proc.returncode
        return
    assert instance.terminate(EXIT_TIMEOUT) == 0


def veth(ns_a, if_a, ns_b, if_b, index=None):
    cmd = ["ip", "link", "add", if_a]
    if index:
        cmd += ["index", str(index)]
    cmd += ["type", "veth", "peer", "name", if_b]
    if index:
        cmd += ["index", str(index + 1)]
    helpers.run(cmd)
    for ns, ifname in ((ns_a, if_a), (ns_b, if_b)):
        helpers.run(["ip", "link", "set", ifname, "netns", ns.name])
        ns.exec(["sysctl", "-qw", "net.ipv6.conf.%s.disable_ipv6=1" % ifname])
        ns.exec(["ip", "link", "set", ifname, "up"])


def test_fanout_group_collision(topology, processes, tmp_path):
    """RX threads of interfaces whose kernel ifindex is equal in the lower
    16 bits (4465 and 70001) use different fanout groups."""
    veth(topology.a, "bblfanA", topology.b, "bblfanB", index=4465)
    veth(topology.a, "bblfanC", topology.b, "bblfanD", index=70001)
    helpers.kernel_address(topology.b, "bblfanB", "192.0.2.1/24")
    helpers.kernel_address(topology.b, "bblfanD", "198.51.100.1/24")
    instance = start(topology, processes, tmp_path, {
        "interfaces": {
            "links": [{"interface": "bblfanA", "rx-threads": 2}, {"interface": "bblfanC", "rx-threads": 2}],
            "network": [{"interface": "bblfanA", "address": "192.0.2.10/24", "gateway": "192.0.2.1"},
                        {"interface": "bblfanC", "address": "198.51.100.10/24", "gateway": "198.51.100.1"}]}})
    for address in ("192.0.2.10", "198.51.100.10"):
        received, out = ping(topology.b, address)
        assert received == 3, out
    assert instance.terminate(EXIT_TIMEOUT) == 0


# UDP packets with 400 source ports, spread over the RX threads (fanout hash).
UDP_SCRIPT = """
import socket, sys
for port in range(1000, 1400):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"x" * 32, (sys.argv[1], port))
    s.close()
"""


def test_lag_member_rx_threads(topology, processes, tmp_path):
    """lag-info packets-rx of a member sums all RX threads."""
    helpers.kernel_address(topology.b, topology.if_b, PEER4 + "/24")
    instance = start(topology, processes, tmp_path, {
        "interfaces": {
            "lag": [{"interface": "lag1", "lacp": False}],
            "links": [{"interface": topology.if_a, "lag-interface": "lag1", "rx-threads": 2}],
            "network": [{"interface": "lag1", "address": BBL4 + "/24", "gateway": PEER4}]}})
    ping(topology.b, BBL4, count=1)
    scapy(topology.b, UDP_SCRIPT, BBL4)
    time.sleep(1)
    member = instance.ctrl("lag-info")["lag-info"][0]["members"][0]
    link = [i for i in instance.ctrl("interfaces")["interfaces"] if i["name"] == topology.if_a][0]
    assert member["packets-rx"] == link["rx-packets"] >= 400, (member, link)
    assert instance.terminate(EXIT_TIMEOUT) == 0


class Lacp:

    def __init__(self, topology, processes, tmp_path, interfaces):
        self.topology = topology
        self.control = tmp_path / "lacp.json"
        self.log = tmp_path / "lacp.log"
        self.config = {}
        for i, ifname in enumerate(interfaces):
            self.config[ifname] = {"system": "02:00:00:00:00:01", "key": 1, "port": i + 1, "partner_key": None}
        self.write()
        proc = subprocess.Popen(topology.b.cmd([sys.executable, LACP_PEER, str(self.control), str(self.log)] +
                                               list(interfaces)))
        processes.append(type("Proc", (), {"stop": proc.kill})())

    def write(self):
        tmp = self.control.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.config))
        tmp.rename(self.control)

    def pdus(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]


def lag_members(instance):
    return {m["interface"]: m for lag in instance.ctrl("lag-info")["lag-info"] for m in lag["members"]}


@pytest.mark.full
def test_lacp_partner_changes(topology, processes, tmp_path):
    """A changed partner key is applied (update_Selected) and stale partner
    information about the BNG Blaster is answered with a LACPDU right away
    (update_NTT, IEEE 802.1AX-2014 6.4.9)."""
    lacp = Lacp(topology, processes, tmp_path, [topology.if_b])
    instance = start(topology, processes, tmp_path, {
        "interfaces": {
            "lag": [{"interface": "lag1", "lacp": True, "lacp-timeout-short": False}],
            "links": [{"interface": topology.if_a, "lag-interface": "lag1"}],
            "network": [{"interface": "lag1", "address": BBL4 + "/24", "gateway": PEER4}]}},
        logging=("info", "lag"))
    wait_until(lambda: lag_members(instance)[topology.if_a]["state"] == "Up", 15, message="member up")
    lacp.config[topology.if_b]["key"] = 2
    lacp.write()
    wait_until(lambda: lag_members(instance)[topology.if_a]["lacp"]["partner-key"] == 2, 5,
               message="partner key 2")
    time.sleep(3)
    sent = time.time()
    count = len(lacp.pdus())
    lacp.config[topology.if_b]["partner_key"] = 999
    lacp.write()
    wait_until(lambda: len(lacp.pdus()) > count, 6, message="LACPDU after stale partner information")
    assert time.time() - sent < 6
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_lacp_different_partner_systems(topology, processes, tmp_path):
    """Members connected to different partner systems do not aggregate."""
    veth(topology.a, "bbllag2a", topology.b, "bbllag2b")
    lacp = Lacp(topology, processes, tmp_path, [topology.if_b, "bbllag2b"])
    lacp.config["bbllag2b"]["system"] = "02:00:00:00:00:02"
    lacp.write()
    instance = start(topology, processes, tmp_path, {
        "interfaces": {
            "lag": [{"interface": "lag1", "lacp": True, "lacp-timeout-short": False}],
            "links": [{"interface": topology.if_a, "lag-interface": "lag1"},
                      {"interface": "bbllag2a", "lag-interface": "lag1"}],
            "network": [{"interface": "lag1", "address": BBL4 + "/24", "gateway": PEER4}]}},
        logging=("info", "lag"))
    wait_until(lambda: [m["state"] for m in lag_members(instance).values()].count("Up") == 1, 15,
               message="one member up")
    time.sleep(3)
    states = sorted(m["state"] for m in lag_members(instance).values())
    assert states == ["Standby", "Up"], lag_members(instance)
    assert instance.terminate(EXIT_TIMEOUT) == 0


def two_ends(local_veth, link, length=200, vlan=None, mtu=None, qinq=False):
    """One instance on both ends of a local veth pair with a stream in
    each direction."""
    network = []
    streams = []
    for i, (ifname, peer) in enumerate(((local_veth.if1, 2), (local_veth.if2, 1))):
        n = {"interface": ifname, "address": "10.0.0.%d/24" % (i + 1), "gateway": "10.0.0.%d" % peer}
        if vlan:
            n["vlan"] = vlan
        if qinq:
            n.update({"qinq": True, "inner-vlan": 20})
        if mtu:
            n["mtu"] = mtu
        network.append(n)
        streams.append({"name": "S%d" % (i + 1), "type": "ipv4", "direction": "downstream", "pps": 200,
                        "length": length, "network-interface": ifname + (":%d" % vlan if vlan else ""),
                        "destination-ipv4-address": "10.0.0.%d" % peer})
    return {"interfaces": {"links": [dict({"interface": i}, **link) for i in (local_veth.if1, local_veth.if2)],
                           "network": network},
            "traffic": {"autostart": True},
            "streams": streams}


def stream_info(instance, flow_id):
    return instance.ctrl("stream-info", **{"flow-id": flow_id})["stream-info"]


def report_interfaces(instance):
    return {i["name"]: i for i in instance.report()["report"]["interfaces"]}


@pytest.mark.parametrize("io_mode", ["raw", "packet_mmap"])
def test_rx_threads_ignore_outgoing(local_veth, processes, tmp_path, io_mode):
    """RX threads (fanout group) do not receive the packets sent by the
    instance itself on this interface with qdisc-bypass false."""
    instance = BngBlaster(local_veth.ns, tmp_path).start(
        two_ends(local_veth, {"io-mode": io_mode, "rx-threads": 1, "qdisc-bypass": False}))
    processes.append(instance)
    wait_until(lambda: all(stream_info(instance, f)["rx-packets"] >= 400 for f in (1, 2)), 20,
               message="stream packets received")
    for f in (1, 2):
        info = stream_info(instance, f)
        assert info["rx-packets"] <= info["tx-packets"], info
        assert info["rx-wrong-order"] == 0, info
    assert instance.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.parametrize("tx_threads", [0, 1])
@pytest.mark.parametrize("length, vlan, qinq, sent", [
    (1500, None, False, True),   # 1514 byte = MTU + 14
    (1501, None, False, False),  # 1515 byte
    (1500, 10, False, True),     # 1518 byte = MTU + 18 with 0x8100 tag
    (1501, 10, False, False),    # 1519 byte
    (1492, 10, True, True),      # 1514 byte with 0x88a8 and 0x8100 tag
    (1493, 10, True, False),     # 1515 byte
], ids=["untagged-max", "untagged-long", "vlan-max", "vlan-long", "qinq-max", "qinq-long"])
def test_packet_mmap_tx_max_len(local_veth, processes, tmp_path, tx_threads, length, vlan, qinq, sent):
    """packet_mmap sends frames up to the length accepted by the kernel
    (MTU + 14, plus 4 only for 802.1Q outer tag), longer frames are
    counted as to long instead of being counted as sent and dropped."""
    link = {"io-mode": "packet_mmap"}
    if tx_threads:
        link["tx-threads"] = tx_threads
    instance = BngBlaster(local_veth.ns, tmp_path).start(two_ends(local_veth, link, length, vlan, mtu=4000, qinq=qinq))
    processes.append(instance)
    time.sleep(3)
    info = stream_info(instance, 1)
    if sent:
        assert info["tx-packets"] > 200 and info["rx-packets"] > 200, info
    else:
        assert info["tx-packets"] == 0 and info["rx-packets"] == 0, info
    assert instance.terminate(EXIT_TIMEOUT) == 0
    interface = report_interfaces(instance)[local_veth.if1]
    assert (interface["tx-to-long"] == 0) == sent, interface


@pytest.mark.full
def test_packet_mmap_tx_mtu_change(local_veth, processes, tmp_path):
    """packet_mmap follows MTU changes of the interface after start."""
    instance = BngBlaster(local_veth.ns, tmp_path).start(two_ends(local_veth, {"io-mode": "packet_mmap"}, 1400))
    processes.append(instance)
    wait_until(lambda: stream_info(instance, 1)["rx-packets"] >= 200, 10, message="stream packets received")
    local_veth.ns.exec(["ip", "link", "set", local_veth.if1, "mtu", "1300"])
    time.sleep(2)
    before = stream_info(instance, 1)
    time.sleep(1)
    after = stream_info(instance, 1)
    # Not sent (and therefore not lost) while the MTU is too small.
    assert after["tx-packets"] == before["tx-packets"], (before, after)
    local_veth.ns.exec(["ip", "link", "set", local_veth.if1, "mtu", "1500"])
    wait_until(lambda: stream_info(instance, 1)["rx-packets"] >= after["rx-packets"] + 200, 10,
               message="stream packets received after MTU increase")
    assert instance.terminate(EXIT_TIMEOUT) == 0
    interface = report_interfaces(instance)[local_veth.if1]
    assert interface["tx-to-long"] > 0, interface
