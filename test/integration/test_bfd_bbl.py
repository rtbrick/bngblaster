"""
BNG Blaster BFD against another BNG Blaster instance

Two BNG Blaster instances (namespaces A and B) with static BFD sessions
(RFC 5880, single-hop RFC 5881 and multi-hop RFC 5883): IPv4/IPv6, timer
negotiation, slow start, poll sequence, authentication, AdminDown,
detection timeout, teardown, passive role, control commands, 1000
sessions and LDP sessions bound to BFD (RFC 5882). Configuration errors
are rejected on start.

BFD packets are sent and received by the BNG Blaster with packet sockets
bypassing the qdisc, which netfilter in the namespace of the instance
can't drop. Tests which need to drop BFD packets connect both instances
through a bridge in a third namespace which drops them with nftables.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import ipaddress
import time

import pytest

import helpers
from helpers import BngBlaster, Netns, wait_until

IP_A, IP_B = "10.0.0.1", "10.0.0.2"
IP6_A, IP6_B = "fc00::1", "fc00::2"
LSR_ID_A, LSR_ID_B = "10.2.3.1", "10.2.3.2"
SLOW_US = 1000000


def network(ifname, local, peer, **extra):
    return dict({"interface": ifname, "address": local[0] + "/24", "gateway": peer[0],
                 "address-ipv6": local[1] + "/64", "gateway-ipv6": peer[1]}, **extra)


def profile(profile_id=1, **values):
    return dict({"bfd-profile-id": profile_id}, **values)


def bfd_config(ifname, side, profiles=None, sessions=None, **extra):
    """Configuration of instance A or B with one network interface."""
    if side == "a":
        local, peer = (IP_A, IP6_A), (IP_B, IP6_B)
    else:
        local, peer = (IP_B, IP6_B), (IP_A, IP6_A)
    config = {"interfaces": {"network": [network(ifname, local, peer)]}}
    if profiles is not None:
        config["bfd"] = profiles
    if sessions is not None:
        config["bfd-sessions"] = sessions
    config.update(extra)
    return config


def static(ifname, side, family="ipv4", **extra):
    """Static single-hop session to the other instance."""
    session = {"network-interface": ifname}
    if family == "ipv4":
        session["peer-ipv4-address"] = IP_B if side == "a" else IP_A
    else:
        session["peer-ipv6-address"] = IP6_B if side == "a" else IP6_A
    session.update(extra)
    return session


def sessions(instance, **filters):
    response = instance.ctrl("bfd-sessions", **filters)
    assert response["code"] == 200, response
    return response["bfd-sessions"]


def session(instance, **filters):
    result = sessions(instance, **filters)
    assert len(result) == 1, result
    return result[0]


def states(instance, **filters):
    return [s["state"] for s in sessions(instance, **filters)]


def wait_states(instances, state, timeout, count=1, interval=0.2):
    wait_until(lambda: all(states(i) == [state] * count for i in instances), timeout, interval,
               message="BFD sessions %s" % state)


def negotiated(instance):
    """Up without poll sequence in progress on both sides."""
    s = session(instance)
    return s["state"] == "Up" and not s["poll"] and s["remote-state"] == "Up"


def bfd_packets(instance, src):
    """Decode the BFD control packets sent from address src (RFC 5880 4.1)
    from the PCAP of the instance, available after it terminated."""
    from scapy.all import IP, UDP, IPv6, rdpcap
    result = []
    for packet in rdpcap(instance.path("pcap")):
        if UDP not in packet or packet[UDP].dport not in (3784, 4784):
            continue
        ip = packet[IP] if IP in packet else packet[IPv6]
        if ip.src != src:
            continue
        data = bytes(packet[UDP].payload)
        bfd = {
            "ttl": ip.ttl if IP in packet else ip.hlim,
            "sport": packet[UDP].sport, "dport": packet[UDP].dport,
            "version": data[0] >> 5, "diag": data[0] & 0x1f,
            "state": data[1] >> 6, "poll": bool(data[1] & 0x20), "final": bool(data[1] & 0x10),
            "auth": bool(data[1] & 0x04), "demand": bool(data[1] & 0x02),
            "mult": data[2], "length": data[3], "size": len(data),
            "my": int.from_bytes(data[4:8], "big"), "your": int.from_bytes(data[8:12], "big"),
            "tx": int.from_bytes(data[12:16], "big"), "rx": int.from_bytes(data[16:20], "big"),
            "echo": int.from_bytes(data[20:24], "big"),
        }
        if bfd["auth"]:
            bfd["auth_type"], bfd["auth_len"], bfd["key_id"] = data[24], data[25], data[26]
        result.append(bfd)
    return result


STATE_ADMIN_DOWN, STATE_DOWN, STATE_INIT, STATE_UP = range(4)


def log(instance):
    with open(instance.path("log")) as f:
        return f.read()


@pytest.fixture
def bbl(processes, tmp_path):
    """Start an instance with BFD (and LDP) logging."""
    def start(ns, name, config, wait_started=True):
        instance = BngBlaster(ns, tmp_path, name=name)
        processes.append(instance)
        return instance.start(config, logging=("info", "bfd", "ldp"), wait_started=wait_started)
    return start


@pytest.fixture
def pair(topology, bbl):
    """Start instances A and B with the given BFD profiles and sessions."""
    def start(profiles_a, sessions_a, profiles_b=None, sessions_b=None, **extra):
        a = bbl(topology.a, "a", bfd_config(topology.if_a, "a", profiles_a, sessions_a, **extra))
        b = bbl(topology.b, "b", bfd_config(topology.if_b, "b",
                                            profiles_a if profiles_b is None else profiles_b,
                                            sessions_b, **extra))
        return a, b
    return start


@pytest.fixture
def bridged():
    """Namespaces A and B connected through a bridge in namespace M,
    where BFD packets can be dropped with nftables (drop(True))."""
    n = helpers.if_id()
    topo = type("Topology", (), {})()
    topo.a, topo.m, topo.b = Netns("%d-a" % n), Netns("%d-m" % n), Netns("%d-b" % n)
    topo.if_a, topo.if_b = "bbl%da" % n, "bbl%db" % n
    port_a, port_b = "bbl%dma" % n, "bbl%dmb" % n
    helpers.veth_pair(topo.a, topo.if_a, topo.m, port_a)
    helpers.veth_pair(topo.m, port_b, topo.b, topo.if_b)
    topo.m.exec(["ip", "link", "add", "br0", "type", "bridge"])
    for port in (port_a, port_b):
        topo.m.exec(["ip", "link", "set", port, "master", "br0"])
    topo.m.exec(["ip", "link", "set", "br0", "up"])

    def drop(enable):
        if enable:
            topo.m.exec(["nft", "add table bridge bfd; "
                         "add chain bridge bfd forward { type filter hook forward priority 0; }; "
                         "add rule bridge bfd forward udp dport { 3784, 4784 } counter drop"])
        else:
            topo.m.exec(["nft", "delete table bridge bfd"])

    def dropped():
        out = topo.m.exec(["nft", "list table bridge bfd"])
        return int(out.split("packets ")[1].split()[0])
    topo.drop, topo.dropped = drop, dropped
    yield topo
    for ns in (topo.a, topo.m, topo.b):
        ns.delete()


# Basic ---------------------------------------------------------------------

def test_bfd_ipv4_single_hop(topology, pair):
    """IPv4 single-hop session with default timers, profile and session
    given as single objects instead of lists."""
    a, b = pair(profile(1),
                dict(static(topology.if_a, "a"), name="S1", **{"bfd-profile-id": 1}),
                sessions_b=static(topology.if_b, "b"))
    wait_states([a, b], "Up", 4, interval=0.1)
    s = session(a)
    assert s["bfd-session-id"] == 1 and s["name"] == "S1"
    assert (s["network-interface"], s["local-address"], s["peer-address"]) == (topology.if_a, IP_A, IP_B)
    assert not s["multihop"] and s["min-ttl"] == 255 and not s["passive"]
    assert (s["remote-state"], s["local-diagnostic"], s["authentication-type"]) == ("Up", "none", "none")
    assert s["clients"] == ["static"] and s["admin-state"] == "enabled"
    assert s["local-discriminator"] != 0
    assert s["remote-discriminator"] == session(b)["local-discriminator"]
    assert session(b)["remote-discriminator"] == s["local-discriminator"]
    # Default 1000 ms and multiplier 3 on both sides.
    assert (s["multiplier"], s["remote-multiplier"]) == (3, 3)
    assert (s["desired-min-tx-interval-us"], s["required-min-rx-interval-us"]) == (SLOW_US, SLOW_US)
    assert (s["tx-interval-us"], s["detection-time-us"]) == (SLOW_US, 3 * SLOW_US)
    assert s["stats"]["up"] == 1 and s["stats"]["down"] == 0
    assert s["stats"]["rx-packets"] > 0 and s["stats"]["tx-packets"] > 0
    assert s["stats"]["rx-errors"] == 0 and s["stats"]["rx-auth-errors"] == 0


# Address families and multi-hop -----------------------------------------------

def mac_link_local(ns, ifname):
    """Link-local address of the BNG Blaster (MAC address without the
    universal/local bit inverted)."""
    mac = helpers.run(ns.cmd(["cat", "/sys/class/net/%s/address" % ifname])).strip().split(":")
    return str(ipaddress.ip_address("fe80::%s%s:%sff:fe%s:%s%s" % tuple(mac)))


@pytest.mark.full
@pytest.mark.parametrize("variant", ["ipv6", "ipv6-link-local", "multihop-ipv4", "multihop-ipv6"])
def test_bfd_session_types(topology, pair, variant):
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100})]
    if variant == "ipv6":
        sa = static(topology.if_a, "a", "ipv6", **{"bfd-profile-id": 1})
        sb = static(topology.if_b, "b", "ipv6", **{"bfd-profile-id": 1})
        expected = (IP6_A, IP6_B)
    elif variant == "ipv6-link-local":
        ll_a, ll_b = mac_link_local(topology.a, topology.if_a), mac_link_local(topology.b, topology.if_b)
        sa = {"network-interface": topology.if_a, "peer-ipv6-address": ll_b, "bfd-profile-id": 1}
        sb = {"network-interface": topology.if_b, "peer-ipv6-address": ll_a, "bfd-profile-id": 1}
        expected = (ll_a, ll_b)
    else:
        # Loopback addresses behind the interface addresses.
        family = variant.split("-")[1]
        if family == "ipv4":
            la, lb, key = "10.10.10.1", "10.10.10.2", "ipv4"
        else:
            la, lb, key = "fc00:10::1", "fc00:10::2", "ipv6"
        sa = {"network-interface": topology.if_a, "local-%s-address" % key: la,
              "peer-%s-address" % key: lb, "multihop": True, "bfd-profile-id": 1}
        sb = {"network-interface": topology.if_b, "local-%s-address" % key: lb,
              "peer-%s-address" % key: la, "multihop": True, "bfd-profile-id": 1}
        expected = (la, lb)
    a, b = pair(prof, [sa], sessions_b=[sb])
    wait_states([a, b], "Up", 10)
    wait_until(lambda: negotiated(a) and negotiated(b), 5, message="poll sequence completed")
    s = session(a)
    assert (s["local-address"], s["peer-address"]) == expected
    assert s["multihop"] == variant.startswith("multihop")
    # Multi-hop sessions accept TTL >= 254 by default (RFC 5883 2).
    assert s["min-ttl"] == (254 if s["multihop"] else 255)
    assert (s["tx-interval-us"], s["detection-time-us"]) == (100000, 300000)
    # Stable for some detection times.
    time.sleep(2)
    for instance in (a, b):
        s = session(instance)
        assert s["state"] == "Up" and s["stats"]["up"] == 1 and s["stats"]["down"] == 0
        assert s["stats"]["rx-errors"] == 0
        # About 2 s / 87.5 ms average interval with jitter (RFC 5880 6.8.7).
        assert s["stats"]["rx-packets"] >= 15
    discr = session(a)["local-discriminator"], session(b)["local-discriminator"]
    assert a.terminate() == 0
    # RFC 5881 4 (and RFC 5883 2): source port 49152-65535, destination
    # port 3784 (multi-hop 4784), TTL or hop limit 255.
    packets = bfd_packets(a, expected[0])
    assert packets
    for bfd in packets:
        assert 49152 <= bfd["sport"] <= 65535 and bfd["sport"] == packets[0]["sport"]
        assert bfd["dport"] == (4784 if variant.startswith("multihop") else 3784)
        assert bfd["ttl"] == 255
        assert (bfd["version"], bfd["length"], bfd["size"]) == (1, 24, 24)
        assert not (bfd["auth"] or bfd["demand"]) and bfd["echo"] == 0
        assert bfd["my"] == discr[0] and bfd["your"] in (0, discr[1])
    up = [bfd for bfd in packets if bfd["state"] == STATE_UP]
    assert up and (up[-1]["tx"], up[-1]["rx"], up[-1]["mult"]) == (100000, 100000, 3)
    # Slow start before Up.
    assert all(bfd["tx"] == SLOW_US for bfd in packets if bfd["state"] in (STATE_DOWN, STATE_INIT))
    assert packets[-1]["state"] == STATE_ADMIN_DOWN and packets[-1]["diag"] == 7


# Timers --------------------------------------------------------------------

@pytest.mark.full
def test_bfd_timer_negotiation(topology, pair):
    """Different intervals and multipliers per side (RFC 5880 6.8.2-6.8.4):
    TX interval = max(local desired min TX, remote required min RX) and
    detection time = remote multiplier x max(local required min RX,
    remote desired min TX)."""
    pa = [profile(1, **{"tx-interval": 100, "rx-interval": 200, "multiplier": 3})]
    pb = [profile(1, **{"tx-interval": 300, "rx-interval": 50, "multiplier": 5})]
    a, b = pair(pa, [static(topology.if_a, "a", **{"bfd-profile-id": 1})],
                pb, [static(topology.if_b, "b", **{"bfd-profile-id": 1})])
    wait_states([a, b], "Up", 10)
    wait_until(lambda: negotiated(a) and negotiated(b), 5, message="poll sequence completed")
    sa, sb = session(a), session(b)
    assert (sa["desired-min-tx-interval-us"], sa["required-min-rx-interval-us"]) == (100000, 200000)
    assert (sa["remote-desired-min-tx-interval-us"], sa["remote-required-min-rx-interval-us"]) == (300000, 50000)
    assert (sa["multiplier"], sa["remote-multiplier"]) == (3, 5)
    assert sa["tx-interval-us"] == max(100000, 50000)
    assert sa["detection-time-us"] == 5 * max(200000, 300000)
    assert (sb["desired-min-tx-interval-us"], sb["required-min-rx-interval-us"]) == (300000, 50000)
    assert (sb["remote-desired-min-tx-interval-us"], sb["remote-required-min-rx-interval-us"]) == (100000, 200000)
    assert sb["tx-interval-us"] == max(300000, 200000)
    assert sb["detection-time-us"] == 3 * max(50000, 100000)
    # The poll sequence after Up which changed the slow start intervals.
    assert sa["stats"]["poll-sequences"] == 1 and sb["stats"]["poll-sequences"] == 1
    # Packet rates match the negotiated TX intervals (jitter 0-25 %).
    rx_a, rx_b = sa["stats"]["rx-packets"], sb["stats"]["rx-packets"]
    time.sleep(3)
    sa, sb = session(a), session(b)
    assert 3 / 0.3 <= sa["stats"]["rx-packets"] - rx_a <= 3 / 0.225 + 2
    assert 3 / 0.1 <= sb["stats"]["rx-packets"] - rx_b <= 3 / 0.075 + 2
    assert sa["stats"]["down"] == 0 and sb["stats"]["down"] == 0


@pytest.mark.full
def test_bfd_slow_start(topology, bbl):
    """While not Up, the desired min TX interval is at least one second
    (RFC 5880 6.8.3), the configured interval is used after Up and again
    slow start after the session went down."""
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100})]
    # The kernel answers ARP until instance B is started.
    helpers.kernel_address(topology.b, topology.if_b, IP_B + "/24")
    a = bbl(topology.a, "a", bfd_config(topology.if_a, "a", prof,
                                        [static(topology.if_a, "a", **{"bfd-profile-id": 1})]))
    s = session(a)
    assert s["state"] == "Down"
    assert (s["desired-min-tx-interval-us"], s["required-min-rx-interval-us"]) == (SLOW_US, 100000)
    assert s["tx-interval-us"] == SLOW_US
    # First packet within one second, then one per 0.75-1 s.
    wait_until(lambda: session(a)["stats"]["tx-packets"] > 0, 2, 0.05, message="first packet")
    tx = session(a)["stats"]["tx-packets"]
    time.sleep(3)
    assert 3 <= session(a)["stats"]["tx-packets"] - tx <= 5
    topology.b.exec(["ip", "addr", "flush", "dev", topology.if_b])
    b = bbl(topology.b, "b", bfd_config(topology.if_b, "b", prof,
                                        [static(topology.if_b, "b", **{"bfd-profile-id": 1})]))
    wait_states([a, b], "Up", 10)
    wait_until(lambda: negotiated(a) and negotiated(b), 5, message="poll sequence completed")
    s = session(a)
    assert (s["desired-min-tx-interval-us"], s["tx-interval-us"]) == (100000, 100000)
    b.kill()
    wait_until(lambda: session(a)["state"] == "Down", 2, 0.05, message="session down")
    s = session(a)
    assert (s["desired-min-tx-interval-us"], s["tx-interval-us"]) == (SLOW_US, SLOW_US)


@pytest.mark.full
def test_bfd_poll_sequence(topology, pair):
    """bfd-session-update while Up starts a poll sequence (RFC 5880 6.8.3)
    which advertises the new values to the peer."""
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100})]
    a, b = pair(prof, [static(topology.if_a, "a", **{"bfd-profile-id": 1})],
                sessions_b=[static(topology.if_b, "b", **{"bfd-profile-id": 1})])
    wait_states([a, b], "Up", 10)
    wait_until(lambda: negotiated(a) and negotiated(b), 5, message="poll sequence completed")
    polls_a, polls_b = session(a)["stats"]["poll-sequences"], session(b)["stats"]["poll-sequences"]

    def updated(tx, rx, mult, polls):
        sa, sb = session(a), session(b)
        return (not sa["poll"] and sa["stats"]["poll-sequences"] == polls and
                sb["remote-desired-min-tx-interval-us"] == tx and
                sb["remote-required-min-rx-interval-us"] == rx and sb["remote-multiplier"] == mult)

    # Longer TX interval and shorter RX interval.
    assert a.ctrl("bfd-session-update", **{"bfd-session-id": 1, "tx-interval": 300, "rx-interval": 50})["code"] == 200
    wait_until(lambda: updated(300000, 50000, 3, polls_a + 1), 3, 0.1, message="update advertised")
    sa, sb = session(a), session(b)
    assert (sa["desired-min-tx-interval-us"], sa["required-min-rx-interval-us"]) == (300000, 50000)
    assert sa["tx-interval-us"] == 300000
    assert sa["detection-time-us"] == 3 * max(50000, 100000)
    assert sb["tx-interval-us"] == max(100000, 50000)
    assert sb["detection-time-us"] == 3 * max(100000, 300000)
    # The peer only answered with final, without poll sequence of its own.
    assert sb["stats"]["poll-sequences"] == polls_b

    # Multiplier only.
    assert a.ctrl("bfd-session-update", **{"bfd-session-id": 1, "multiplier": 10})["code"] == 200
    wait_until(lambda: updated(300000, 50000, 10, polls_a + 2), 3, 0.1, message="multiplier advertised")
    assert session(b)["detection-time-us"] == 10 * 300000

    # Back to shorter TX interval, update of all sessions without filter.
    assert a.ctrl("bfd-session-update", **{"tx-interval": 100, "rx-interval": 100, "multiplier": 3})["code"] == 200
    wait_until(lambda: updated(100000, 100000, 3, polls_a + 3), 3, 0.1, message="update advertised")
    sa, sb = session(a), session(b)
    assert (sa["tx-interval-us"], sa["detection-time-us"]) == (100000, 300000)
    assert (sb["tx-interval-us"], sb["detection-time-us"]) == (100000, 300000)
    # No flap during the poll sequences.
    time.sleep(1)
    for instance in (a, b):
        s = session(instance)
        assert s["state"] == "Up" and s["stats"]["down"] == 0 and s["stats"]["timeout"] == 0

    # Update of a session not Up changes the values used after slow start.
    b.kill()
    wait_until(lambda: session(a)["state"] == "Down", 2, 0.05, message="session down")
    assert a.ctrl("bfd-session-update", **{"bfd-session-id": 1, "tx-interval": 200})["code"] == 200
    s = session(a)
    assert (s["desired-min-tx-interval-us"], s["poll"]) == (SLOW_US, False)
    assert a.terminate() == 0
    # Poll with the new values answered with final (RFC 5880 6.5), never both.
    packets_a, packets_b = bfd_packets(a, IP_A), bfd_packets(a, IP_B)
    polls = [(p["tx"], p["rx"], p["mult"]) for p in packets_a if p["poll"]]
    # Values after Up (end of slow start) and of the three updates.
    for values in ((100000, 100000, 3), (300000, 50000, 3), (300000, 50000, 10)):
        assert values in polls
    assert polls.count((100000, 100000, 3)) >= 2
    assert sum(p["final"] for p in packets_b) >= 4
    assert not any(p["poll"] and p["final"] for p in packets_a + packets_b)


# Authentication --------------------------------------------------------------

AUTH = {
    "simple": "simple-pw",
    "keyed-md5": "md5-key-16-chars",
    "meticulous-keyed-md5": "m-md5",
    "keyed-sha1": "sha1-key-is-20-chars",
    "meticulous-keyed-sha1": "m-sha1",
}


def auth(auth_type, key=None, key_id=None, **timers):
    p = profile(1, **timers)
    if auth_type:
        p["authentication-type"] = auth_type
        p["authentication-key"] = key or AUTH[auth_type]
    if key_id is not None:
        p["authentication-key-id"] = key_id
    return [p]


@pytest.mark.full
@pytest.mark.parametrize("auth_type", list(AUTH))
def test_bfd_authentication(topology, pair, auth_type):
    timers = {"tx-interval": 100, "rx-interval": 100}
    a, b = pair(auth(auth_type, key_id=7, **timers), [static(topology.if_a, "a", **{"bfd-profile-id": 1})],
                auth(auth_type, key_id=7, **timers), [static(topology.if_b, "b", **{"bfd-profile-id": 1})])
    wait_states([a, b], "Up", 10)
    # Stable with sequence numbers checked (meticulous: incremented with each packet).
    time.sleep(2)
    for instance in (a, b):
        s = session(instance)
        assert s["authentication-type"] == auth_type
        assert s["state"] == "Up" and s["stats"]["down"] == 0
        assert s["stats"]["rx-auth-errors"] == 0 and s["stats"]["rx-packets"] >= 15
    assert a.terminate() == 0
    # Authentication section (RFC 5880 4.2-4.4).
    auth_types = list(AUTH)
    auth_len = {"simple": 3 + len(AUTH[auth_type]), "keyed-md5": 24, "meticulous-keyed-md5": 24,
                "keyed-sha1": 28, "meticulous-keyed-sha1": 28}[auth_type]
    packets = bfd_packets(a, IP_A)
    assert packets
    for bfd in packets:
        assert bfd["auth"] and bfd["auth_type"] == auth_types.index(auth_type) + 1
        assert (bfd["auth_len"], bfd["key_id"]) == (auth_len, 7)
        assert bfd["length"] == bfd["size"] == 24 + auth_len


@pytest.mark.full
@pytest.mark.parametrize("auth_a,auth_b", [
    (("keyed-md5", "key-a", None), ("keyed-md5", "key-b", None)),
    (("meticulous-keyed-sha1", "key", 1), ("meticulous-keyed-sha1", "key", 2)),
    (("simple", "key-a", None), ("simple", "key-b", None)),
    (("keyed-sha1", None, None), (None, None, None)),
    (("keyed-md5", "key", None), ("keyed-sha1", "key", None)),
], ids=["wrong-key", "wrong-key-id", "wrong-simple-password", "one-side", "type-mismatch"])
def test_bfd_authentication_mismatch(topology, pair, auth_a, auth_b):
    """Packets failing authentication are discarded (RFC 5880 6.7, 6.8.6)."""
    a, b = pair(auth(*auth_a), [static(topology.if_a, "a", **{"bfd-profile-id": 1})],
                auth(*auth_b), [static(topology.if_b, "b", **{"bfd-profile-id": 1})])
    wait_until(lambda: all(session(i)["stats"]["rx-auth-errors"] >= 2 for i in (a, b)), 5,
               message="authentication errors")
    for instance in (a, b):
        s = session(instance)
        assert s["state"] == "Down" and s["stats"]["rx-packets"] == 0 and s["remote-discriminator"] == 0
        assert s["stats"]["up"] == 0


@pytest.mark.full
@pytest.mark.parametrize("auth_type", ["meticulous-keyed-md5", "meticulous-keyed-sha1"])
def test_bfd_authentication_peer_restart(topology, bbl, auth_type):
    """The received sequence number is no longer known after the detection
    time (RFC 5880 6.7.3), so the restarted peer with another sequence
    number comes up again."""
    config_a = bfd_config(topology.if_a, "a", auth(auth_type),
                          [static(topology.if_a, "a", **{"bfd-profile-id": 1})])
    a = bbl(topology.a, "a", config_a)
    b = bbl(topology.b, "b", bfd_config(topology.if_b, "b", auth(auth_type),
                                        [static(topology.if_b, "b", **{"bfd-profile-id": 1})]))
    wait_states([a, b], "Up", 10)
    a.kill()
    # Restarted within the detection time of 3 s.
    a = bbl(topology.a, "a2", config_a)
    wait_states([a, b], "Up", 15)
    s = session(b)
    assert s["stats"]["up"] == 2 and s["stats"]["timeout"] <= 1


# AdminDown, detection timeout, teardown, passive ------------------------------

@pytest.mark.full
@pytest.mark.parametrize("disabled", ["a", "b"])
def test_bfd_admin_down(topology, pair, disabled):
    """bfd-session-disable signals AdminDown, the peer goes Down with
    diagnostic neighbor signaled session down (RFC 5880 6.8.6) and both
    come Up again after bfd-session-enable."""
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100})]
    a, b = pair(prof, [static(topology.if_a, "a", **{"bfd-profile-id": 1})],
                sessions_b=[static(topology.if_b, "b", **{"bfd-profile-id": 1})])
    wait_states([a, b], "Up", 10)
    local, peer = (a, b) if disabled == "a" else (b, a)
    assert local.ctrl("bfd-session-disable")["code"] == 200
    s = session(local)
    assert (s["state"], s["local-diagnostic"], s["admin-state"]) == ("AdminDown", "administratively-down", "disabled")
    wait_until(lambda: session(peer)["state"] == "Down", 1, 0.05, message="peer down")
    s = session(peer)
    assert (s["remote-state"], s["remote-diagnostic"]) == ("AdminDown", "administratively-down")
    assert s["local-diagnostic"] == "neighbor-signaled-session-down"
    # The sessions stay down without detection timeout.
    time.sleep(1.5)
    for instance in (local, peer):
        s = session(instance)
        assert s["stats"]["timeout"] == 0 and s["stats"]["down"] == 1
    assert session(local)["state"] == "AdminDown" and session(peer)["state"] == "Down"
    # Disable again is no state change.
    assert local.ctrl("bfd-session-disable", **{"bfd-session-id": 1})["code"] == 200
    assert local.ctrl("bfd-session-enable", **{"bfd-session-id": 1})["code"] == 200
    assert session(local)["admin-state"] == "enabled"
    wait_states([a, b], "Up", 5)
    for instance in (local, peer):
        s = session(instance)
        assert s["stats"]["up"] == 2 and s["local-diagnostic"] == "none"


def wait_down_time(instance, timeout):
    """Wait until the session is no longer Up, return the elapsed time."""
    start = time.monotonic()
    wait_until(lambda: session(instance)["state"] != "Up", timeout, 0.02, message="session down")
    return time.monotonic() - start


@pytest.mark.full
def test_bfd_detection_timeout_kill(topology, pair):
    """The peer killed stops sending, the session goes Down after the
    detection time with diagnostic control detection time expired."""
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100})]
    a, b = pair(prof, [static(topology.if_a, "a", **{"bfd-profile-id": 1})],
                sessions_b=[static(topology.if_b, "b", **{"bfd-profile-id": 1})])
    wait_states([a, b], "Up", 10)
    wait_until(lambda: negotiated(a), 5, message="poll sequence completed")
    b.kill()
    assert wait_down_time(a, 2) < 0.3 + 0.3
    s = session(a)
    assert (s["state"], s["local-diagnostic"]) == ("Down", "control-detection-time-expired")
    assert s["stats"]["timeout"] == 1 and s["stats"]["down"] == 1
    assert s["remote-discriminator"] == 0
    # The session stays down and sends slow start packets.
    time.sleep(1)
    assert session(a)["state"] == "Down"


@pytest.mark.full
def test_bfd_detection_timeout_drop(bridged, bbl):
    """BFD packets dropped in both directions: both sessions go Down
    after the detection time and Up again once no longer dropped."""
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100})]
    a = bbl(bridged.a, "a", bfd_config(bridged.if_a, "a", prof,
                                       [static(bridged.if_a, "a", **{"bfd-profile-id": 1})]))
    b = bbl(bridged.b, "b", bfd_config(bridged.if_b, "b", prof,
                                       [static(bridged.if_b, "b", **{"bfd-profile-id": 1})]))
    wait_states([a, b], "Up", 10)
    wait_until(lambda: negotiated(a) and negotiated(b), 5, message="poll sequence completed")
    bridged.drop(True)
    wait_down_time(a, 1)
    wait_until(lambda: session(b)["state"] == "Down", 1, 0.05, message="session down")
    assert bridged.dropped() > 0
    for instance in (a, b):
        s = session(instance)
        assert (s["state"], s["local-diagnostic"]) == ("Down", "control-detection-time-expired")
        assert s["stats"]["timeout"] == 1
    bridged.drop(False)
    wait_states([a, b], "Up", 5)
    for instance in (a, b):
        assert session(instance)["stats"]["up"] == 2


@pytest.mark.full
def test_bfd_teardown(topology, pair):
    """On teardown, AdminDown is sent to the peer, which goes Down without
    detection timeout (RFC 5880 6.8.16)."""
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100})]
    a, b = pair(prof, [static(topology.if_a, "a", **{"bfd-profile-id": 1}),
                       static(topology.if_a, "a", "ipv6", **{"bfd-profile-id": 1})],
                sessions_b=[static(topology.if_b, "b", **{"bfd-profile-id": 1}),
                            static(topology.if_b, "b", "ipv6", **{"bfd-profile-id": 1})])
    wait_states([a, b], "Up", 10, count=2)
    assert a.terminate() == 0
    wait_until(lambda: states(b) == ["Down", "Down"], 2, 0.05, message="sessions down")
    time.sleep(1)
    for s in sessions(b):
        assert (s["state"], s["remote-state"]) == ("Down", "AdminDown")
        assert s["remote-diagnostic"] == "administratively-down"
        assert s["local-diagnostic"] == "neighbor-signaled-session-down"
        assert s["stats"]["timeout"] == 0
    for src in (IP_A, IP6_A):
        last = bfd_packets(a, src)[-1]
        assert (last["state"], last["diag"]) == (STATE_ADMIN_DOWN, 7)
    report = a.report()["report"]["bfd"]
    assert (report["sessions"], report["up"], report["timeout"]) == (2, 2, 0)
    assert report["tx-packets"] > 0 and report["rx-packets"] > 0 and report["rx-errors"] == 0
    assert b.terminate() == 0
    report = b.report()["report"]["bfd"]
    assert (report["sessions"], report["up"], report["down"], report["timeout"]) == (2, 2, 2, 0)


@pytest.mark.full
def test_bfd_passive(topology, bbl):
    """A passive system does not send before it received a packet from
    the peer (RFC 5880 6.1), two passive systems never come up."""
    active = [profile(1, **{"tx-interval": 100, "rx-interval": 100})]
    passive = [profile(1, **{"tx-interval": 100, "rx-interval": 100, "passive": True})]
    a = bbl(topology.a, "a", bfd_config(topology.if_a, "a", passive,
                                        [static(topology.if_a, "a", **{"bfd-profile-id": 1})]))
    assert session(a)["passive"]
    time.sleep(2.5)
    # Not even tried to send (tx-errors if the next hop is not resolved).
    assert (session(a)["stats"]["tx-packets"], session(a)["stats"]["tx-errors"]) == (0, 0)
    b = bbl(topology.b, "b", bfd_config(topology.if_b, "b", active,
                                        [static(topology.if_b, "b", **{"bfd-profile-id": 1})]))
    wait_states([a, b], "Up", 5)
    assert session(a)["stats"]["tx-packets"] > 0
    b.terminate()
    a.terminate()


@pytest.mark.full
def test_bfd_passive_both(topology, pair):
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100, "passive": True})]
    a, b = pair(prof, [static(topology.if_a, "a", **{"bfd-profile-id": 1})],
                sessions_b=[static(topology.if_b, "b", **{"bfd-profile-id": 1})])
    time.sleep(3)
    for instance in (a, b):
        s = session(instance)
        assert s["state"] == "Down"
        assert s["stats"]["tx-packets"] == 0 and s["stats"]["rx-packets"] == 0
        assert s["stats"]["tx-errors"] == 0


# Control commands --------------------------------------------------------------

@pytest.mark.full
def test_bfd_ctrl(topology, pair):
    a, b = pair([profile(1)],
                [dict(static(topology.if_a, "a"), name="v4"),
                 dict(static(topology.if_a, "a", "ipv6"), name="v6"),
                 {"network-interface": topology.if_a, "local-ipv4-address": IP_A,
                  "peer-ipv4-address": "10.9.9.9", "multihop": True, "name": "mh"}],
                sessions_b=[static(topology.if_b, "b"), static(topology.if_b, "b", "ipv6")])
    wait_until(lambda: states(a) == ["Up", "Up", "Down"], 10, message="sessions up")

    def names(**filters):
        return [s["name"] for s in sessions(a, **filters)]

    assert names() == ["v4", "v6", "mh"]
    assert names(**{"bfd-session-id": 2}) == ["v6"]
    assert names(**{"bfd-session-id": 4}) == []
    assert names(**{"network-interface": topology.if_a}) == ["v4", "v6", "mh"]
    assert names(**{"network-interface": "unknown"}) == []
    assert names(**{"peer-address": IP_B}) == ["v4"]
    assert names(**{"peer-address": "fc00:0:0::2"}) == ["v6"]
    assert names(**{"peer-address": "10.9.9.9"}) == ["mh"]
    assert names(**{"peer-address": "10.9.9.8"}) == []
    assert names(state="up") == ["v4", "v6"]
    assert names(state="DOWN") == ["mh"]
    assert names(state="Up", **{"peer-address": IP6_B}) == ["v6"]
    assert names(state="adminDown") == []

    # Not found.
    for command in ("bfd-session-disable", "bfd-session-enable"):
        response = a.ctrl(command, **{"bfd-session-id": 99})
        assert response["code"] == 404, response
    response = a.ctrl("bfd-session-update", **{"bfd-session-id": 99, "tx-interval": 100})
    assert response["code"] == 404, response
    response = a.ctrl("bfd-session-disable", **{"peer-address": "10.9.9.8"})
    assert response["code"] == 404, response

    # Invalid arguments.
    invalid = [
        ("bfd-sessions", {"bfd-session-id": 0}),
        ("bfd-sessions", {"bfd-session-id": "x"}),
        ("bfd-sessions", {"peer-address": "foo"}),
        ("bfd-session-disable", {"peer-address": "10.0.0.256"}),
        ("bfd-session-update", {"bfd-session-id": 1}),
        ("bfd-session-update", {}),
        ("bfd-session-update", {"tx-interval": 0}),
        ("bfd-session-update", {"tx-interval": 60001}),
        ("bfd-session-update", {"rx-interval": 0}),
        ("bfd-session-update", {"rx-interval": 60001}),
        ("bfd-session-update", {"multiplier": 0}),
        ("bfd-session-update", {"multiplier": 256}),
        ("bfd-session-update", {"tx-interval": "100"}),
        ("bfd-session-update", {"tx-interval": 100.5}),
    ]
    for command, arguments in invalid:
        response = a.ctrl(command, **arguments)
        assert response["code"] == 400, (command, arguments, response)
    # Nothing changed by the rejected commands.
    for s in sessions(a):
        assert (s["multiplier"], s["admin-state"]) == (3, "enabled")
        assert s["required-min-rx-interval-us"] == SLOW_US

    # Disable by state filter (case-insensitive) only matches the Up sessions.
    assert a.ctrl("bfd-session-disable", state="UP")["code"] == 200
    assert states(a) == ["AdminDown", "AdminDown", "Down"]
    assert names(state="admindown") == ["v4", "v6"]
    assert a.ctrl("bfd-session-enable", **{"peer-address": IP6_B})["code"] == 200
    wait_until(lambda: states(a) == ["AdminDown", "Up", "Down"], 5, message="v6 up")
    assert a.ctrl("bfd-session-enable")["code"] == 200
    wait_until(lambda: states(a) == ["Up", "Up", "Down"], 5, message="sessions up")


# Scale ---------------------------------------------------------------------------

SCALE = 1000


def scale_address(i):
    return "10.1.%d.%d" % (i // 250, i % 250 + 1)


@pytest.mark.full
def test_bfd_scale(topology, pair):
    """1000 multi-hop sessions at 100 ms (10 kpps per direction) stay Up
    for 30 s and go Down within the detection time after the peer was
    killed."""
    prof = [profile(1, **{"tx-interval": 100, "rx-interval": 100, "multiplier": 3})]
    sessions_a = [{"network-interface": topology.if_a, "local-ipv4-address": IP_A,
                   "peer-ipv4-address": scale_address(i), "multihop": True, "bfd-profile-id": 1}
                  for i in range(SCALE)]
    sessions_b = [{"network-interface": topology.if_b, "local-ipv4-address": scale_address(i),
                   "peer-ipv4-address": IP_A, "multihop": True, "bfd-profile-id": 1}
                  for i in range(SCALE)]
    a, b = pair(prof, sessions_a, sessions_b=sessions_b)

    def all_negotiated(instance):
        result = sessions(instance)
        return len(result) == SCALE and all(s["state"] == "Up" and not s["poll"] and
                                            s["tx-interval-us"] == 100000 for s in result)
    wait_until(lambda: all_negotiated(a) and all_negotiated(b), 30, 1, message="all sessions up")
    before = {i: {s["bfd-session-id"]: s["stats"] for s in sessions(i)} for i in (a, b)}
    duration = 30
    time.sleep(duration)
    for instance in (a, b):
        result = sessions(instance)
        assert len(result) == SCALE
        for s in result:
            assert s["state"] == "Up", s
            stats = s["stats"]
            assert (stats["up"], stats["down"], stats["timeout"]) == (1, 0, 0), s
            # TX errors only before the next hop was resolved.
            old = before[instance][s["bfd-session-id"]]
            assert stats["rx-errors"] == 0 and stats["tx-errors"] == old["tx-errors"], s
            # 100 ms with jitter of 0-25 %, 87.5 ms average.
            received = stats["rx-packets"] - old["rx-packets"]
            assert duration / 0.1 * 0.9 <= received <= duration / 0.075 * 1.05, s

    b.kill()
    start = time.monotonic()
    wait_until(lambda: not sessions(a, state="up"), 3, 0.05, message="all sessions down")
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, "all sessions down after %.2f s" % elapsed
    for s in sessions(a):
        assert (s["state"], s["local-diagnostic"]) == ("Down", "control-detection-time-expired"), s
        assert s["stats"]["timeout"] == 1, s
    assert a.terminate() == 0
    report = a.report()["report"]["bfd"]
    assert (report["sessions"], report["up"], report["down"], report["timeout"]) == (SCALE, SCALE, SCALE, SCALE)


# LDP ------------------------------------------------------------------------------

LDP_PROFILE = [profile(1, **{"tx-interval": 100, "rx-interval": 100, "multiplier": 3})]


def ldp_config(ifname, side, mode):
    if side == "a":
        local, peer, lsr_id, peer_lsr_id = (IP_A, IP6_A), (IP_B, IP6_B), LSR_ID_A, LSR_ID_B
    else:
        local, peer, lsr_id, peer_lsr_id = (IP_B, IP6_B), (IP_A, IP6_A), LSR_ID_B, LSR_ID_A
    ldp = {"instance-id": 1, "lsr-id": lsr_id, "keepalive-time": 15}
    if mode == "link":
        interface = network(ifname, local, peer, **{"ldp-instance-id": 1, "ldp-bfd-profile-id": 1})
    else:
        interface = network(ifname, local, peer)
        ldp["targeted-neighbors"] = [{"address": peer_lsr_id, "network-interface": ifname,
                                      "bfd-profile-id": 1}]
    return {"interfaces": {"network": [interface]}, "ldp": [ldp], "bfd": LDP_PROFILE}


def ldp_session(instance):
    result = instance.ctrl("ldp-sessions", **{"ldp-instance-id": 1})["ldp-sessions"]
    assert len(result) <= 1, result
    return result[0] if result else {}


def start_ldp(topo, bbl, mode):
    a = bbl(topo.a, "a", ldp_config(topo.if_a, "a", mode))
    b = bbl(topo.b, "b", ldp_config(topo.if_b, "b", mode))
    wait_until(lambda: ldp_session(a).get("state") == "operational" and
               ldp_session(b).get("state") == "operational", 30, message="LDP sessions operational")
    wait_states([a, b], "Up", 10)
    return a, b


@pytest.mark.full
@pytest.mark.parametrize("mode", ["link", "targeted"])
def test_bfd_ldp(bridged, bbl, mode):
    """LDP session with BFD, single-hop to the hello source for link LDP
    and multi-hop between the transport addresses for targeted LDP.
    Peer AdminDown does not close the LDP session (RFC 5882 3.2), but a
    BFD failure does."""
    a, b = start_ldp(bridged, bbl, mode)
    for instance, local, peer in ((a, LSR_ID_A, LSR_ID_B), (b, LSR_ID_B, LSR_ID_A)):
        s = session(instance)
        assert s["clients"] == ["ldp"]
        if mode == "link":
            local = IP_A if instance is a else IP_B
            peer = IP_B if instance is a else IP_A
        assert (s["local-address"], s["peer-address"]) == (local, peer)
        assert s["multihop"] == (mode == "targeted")
        assert s["min-ttl"] == (254 if mode == "targeted" else 255)
    wait_until(lambda: negotiated(a) and negotiated(b), 5, message="poll sequence completed")
    assert session(a)["detection-time-us"] == 300000
    transitions = {i: ldp_session(i)["state-transitions"] for i in (a, b)}

    # Peer AdminDown: BFD Down, LDP stays operational on both sides.
    assert b.ctrl("bfd-session-disable")["code"] == 200
    wait_until(lambda: session(a)["state"] == "Down", 1, 0.05, message="BFD down")
    assert session(a)["remote-state"] == "AdminDown"
    time.sleep(1)
    for instance in (a, b):
        assert ldp_session(instance)["state"] == "operational"
        assert ldp_session(instance)["state-transitions"] == transitions[instance]
        assert "BFD down" not in log(instance)
    assert b.ctrl("bfd-session-enable")["code"] == 200
    wait_states([a, b], "Up", 5)

    # BFD failure (BFD dropped, LDP not): the LDP sessions are closed.
    bridged.drop(True)
    wait_until(lambda: "BFD down" in log(a), 2, 0.05, message="LDP closed by BFD")
    assert "state Up -> Down (control-detection-time-expired)" in log(a)
    # The BFD session is deleted with the LDP session and added again when the
    # LDP session is operational again, which stays Down while BFD is dropped.
    wait_until(lambda: ldp_session(a).get("state") == "operational" and
               ldp_session(b).get("state") == "operational", 30, message="LDP sessions operational again")
    assert ldp_session(a)["state-transitions"] > transitions[a]
    assert bridged.dropped() > 0
    # A BFD session which was never Up does not close the LDP session.
    wait_until(lambda: states(a) == ["Down"], 5, message="new BFD session")
    transitions = {i: ldp_session(i)["state-transitions"] for i in (a, b)}
    time.sleep(2)
    for instance in (a, b):
        assert ldp_session(instance)["state"] == "operational"
        assert ldp_session(instance)["state-transitions"] == transitions[instance]
    bridged.drop(False)
    wait_states([a, b], "Up", 5)
    s = session(a)
    assert s["clients"] == ["ldp"] and s["stats"]["up"] == 1


@pytest.mark.full
@pytest.mark.parametrize("command", ["ldp-teardown", "ldp-disconnect"])
def test_bfd_ldp_session_down(topology, bbl, command):
    """The BFD session is deleted when the LDP session goes down without
    BFD failure, which signals AdminDown to the peer first."""
    a, b = start_ldp(topology, bbl, "link")
    ids = {i: session(i)["bfd-session-id"] for i in (a, b)}
    assert a.ctrl(command, **({"ldp-instance-id": 1} if command == "ldp-disconnect" else {}))["code"] == 200
    if command == "ldp-teardown":
        wait_until(lambda: not sessions(a), 5, 0.1, message="BFD session deleted")
        wait_until(lambda: not sessions(b), 10, 0.1, message="peer BFD session deleted")
    else:
        # Deleted and added again with the new LDP session.
        wait_until(lambda: all([s["bfd-session-id"] for s in sessions(i)] == [ids[i] + 1] for i in (a, b)), 30,
                   message="BFD sessions added again")
        wait_states([a, b], "Up", 10)
    for instance in (a, b):
        assert "BFD down" not in log(instance)
        assert "detection time expired" not in log(instance)


# Configuration -------------------------------------------------------------------

def invalid_config(ifname, bfd=None, sessions=None, interface=None, ldp=None):
    config = bfd_config(ifname, "a")
    if bfd is not None:
        config["bfd"] = bfd
    if sessions is not None:
        config["bfd-sessions"] = sessions
    if interface:
        config["interfaces"]["network"][0].update(interface)
    if ldp:
        config["ldp"] = [dict({"instance-id": 1, "lsr-id": LSR_ID_A}, **ldp)]
    return config


IF = "@if"  # replaced by the interface name


@pytest.mark.full
@pytest.mark.parametrize("args,message", [
    ({"bfd": [profile(1), profile(1)]}, "Duplicate bfd->bfd-profile-id 1"),
    ({"bfd": [{"tx-interval": 100}]}, "Missing value for bfd->bfd-profile-id"),
    ({"bfd": [profile(0)]}, "Invalid value for bfd->bfd-profile-id (1 - 65535)"),
    ({"bfd": [profile(1, **{"tx-interval": 0})]}, "Invalid value for bfd->tx-interval (1 - 60000)"),
    ({"bfd": [profile(1, **{"rx-interval": 60001})]}, "Invalid value for bfd->rx-interval (1 - 60000)"),
    ({"bfd": [profile(1, multiplier=0)]}, "Invalid value for bfd->multiplier (1 - 255)"),
    ({"bfd": [profile(1, multiplier=256)]}, "Invalid value for bfd->multiplier (1 - 255)"),
    ({"bfd": [profile(1, **{"min-ttl": 0})]}, "Invalid value for bfd->min-ttl (1 - 255)"),
    ({"bfd": [profile(1, **{"authentication-type": "md5", "authentication-key": "x"})]},
     "Invalid value for bfd->authentication-type"),
    ({"bfd": [profile(1, **{"authentication-type": "simple", "authentication-key": "x",
                            "authentication-key-id": 256})]},
     "Invalid value for bfd->authentication-key-id (0 - 255)"),
    ({"bfd": [profile(1, **{"authentication-type": "simple", "authentication-key": "x" * 17})]},
     "Invalid length of bfd->authentication-key"),
    ({"bfd": [profile(1, **{"authentication-type": "meticulous-keyed-md5", "authentication-key": "x" * 17})]},
     "Invalid length of bfd->authentication-key"),
    ({"bfd": [profile(1, **{"authentication-type": "keyed-sha1", "authentication-key": "x" * 21})]},
     "Invalid length of bfd->authentication-key"),
    ({"bfd": [profile(1, **{"authentication-type": "keyed-sha1", "authentication-key": ""})]},
     "Invalid length of bfd->authentication-key"),
    ({"bfd": [profile(1, **{"authentication-type": "keyed-md5"})]}, "Missing value for bfd->authentication-key"),
    ({"bfd": [profile(1, **{"authentication-key": "secret"})]},
     "bfd->authentication-key requires bfd->authentication-type"),
    ({"bfd": [profile(1, **{"authentication-type": "none", "authentication-key": "secret"})]},
     "bfd->authentication-key requires bfd->authentication-type"),
    ({"bfd": [profile(1, interval=100)]}, "Invalid attribute name 'interval' in 'bfd'"),
    ({"bfd": "profile"}, "Invalid value for bfd (list expected)"),
    ({"sessions": [{"network-interface": IF, "peer-ipv4-address": IP_B, "bfd-profile-id": 2}]},
     "Profile not found for bfd-sessions->bfd-profile-id 2"),
    ({"bfd": [profile(1)], "interface": {"ldp-instance-id": 1, "ldp-bfd-profile-id": 2}, "ldp": {}},
     "Profile not found for network->ldp-bfd-profile-id 2"),
    ({"interface": {"isis-bfd-profile-id": 1}}, "Profile not found for network->isis-bfd-profile-id 1"),
    ({"interface": {"ospfv2-bfd-profile-id": 1}}, "Profile not found for network->ospfv2-bfd-profile-id 1"),
    ({"interface": {"ospfv3-bfd-profile-id": 0}}, "Invalid value for network->ospfv3-bfd-profile-id (1 - 65535)"),
    ({"ldp": {"targeted-neighbors": [{"address": IP_B, "bfd-profile-id": 3}]}},
     "Profile not found for ldp->targeted-neighbors->bfd-profile-id 3"),
    ({"sessions": [{"network-interface": IF}]},
     "Either bfd-sessions->peer-ipv4-address or bfd-sessions->peer-ipv6-address is required"),
    ({"sessions": [{"network-interface": IF, "local-ipv4-address": IP_A}]},
     "Either bfd-sessions->peer-ipv4-address or bfd-sessions->peer-ipv6-address is required"),
    ({"sessions": [{"network-interface": IF, "peer-ipv4-address": IP_B, "peer-ipv6-address": IP6_B}]},
     "Either bfd-sessions->peer-ipv4-address or bfd-sessions->peer-ipv6-address is required"),
    ({"sessions": [{"network-interface": IF, "local-ipv6-address": IP6_A, "peer-ipv4-address": IP_B}]},
     "Address family of bfd-sessions local and peer address must match"),
    ({"sessions": [{"network-interface": IF, "local-ipv4-address": IP_A, "peer-ipv6-address": IP6_B}]},
     "Address family of bfd-sessions local and peer address must match"),
    ({"sessions": [{"network-interface": IF, "peer-ipv4-address": "10.0.0.256"}]},
     "Invalid value for bfd-sessions->peer-ipv4-address"),
    ({"sessions": [{"network-interface": IF, "peer-ipv6-address": IP_B}]},
     "Invalid value for bfd-sessions->peer-ipv6-address"),
    ({"sessions": [{"peer-ipv4-address": IP_B}]},
     "Missing value for bfd-sessions->network-interface (required for single-hop)"),
    ({"sessions": [{"network-interface": IF, "peer-ipv4-address": IP_B, "multi-hop": True}]},
     "Invalid attribute name 'multi-hop' in 'bfd-sessions'"),
    ({"sessions": "session"}, "Invalid value for bfd-sessions (list expected)"),
    ({"sessions": [{"network-interface": "unknown", "peer-ipv4-address": IP_B}]},
     "network interface unknown not found"),
    ({"sessions": [{"network-interface": IF, "peer-ipv4-address": IP_B},
                   {"network-interface": IF, "peer-ipv4-address": IP_B}]},
     "Failed to add BFD session (duplicate"),
], ids=["duplicate-profile", "missing-profile-id", "profile-id", "tx-interval", "rx-interval",
        "multiplier-0", "multiplier-256", "min-ttl", "auth-type", "key-id", "simple-key-too-long",
        "md5-key-too-long", "sha1-key-too-long", "empty-key", "type-without-key", "key-without-type",
        "key-with-type-none", "unknown-profile-attribute", "profiles-type", "session-unknown-profile",
        "ldp-unknown-profile", "isis-unknown-profile", "ospfv2-unknown-profile", "ospfv3-profile-id",
        "targeted-unknown-profile", "missing-peer", "local-without-peer", "both-families",
        "mismatching-families", "mismatching-families-v6", "invalid-peer", "invalid-peer-v6",
        "single-hop-without-interface", "unknown-session-attribute", "sessions-type",
        "unknown-interface", "duplicate-session"])
def test_bfd_config_invalid(topology, tmp_path, args, message):
    args = dict(args)
    if "sessions" in args and isinstance(args["sessions"], list):
        args["sessions"] = [{k: (topology.if_a if v == IF else v) for k, v in s.items()}
                            for s in args["sessions"]]
    instance = BngBlaster(topology.a, tmp_path, "bbl")
    with pytest.raises(RuntimeError, match="exited on start"):
        instance.start(invalid_config(topology.if_a, **args))
    output = open(instance.path("stdout")).read()
    try:
        output += log(instance)
    except FileNotFoundError:
        pass
    assert message in output
