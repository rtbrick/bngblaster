"""
BNG Blaster stream statistics and stream control commands

A single BNG Blaster instance runs on both ends of a veth pair, loss and
reordering are added with netem on the first interface (qdisc bypass
disabled).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import sys
import time

import pytest

from helpers import BngBlaster, wait_until

EXIT_TIMEOUT = 30
SESSIONS = 2


@pytest.fixture
def bbl(local_veth, processes, tmp_path):
    def start(config, logging=("info",)):
        instance = BngBlaster(local_veth.ns, tmp_path).start(config, logging=logging,
                                                              args=("-j", "streams"))
        processes.append(instance)
        return instance
    return start


def network_config(veth, pps=10, **stream_extra):
    return {
        "interfaces": {
            "links": [{"interface": veth.if1, "qdisc-bypass": False}],
            "network": [
                {"interface": veth.if1, "address": "192.168.0.1/24", "gateway": "192.168.0.2"},
                {"interface": veth.if2, "address": "192.168.0.2/24", "gateway": "192.168.0.1"}
            ]
        },
        "streams": [
            dict({"name": "S1", "type": "ipv4", "pps": pps, "network-interface": veth.if1,
                  "destination-ipv4-address": "192.168.0.2"}, **stream_extra),
            {"name": "S2", "type": "ipv4", "pps": pps, "network-interface": veth.if2,
             "destination-ipv4-address": "192.168.0.1"}
        ]
    }


def netem(veth, *args):
    veth.ns.exec(["tc", "qdisc", "replace", "dev", veth.if1, "root", "netem"] + list(args))


def netem_del(veth):
    veth.ns.exec(["tc", "qdisc", "del", "dev", veth.if1, "root"], check=False)


def stream_info(instance, name):
    for summary in instance.ctrl("stream-summary")["stream-summary"]:
        if summary["name"] == name:
            return instance.ctrl("stream-info", **{"flow-id": summary["flow-id"]})["stream-info"]
    return None


def streams_verified(instance, count):
    return instance.ctrl("session-counters")["session-counters"]["stream-traffic-flows-verified"] == count


def test_report_loss_after_reset(local_veth, bbl):
    """The report uses loss and first sequence number since the last
    stream-reset, as stream-info does."""
    instance = bbl(network_config(local_veth, pps=50))
    wait_until(lambda: streams_verified(instance, 2), 10, message="streams verified")
    netem(local_veth, "loss", "30%")
    wait_until(lambda: stream_info(instance, "S1")["rx-loss"] > 5, 10, message="loss")
    netem_del(local_veth)
    assert instance.ctrl("stream-reset")["code"] == 200
    wait_until(lambda: streams_verified(instance, 2), 10, message="streams verified after reset")
    time.sleep(1)
    assert instance.terminate(EXIT_TIMEOUT) == 0
    report = instance.report()["report"]["traffic-streams"]
    assert report["flow-rx-packet-loss-max"] == 0, report
    assert report["first-seq-rx-max"] <= 5, report


def test_report_loss_min(local_veth, bbl):
    """flow-rx-packet-loss-min is 0 if one flow has no loss."""
    instance = bbl(network_config(local_veth, pps=50))
    wait_until(lambda: streams_verified(instance, 2), 10, message="streams verified")
    netem(local_veth, "loss", "30%")
    wait_until(lambda: stream_info(instance, "S1")["rx-loss"] > 5, 10, message="loss")
    assert instance.terminate(EXIT_TIMEOUT) == 0
    report = instance.report()["report"]["traffic-streams"]
    assert report["flow-rx-packet-loss-min"] == 0, report
    assert report["flow-rx-packet-loss-max"] > 5, report


def test_stream_stats_total_pps(local_veth, bbl):
    """stream-stats total-pps follows stream-update."""
    instance = bbl(network_config(local_veth))
    assert instance.ctrl("stream-stats")["stream-stats"]["total-pps"] == 20
    assert instance.ctrl("stream-update", name="S1", pps=50)["code"] == 200
    assert instance.ctrl("stream-stats")["stream-stats"]["total-pps"] == 60
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_streams_pending_multicast(local_veth, bbl):
    """Multicast streams are not listed as pending (never verified)."""
    config = network_config(local_veth)
    config["igmp"] = {"group": "239.0.0.1", "group-count": 2, "source": "192.168.0.1",
                      "send-multicast-traffic": True, "multicast-traffic-autostart": True,
                      "network-interface": local_veth.if1}
    instance = bbl(config)
    wait_until(lambda: streams_verified(instance, 2), 10, message="streams verified")
    assert instance.ctrl("streams-pending")["streams-pending"] == []
    pending = instance.ctrl("stream-summary", **{"pending-only": True})["stream-summary"]
    assert pending == [], pending
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_stream_reset_wrong_order(local_veth, bbl):
    """stream-reset clears rx-wrong-order."""
    instance = bbl(network_config(local_veth, pps=200))
    wait_until(lambda: streams_verified(instance, 2), 10, message="streams verified")
    netem(local_veth, "delay", "20ms", "reorder", "50%", "50%")
    wait_until(lambda: stream_info(instance, "S1")["rx-wrong-order"] > 0, 10, message="wrong order")
    netem_del(local_veth)
    time.sleep(0.5)
    assert instance.ctrl("stream-reset")["code"] == 200
    time.sleep(1)
    assert stream_info(instance, "S1")["rx-wrong-order"] == 0
    assert instance.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.parametrize("labels", [{"rx-label1": 0}, {"rx-label2": 5}])
def test_rx_label_expectation(local_veth, bbl, labels):
    """An expected label (label 0 included, label 2 alone) is verified, a
    stream received without MPLS labels is not verified."""
    instance = bbl(network_config(local_veth, **labels))
    wait_until(lambda: stream_info(instance, "S2")["verified"], 10, message="S2 verified")
    time.sleep(2)
    assert not stream_info(instance, "S1")["verified"]
    assert instance.terminate(EXIT_TIMEOUT) == 0


def access_config(veth, **config):
    """PPPoE sessions with session traffic against the A10NSP mock."""
    conf = {
        "interfaces": {
            "a10nsp": [{"interface": veth.if1}],
            "access": [{"interface": veth.if2, "type": "pppoe", "outer-vlan-min": 1, "outer-vlan-max": 100,
                        "inner-vlan": 7}]
        },
        "sessions": {"count": SESSIONS, "reconnect": True},
        "session-traffic": {"ipv4-pps": 10},
        "dhcpv6": {"enable": False},
        "ppp": {"ip6cp": {"enable": False}}
    }
    conf.update(config)
    return conf


def counters(instance):
    return instance.ctrl("session-counters")["session-counters"]


def wait_session_traffic(instance):
    wait_until(lambda: counters(instance)["sessions-established"] == SESSIONS, 30, message="sessions established")
    wait_until(lambda: counters(instance)["session-traffic-flows-verified"] == 2 * SESSIONS, 15,
               message="session traffic verified")


@pytest.mark.full
def test_session_traffic_reconnect(local_veth, bbl):
    """Session traffic convergence in the report is relative to the first
    packet sent after the reconnect, the L3 rate of session traffic is
    based on the packet length."""
    instance = bbl(access_config(local_veth))
    wait_session_traffic(instance)
    time.sleep(2)
    streams = instance.ctrl("session-streams", **{"session-id": 1})["session-streams"]["streams"]
    assert streams and all(s["rx-bps-l3"] > 0 for s in streams), streams
    assert instance.ctrl("session-restart", **{"session-id": 1})["code"] == 200
    wait_until(lambda: instance.ctrl("session-info", **{"session-id": 1})["session-info"]["flapped"] == 1,
               10, message="session flapped")
    wait_session_traffic(instance)
    assert instance.terminate(EXIT_TIMEOUT) == 0
    report = instance.report()["report"]["session-traffic"]
    assert report["first-seq-rx-downstream-ipv4-max"] <= 10, report
    assert report["violated-flows-downstream-ipv4-3s"] == 0, report


def test_session_traffic_stop_verified_reconnect(local_veth, bbl):
    """With stop-verified, session traffic starts again after a reconnect
    and is verified again."""
    instance = bbl(access_config(local_veth, traffic={"stop-verified": True}))
    wait_session_traffic(instance)
    assert instance.ctrl("session-restart", **{"session-id": 1})["code"] == 200
    wait_until(lambda: instance.ctrl("session-info", **{"session-id": 1})["session-info"]["flapped"] == 1,
               10, message="session flapped")
    wait_session_traffic(instance)
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_session_group_filter_raw_stream(local_veth, bbl):
    """stream-stop with session-group-id does not stop streams without
    session (RAW streams)."""
    config = {
        "interfaces": {
            "network": [{"interface": local_veth.if1, "address": "10.0.0.1/16", "gateway": "10.0.1.1",
                         "gateway-resolve-wait": False}],
            "access": [{"interface": local_veth.if2, "type": "ipoe", "vlan-mode": "N:1", "ipv6": False,
                        "address": "10.0.1.1", "gateway": "10.0.0.1", "session-group-id": 1,
                        "stream-group-id": 1}]
        },
        "sessions": {"count": 1},
        "dhcp": {"enable": False},
        "streams": [
            {"name": "RAW", "type": "ipv4", "pps": 20, "network-interface": local_veth.if1,
             "destination-ipv4-address": "10.0.1.1"},
            {"name": "SESSION", "stream-group-id": 1, "type": "ipv4", "direction": "downstream", "pps": 20}
        ]
    }
    instance = bbl(config)
    wait_until(lambda: stream_info(instance, "RAW")["tx-packets"] > 0, 10, message="RAW stream sending")
    assert instance.ctrl("stream-stop", **{"session-group-id": 1})["code"] == 200
    time.sleep(0.5)
    before = stream_info(instance, "RAW")["tx-packets"]
    time.sleep(1)
    assert stream_info(instance, "RAW")["tx-packets"] > before
    assert instance.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.parametrize("vlan", [{"vlan": 100}, {"vlan": 100, "inner-vlan": 200, "qinq": True}],
                         ids=["single", "double"])
@pytest.mark.parametrize("link", [{}, {"rx-threads": 1}, {"io-mode": "raw"}, {"io-mode": "raw", "rx-threads": 1}],
                         ids=["packet_mmap", "packet_mmap-rx-thread", "raw", "raw-rx-thread"])
def test_rx_len_vlan(local_veth, bbl, vlan, link):
    """The received frame length includes the outer VLAN tag stripped by
    the kernel, so rx-len and the RX L2 rate match the sent frames."""
    config = {
        "interfaces": {
            "links": [dict({"interface": ifname}, **link) for ifname in (local_veth.if1, local_veth.if2)],
            "network": [
                dict({"interface": local_veth.if1, "address": "192.168.0.1/24", "gateway": "192.168.0.2"}, **vlan),
                dict({"interface": local_veth.if2, "address": "192.168.0.2/24", "gateway": "192.168.0.1"}, **vlan)
            ]
        },
        "streams": [{"name": "S1", "type": "ipv4", "pps": 20, "length": 1000,
                     "network-interface": "%s:%d" % (local_veth.if1, vlan["vlan"]),
                     "destination-ipv4-address": "192.168.0.2"}]
    }
    instance = bbl(config)
    wait_until(lambda: stream_info(instance, "S1")["verified"], 10, message="S1 verified")
    info = stream_info(instance, "S1")
    assert info["rx-len"] == info["tx-len"], info
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_flow_id_range(local_veth, bbl):
    """Flow IDs are 32 bit, larger values are rejected instead of being
    truncated to another flow."""
    instance = bbl(network_config(local_veth))
    big = 2**32 + 2  # flow 2 if truncated
    for command in ("stream-info", "stream-stop"):
        response = instance.ctrl(command, **{"flow-id": big})
        assert response["code"] == 400, (command, response)
    for argument in ("flow-id-min", "flow-id-max"):
        response = instance.ctrl("stream-stop", **{argument: 2**32})
        assert response["code"] == 400, (argument, response)
    assert instance.ctrl("stream-info", **{"flow-id": 2})["stream-info"]["enabled"]
    assert instance.terminate(EXIT_TIMEOUT) == 0


EOMPLS_INJECT = r"""
import socket, struct, sys
ifname, dst, count = sys.argv[1], bytes.fromhex(sys.argv[2].replace(":", "")), int(sys.argv[3])
src = bytes.fromhex("020000000002")
# BBL header of flow 1 with a sub-type the stream does not expect (rejected).
bbl = struct.pack("<QBBBBIIHHIIQII", 0x5274427269636b21, 1, 99, 2, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0)
udp = struct.pack("!HHHH", 65056, 65056, 8 + len(bbl), 0) + bbl
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                 socket.inet_aton("192.168.0.2"), socket.inet_aton("192.168.0.1"))
csum = sum(struct.unpack("!10H", ip))
csum = (csum & 0xffff) + (csum >> 16)
ip = ip[:10] + struct.pack("!H", ~csum & 0xffff) + ip[12:]
inner = dst + src + struct.pack("!H", 0x0800) + ip + udp
frame = dst + src + struct.pack("!HI", 0x8847, (1000 << 12) | (1 << 8) | 64) + inner
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((ifname, 0))
for _ in range(count):
    s.send(frame)
"""


@pytest.mark.parametrize("a10nsp", [False, True], ids=["evpn", "a10nsp"])
def test_eompls_rejected_rx_thread(local_veth, bbl, a10nsp):
    """Ethernet over MPLS stream packets which are not accepted (e.g. sent
    before stream-reset) are dropped by the RX thread instead of being
    processed by the main thread a second time, which counts them as
    received on the network or A10NSP interface."""
    count = 200
    local_veth.ns.exec(["sysctl", "-qw", "net.ipv6.conf.%s.disable_ipv6=1" % local_veth.if2])
    config = {
        "interfaces": {
            "links": [{"interface": local_veth.if1, "rx-threads": 1}],
            "network": [{"interface": local_veth.if1, "address": "192.168.0.1/24", "gateway": "192.168.0.2",
                         "gateway-resolve-wait": False, "a10nsp": a10nsp}]
        },
        "traffic": {"autostart": False},
        "streams": [{"name": "S1", "type": "ipv4", "pps": 10, "network-interface": local_veth.if1,
                     "destination-ipv4-address": "192.168.0.2"}]
    }
    instance = bbl(config)
    command = "a10nsp-interfaces" if a10nsp else "network-interfaces"

    def rx_packets():
        return instance.ctrl(command)[command][0]["rx-packets"]

    mac = local_veth.ns.exec(["cat", "/sys/class/net/%s/address" % local_veth.if1]).strip()
    before = rx_packets()
    local_veth.ns.exec([sys.executable, "-c", EOMPLS_INJECT, local_veth.if2, mac, str(count)])
    time.sleep(1)
    assert rx_packets() - before < count // 10
    assert not stream_info(instance, "S1")["verified"]
    assert instance.terminate(EXIT_TIMEOUT) == 0
