"""
BNG Blaster BGP message validation and FSM against a scripted peer

Namespace A runs the BNG Blaster (10.0.0.1, fd00::1), namespace B runs
the scripted peer bgp_peer.py on the kernel interface (10.0.0.2, fd00::2),
which sends valid and invalid messages and reports the NOTIFICATION
received from the BNG Blaster.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import os
import re
import subprocess
import sys
import time

import pytest

import helpers
from helpers import BngBlaster, bgpupdate, wait_until

BBL_ADDRESS, PEER_ADDRESS = "10.0.0.1", "10.0.0.2"
BBL_ADDRESS6, PEER_ADDRESS6 = "fd00::1", "fd00::2"
AS = 65001
PEER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bgp_peer.py")


def peer_open(**kwargs):
    args = {"as": AS, "id": PEER_ADDRESS}
    args.update(kwargs)
    return {"open": {"version": args.get("version", 4), "asn": args["as"], "hold": args.get("hold", 90),
                     "router_id": args["id"], "marker": args.get("marker", "ff")}}


ESTABLISH = [peer_open(), {"keepalive": {}}, {"sleep": 1}]


class Setup:

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.bbl = None
        helpers.kernel_address(topology.b, topology.if_b, PEER_ADDRESS + "/24", PEER_ADDRESS6 + "/64")

    def start_bbl(self, ipv6=False, mtu=None, **bgp):
        network = {"interface": self.topology.if_a, "address": BBL_ADDRESS + "/24", "gateway": PEER_ADDRESS,
                   "address-ipv6": BBL_ADDRESS6 + "/64", "gateway-ipv6": PEER_ADDRESS6}
        if mtu:
            network["mtu"] = mtu
        session = {"local-address": BBL_ADDRESS6 if ipv6 else BBL_ADDRESS,
                   "peer-address": PEER_ADDRESS6 if ipv6 else PEER_ADDRESS,
                   "local-as": AS, "peer-as": AS, "id": BBL_ADDRESS, "hold-time": 9, "reconnect": False}
        session.update(bgp)
        session = {k: v for k, v in session.items() if v is not None}
        config = {"interfaces": {"network": network}, "bgp": [session]}
        self.bbl = BngBlaster(self.topology.a, self.tmp_path).start(config, logging=("info", "bgp", "tcp"))
        self.processes.append(self.bbl)

    def peer_cmd(self, mode, steps=(), ipv6=False, **args):
        cmd = [sys.executable, PEER, mode,
               "--local", PEER_ADDRESS6 if ipv6 else PEER_ADDRESS,
               "--peer", BBL_ADDRESS6 if ipv6 else BBL_ADDRESS,
               "--steps", json.dumps(list(steps))]
        for key, value in args.items():
            cmd += ["--" + key, str(value)]
        return self.topology.b.cmd(cmd)

    def peer(self, mode, steps=(), **args):
        """Run the peer until it finishes and return its result."""
        out = helpers.run(self.peer_cmd(mode, steps, **args), timeout=90)
        return json.loads(out)

    def peer_start(self, mode, steps=(), **args):
        proc = subprocess.Popen(self.peer_cmd(mode, steps, **args), stdout=subprocess.PIPE, text=True)
        self.processes.append(type("Proc", (), {"stop": proc.kill})())
        return proc

    def session(self):
        return self.bbl.ctrl("bgp-sessions")["bgp-sessions"][0]

    def log(self):
        return open(self.bbl.path("log")).read()


@pytest.fixture
def setup(topology, processes, tmp_path):
    return Setup(topology, processes, tmp_path)


def notifications(result):
    return [(m["code"], m["subcode"]) for m in result["messages"] if m["type"] == 3]


@pytest.mark.parametrize("steps,error", [
    ([peer_open(**{"as": 65002})], (2, 2)),
    ([peer_open(version=3)], (2, 1)),
    ([peer_open(hold=1)], (2, 6)),
    ([peer_open(id="0.0.0.0")], (2, 3)),
    ([peer_open(marker="00")], (1, 1)),
    ([{"keepalive": {}}], (5, 1)),
    ([peer_open(), {"update": {}}], (5, 2)),
    (ESTABLISH + [peer_open()], (5, 3)),
    (ESTABLISH + [{"type": 9}], (1, 3)),
    (ESTABLISH + [{"keepalive": {"length": 20}}], (1, 2)),
], ids=["bad-peer-as", "version", "hold-time", "identifier", "marker", "keepalive-opensent",
        "update-openconfirm", "open-established", "message-type", "keepalive-length"])
def test_notification(setup, steps, error):
    """Invalid OPEN messages (RFC 4271 section 6.2), headers (section 6.1)
    and messages unexpected in the current state (section 8.2.2, RFC 6608)
    are answered with the matching NOTIFICATION and the connection is
    closed."""
    peer = setup.peer_start("accept", steps)
    setup.start_bbl()
    result = json.loads(peer.communicate(timeout=60)[0])
    assert notifications(result) == [error], result
    assert result["end"] == "fin", result
    wait_until(lambda: setup.session()["state"] == "closed", 10, message="session closed")


def test_peer_as_not_configured(setup):
    """Without peer-as, any peer AS is accepted."""
    peer = setup.peer_start("accept", [peer_open(**{"as": 65099}), {"keepalive": {}}], wait=3)
    setup.start_bbl(**{"peer-as": None})
    wait_until(lambda: setup.session()["state"] == "established", 15, message="session established")
    assert setup.session()["peer-as"] == 65099
    result = json.loads(peer.communicate(timeout=60)[0])
    assert notifications(result) == [], result


def test_closing_ignores_messages(setup):
    """KEEPALIVE messages received after the NOTIFICATION of bgp-disconnect
    (while closing) do not restart the hold timer, which would expire
    after the close."""
    peer = setup.peer_start("accept", ESTABLISH + [{"keepalive_for": 6}], wait=1)
    setup.start_bbl(**{"hold-time": 3})
    wait_until(lambda: setup.session()["state"] == "established", 15, message="session established")
    setup.bbl.ctrl("bgp-disconnect")
    result = json.loads(peer.communicate(timeout=60)[0])
    assert notifications(result) == [(6, 2)], result
    wait_until(lambda: setup.session()["state"] == "closed", 10, message="session closed")
    time.sleep(5)
    assert "session timeout" not in setup.log()


def test_no_reconnect_refuses_connection(setup):
    """A session with reconnect false stays down after bgp-disconnect,
    also if the peer connects again (RFC 4271 section 8.2.2)."""
    peer = setup.peer_start("accept", ESTABLISH, wait=30)
    setup.start_bbl()
    wait_until(lambda: setup.session()["state"] == "established", 15, message="session established")
    setup.bbl.ctrl("bgp-disconnect")
    result = json.loads(peer.communicate(timeout=60)[0])
    assert notifications(result) == [(6, 2)], result
    wait_until(lambda: setup.session()["state"] == "closed", 10, message="session closed")
    result = setup.peer("connect", timeout=5)
    assert result["connect"] != "established", result
    assert setup.session()["state"] == "closed"


@pytest.mark.parametrize("lose", ["passive", "active"])
def test_collision_cease(setup, lose):
    """Both sides connect, the peer sends its OPEN first on the connection
    which loses the collision resolution (RFC 4271 section 6.8). This
    connection is closed from its own receive callback with NOTIFICATION
    Cease (Connection Collision Resolution) and FIN instead of RST, the
    session is established on the other connection."""
    # The connection initiated by the higher BGP identifier survives.
    peer_id = "10.0.0.9" if lose == "passive" else "9.0.0.1"
    peer = setup.peer_start("collision", [peer_open(id=peer_id)], lose=lose, wait=5)
    setup.start_bbl(reconnect=True)
    result = json.loads(peer.communicate(timeout=90)[0])
    assert "error" not in result, result
    assert notifications(result["lose"]) == [(6, 7)], result
    assert result["lose"]["end"] == "fin", result
    assert notifications(result["win"]) == [], result
    assert 4 in [m["type"] for m in result["win"]["messages"]], result
    assert "openconfirm -> established" in setup.log()


def max_tcp_payload(capture, source):
    sizes = [int(m) for m in re.findall(r"%s\.\d+ > \S+: tcp (\d+)" % re.escape(source), capture)]
    return max(sizes) if sizes else 0


@pytest.mark.parametrize("ipv6,mtu,mss", [(False, 1280, 1240), (True, None, 1440)], ids=["ipv4-mtu1280", "ipv6"])
def test_send_mss(setup, tmp_path, ipv6, mtu, mss):
    """The send MSS is limited by the MTU of the network interface (IPv4
    without IP fragmentation) and is not limited to 1220 for IPv6."""
    update = str(tmp_path / "update.bgp")
    bgpupdate(["-f", update, "-a", str(AS), "-n", BBL_ADDRESS, "-p", "10.1.0.0/28", "-P", "3000"])
    capture = subprocess.Popen(setup.topology.b.cmd(
        ["timeout", "25", "tcpdump", "-nn", "-q", "-l", "-i", setup.topology.if_b,
         "(tcp port 179) or (ip[6:2] & 0x3fff != 0)"]),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(1)
    peer = setup.peer_start("accept", ESTABLISH, ipv6=ipv6, wait=8)
    setup.start_bbl(ipv6=ipv6, mtu=mtu, **{"raw-update-file": update})
    wait_until(lambda: setup.session()["raw-update-state"] == "done", 20, message="raw update done")
    json.loads(peer.communicate(timeout=60)[0])
    capture.terminate()
    out = capture.communicate(timeout=10)[0]
    assert max_tcp_payload(out, BBL_ADDRESS6 if ipv6 else BBL_ADDRESS) == mss, out[-2000:]
    # Non-first IPv4 fragments
    assert "ip-proto-6" not in out, out[-2000:]
