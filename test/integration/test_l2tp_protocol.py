"""
BNG Blaster L2TP LNS and LAC against a scripted L2TP peer

Namespace A runs the BNG Blaster LNS (10.0.0.1, second server 10.0.0.3)
or LAC (10.0.0.1), namespace B the scripted peer l2tp_peer.py on the
kernel interface (10.0.0.2).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

import helpers
from helpers import BngBlaster, wait_until

BBL_ADDRESS, PEER_ADDRESS, BBL_ADDRESS2 = "10.0.0.1", "10.0.0.2", "10.0.0.3"
SCCRP, SCCCN, STOPCCN, ICRP, ICCN, CDN = 2, 3, 4, 11, 12, 14
LCP = 0xc021
CONF_REQ, TERM_ACK, ECHO_REP = 1, 6, 10
PEER_MAGIC = 0x11223344
PEER = str(Path(__file__).parent / "l2tp_peer.py")


class Setup:

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.bbl = None
        helpers.kernel_address(topology.b, topology.if_b, PEER_ADDRESS + "/24")

    def network(self):
        return {"interface": self.topology.if_a, "address": BBL_ADDRESS + "/24", "gateway": PEER_ADDRESS}

    def start_lns(self):
        config = {
            "interfaces": {"network": self.network()},
            "l2tp-server": [
                {"name": "LNS1", "address": BBL_ADDRESS, "lcp-conf-request": True},
                {"name": "LNS2", "address": BBL_ADDRESS2}
            ]
        }
        self.bbl = BngBlaster(self.topology.a, self.tmp_path, "lns").start(config, logging=("info", "l2tp"))
        self.processes.append(self.bbl)

    def start_lac(self):
        config = {
            "interfaces": {
                "network": self.network(),
                "access": [{"interface": self.topology.if_a, "type": "pppol2tp", "l2tp-client-group-id": 1,
                            "outer-vlan": 1}]
            },
            "sessions": {"count": 1, "reconnect": False},
            "l2tp-client": [{"group-id": 1, "name": "LAC", "network-interface": self.topology.if_a,
                             "server-address": PEER_ADDRESS, "max-retry": 2}]
        }
        self.bbl = BngBlaster(self.topology.a, self.tmp_path, "lac").start(config, logging=("info", "l2tp"))
        self.processes.append(self.bbl)

    def peer_cmd(self, mode, scenario, server=BBL_ADDRESS, duration=3):
        return self.topology.b.cmd([sys.executable, PEER, mode, scenario, "--local", PEER_ADDRESS,
                                    "--server", server, "--duration", str(duration)])

    def peer(self, mode, scenario, **args):
        return json.loads(helpers.run(self.peer_cmd(mode, scenario, **args), timeout=60))

    def peer_start(self, mode, scenario, **args):
        proc = subprocess.Popen(self.peer_cmd(mode, scenario, **args), stdout=subprocess.PIPE, text=True)
        self.processes.append(type("Proc", (), {"stop": proc.kill})())
        return proc

    def tunnels(self):
        return self.bbl.ctrl("l2tp-tunnels")["l2tp-tunnels"]

    def sessions(self):
        return self.bbl.ctrl("l2tp-sessions")["l2tp-sessions"]


@pytest.fixture
def l2tp(topology, processes, tmp_path):
    return Setup(topology, processes, tmp_path)


def types(result):
    return [m["type"] for m in result["control"]]


def test_private_group_id(l2tp):
    """The Private Group ID AVP may have any number of octets (RFC 2661
    section 4.4.5), the session is not cleared."""
    l2tp.start_lns()
    peer = l2tp.peer_start("lac", "private-group-id")
    wait_until(lambda: [s for s in l2tp.sessions() if s["state"] == "Established"], 10,
               message="LNS session established")
    result = json.loads(peer.communicate(timeout=30)[0])
    assert CDN not in types(result), result


def test_sequencing_required(l2tp):
    """A call with Sequencing Required is cleared with CDN, as data
    messages are sent without sequence numbers."""
    l2tp.start_lns()
    result = l2tp.peer("lac", "sequencing")
    cdn = [m for m in result["control"] if m["type"] == CDN]
    assert cdn and cdn[0]["result-code"] == 2, result


def test_icrq_without_session_id(l2tp):
    """An ICRQ without the mandatory Assigned Session ID is not answered
    with ICRP and creates no session."""
    l2tp.start_lns()
    result = l2tp.peer("lac", "no-session-id")
    assert ICRP not in types(result), result
    assert l2tp.sessions() == []


def test_lns_iccn_timeout(l2tp):
    """A call answered with ICRP is cleared with CDN if no ICCN follows
    within 30 seconds, sessions waiting for ICCN kept their session ID
    forever, which could exhaust all session IDs of a tunnel."""
    l2tp.start_lns()
    peer = l2tp.peer_start("lac", "no-iccn", duration=36)
    wait_until(lambda: [s for s in l2tp.sessions() if s["state"] == "Wait-Control-Connection"], 10,
               message="LNS session waiting for ICCN")
    result = json.loads(peer.communicate(timeout=60)[0])
    assert ICRP in types(result), result
    cdn = [m for m in result["control"] if m["type"] == CDN]
    assert cdn and cdn[0]["result-code"] == 2, result
    assert l2tp.sessions() == []


def test_lns_lcp(l2tp):
    """The LNS answers LCP echo-request with its own Magic-Number (RFC 1661
    section 5.8), acknowledges LCP terminate-request (section 5.5) and clears
    the call with a CDN with a valid result code (RFC 2661 section 4.4.2)."""
    l2tp.start_lns()
    result = l2tp.peer("lac", "lcp")
    ppp = result["ppp"]
    request = [p for p in ppp if p["protocol"] == LCP and p["code"] == CONF_REQ]
    reply = [p for p in ppp if p["protocol"] == LCP and p["code"] == ECHO_REP]
    assert request and reply, result
    assert reply[0]["magic"] == request[0]["magic"] != PEER_MAGIC, result
    assert [p for p in ppp if p["protocol"] == LCP and p["code"] == TERM_ACK], result
    cdn = [m for m in result["control"] if m["type"] == CDN]
    assert cdn and cdn[0]["result-code"] not in (None, 0), result


def test_binary_peer_strings(l2tp):
    """Peer strings with invalid UTF-8 do not drop the tunnel and session
    from the l2tp-tunnels and l2tp-sessions output."""
    l2tp.start_lns()
    peer = l2tp.peer_start("lac", "binary-strings", duration=5)
    wait_until(lambda: l2tp.sessions(), 10, message="LNS session listed")
    tunnel = l2tp.tunnels()[0]
    assert tunnel["peer-name"] == "LAC-\\xFF\\xFE", tunnel
    session = l2tp.sessions()[0]
    assert session["peer-called-number"] == "\\xC3(" and session["peer-ari"] == "ari-\\xFF", session
    peer.communicate(timeout=30)


def test_sccrq_retry_second_server(l2tp):
    """A SCCRQ retransmitted to the second l2tp-server creates only one tunnel."""
    l2tp.start_lns()
    l2tp.peer("lac", "sccrq-retry", server=BBL_ADDRESS2)
    assert len(l2tp.tunnels()) == 1, l2tp.tunnels()


def test_l2tp_ctrl_tunnel_id_range(l2tp):
    """Tunnel IDs above 65535 are rejected instead of truncated."""
    l2tp.start_lns()
    peer = l2tp.peer_start("lac", "private-group-id")
    wait_until(lambda: l2tp.tunnels(), 10, message="tunnel")
    tunnel_id = l2tp.tunnels()[0]["tunnel-id"]
    for command in ("l2tp-tunnel-terminate", "l2tp-csurq"):
        result = l2tp.bbl.ctrl(command, **{"tunnel-id": tunnel_id + 65536, "sessions": [1]})
        assert result["code"] == 400, result
    result = l2tp.bbl.ctrl("l2tp-sessions", **{"tunnel-id": tunnel_id + 65536})
    assert result["code"] == 400, result
    assert l2tp.tunnels()[0]["state"] == "Established"
    peer.communicate(timeout=30)


@pytest.mark.parametrize("scenario,expected", [("no-tunnel-id", STOPCCN), ("no-session-id", CDN)])
def test_lac_missing_assigned_id(l2tp, scenario, expected):
    """The LAC rejects SCCRP without Assigned Tunnel ID with StopCCN and
    ICRP without Assigned Session ID with CDN (RFC 2661 section 6)."""
    peer = l2tp.peer_start("lns", scenario, duration=8)
    l2tp.start_lac()
    result = json.loads(peer.communicate(timeout=30)[0])
    received = types(result)
    assert expected in received, result
    if scenario == "no-tunnel-id":
        assert SCCCN not in received, result
    else:
        assert ICCN not in received, result
