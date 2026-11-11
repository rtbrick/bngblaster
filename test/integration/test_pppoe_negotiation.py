"""
BNG Blaster PPPoE client negotiation against a scripted PPPoE server

The BNG Blaster PPPoE client (namespace A) runs against ppp_peer.py
(namespace B), which rejects options, ignores or terminates NCPs,
renegotiates, sends invalid offers or unexpected packets as configured.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from helpers import BngBlaster, wait_until

CONF_REQ, CONF_ACK, CONF_NAK, CONF_REJ, TERM_REQ, TERM_ACK, CODE_REJ, PROT_REJ = 1, 2, 3, 4, 5, 6, 7, 8
LCP_MRU, LCP_MAGIC = 1, 5
LCP, IPCP, CCP = 0xc021, 0x8021, 0x80fd


class Setup:

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.log = str(tmp_path / "ppp_peer.json")
        self.server = None
        self.bbl = None

    def start_server(self, *args):
        cmd = [sys.executable, str(Path(__file__).parent / "ppp_peer.py"), self.topology.if_b, self.log]
        cmd += [str(a) for a in args]
        with open(str(self.tmp_path / "ppp_peer.log"), "w") as out:
            self.server = subprocess.Popen(self.topology.b.cmd(cmd), stdout=out, stderr=subprocess.STDOUT)
        self.processes.append(type("Proc", (), {"stop": self.server.kill})())
        wait_until(lambda: os.path.exists(self.log) or self.server.poll() is not None, 10, 0.2, "PPP peer")
        if self.server.poll() is not None:
            raise RuntimeError("PPP peer exited on start, see ppp_peer.log")

    def start_bbl(self, access=None, **config):
        interface = {"interface": self.topology.if_a, "type": "pppoe", "outer-vlan": 0, "inner-vlan": 0,
                     "vlan-mode": "N:1", "username": "user", "password": "secret"}
        interface.update(access or {})
        conf = {"interfaces": {"access": [interface]}, "sessions": {"count": 1, "reconnect": False},
                "dhcpv6": {"enable": False}}
        conf.update(config)
        self.bbl = BngBlaster(self.topology.a, self.tmp_path).start(conf, logging=("info", "pppoe"))
        self.processes.append(self.bbl)

    def received(self, kind=None, code=None):
        with open(self.log) as f:
            packets = [json.loads(line) for line in f]
        return [p for p in packets if (kind is None or p["kind"] == kind) and (code is None or p.get("code") == code)]

    def session(self):
        return self.bbl.ctrl("session-info", **{"session-id": 1})["session-info"]

    def state(self):
        return self.session()["session-state"]

    def counters(self):
        return self.bbl.ctrl("session-counters")["session-counters"]

    def wait_state(self, state, timeout=20):
        wait_until(lambda: self.state() == state, timeout, message="session %s" % state)


@pytest.fixture
def ppp(topology, processes, tmp_path):
    return Setup(topology, processes, tmp_path)


def test_lcp_conf_reject(ppp):
    """MRU and Magic-Number rejected by the server are not requested again
    (RFC 1661 section 5.4). Code-Reject and Discard-Request are not answered
    with Code-Reject (sections 5.6 and 5.9)."""
    ppp.start_server("--lcp-reject", "mru,magic", "--actions", "1:lcp-code-reject,1:lcp-discard")
    ppp.start_bbl()
    ppp.wait_state("Established")
    requests = ppp.received("lcp", CONF_REQ)
    assert {LCP_MRU, LCP_MAGIC} <= set(requests[0]["options"])
    assert not set(requests[-1]["options"]) & {LCP_MRU, LCP_MAGIC}, requests
    time.sleep(2)
    assert ppp.received("lcp", CODE_REJ) == []
    assert ppp.state() == "Established"


def test_ipcp_timeout_ipv4_only(ppp):
    """IPCP is not answered on an IPv4 only session: the session is
    terminated after the IPCP retries instead of hanging in network phase."""
    ppp.start_server("--ipcp", "ignore")
    ppp.start_bbl(access={"ipv6": False}, ppp={"ipcp": {"conf-request-timeout": 1, "conf-request-retry": 2}})
    ppp.wait_state("Terminated", 30)
    assert ppp.received("padt")


def test_ipcp_timeout_dual_stack(ppp):
    """IPCP is not answered but IP6CP is opened: the session is established
    with IPv6 after the IPCP retries."""
    ppp.start_server("--ipcp", "ignore")
    ppp.start_bbl(ppp={"ipcp": {"conf-request-timeout": 1, "conf-request-retry": 2}})
    ppp.wait_state("Established", 30)
    session = ppp.session()
    assert (session["ipcp-state"], session["ip6cp-state"]) == ("Closed", "Opened")


def test_ipcp_nak_max_failure(ppp):
    """The server answers every IPCP configure-request with configure-nak:
    the client gives up after Max-Failure (RFC 1661 section 4.6) and the
    IPv4 only session is terminated."""
    ppp.start_server("--ipcp", "nak-always")
    ppp.start_bbl(access={"ipv6": False})
    ppp.wait_state("Terminated", 30)
    requests = ppp.received("ipcp", CONF_REQ)
    assert 2 <= len(requests) <= 10, len(requests)


def test_ipcp_terminate_by_peer(ppp):
    """IPCP terminate-request of the server closes IPCP and stops IPv4,
    the session stays established with IPv6."""
    ppp.start_server("--actions", "2:ipcp-term")
    ppp.start_bbl()
    ppp.wait_state("Established")
    wait_until(lambda: ppp.session()["ipcp-state"] == "Closed", 10, message="IPCP closed")
    session = ppp.session()
    assert session["session-state"] == "Established" and session["ip6cp-state"] == "Opened"
    assert session.get("ipv4-address") in (None, "0.0.0.0")


def test_ipcp_renegotiation_by_peer(ppp):
    """IPCP configure-request of the server in opened state renegotiates
    IPCP: the client sends a new configure-request and IPCP is opened again."""
    ppp.start_server("--actions", "2:ipcp-reneg")
    ppp.start_bbl()
    ppp.wait_state("Established")
    before = len(ppp.received("ipcp", CONF_REQ))
    wait_until(lambda: len(ppp.received("ipcp", CONF_REQ)) > before, 10, message="IPCP configure-request")
    wait_until(lambda: ppp.session()["ipcp-state"] == "Opened", 10, message="IPCP opened again")
    assert ppp.session()["ipv4-address"] == "10.0.0.100"


def test_icmp_echo_reply(ppp):
    """ICMP echo request of the server to the session address is answered
    with an echo reply in the PPPoE session (crashed with the replies built
    from copies of the received headers)."""
    ppp.start_server("--actions", "3:icmp-echo")
    ppp.start_bbl(access={"ipv6": False})
    ppp.wait_state("Established")
    wait_until(lambda: ppp.received("icmp"), 10, message="ICMP echo reply")
    reply = ppp.received("icmp")[0]
    assert (reply["type"], reply["src"], reply["dst"]) == (0, "10.0.0.100", "10.0.0.1")
    assert ppp.bbl.alive() and ppp.state() == "Established"


def test_ipcp_close_retransmit(ppp):
    """ipcp-close on an established session with the first terminate-request
    lost: it is retransmitted, IPCP is closed and can be opened again."""
    ppp.start_server("--ipcp-ignore-first-term")
    ppp.start_bbl(ppp={"ipcp": {"conf-request-timeout": 1}})
    ppp.wait_state("Established")
    ppp.bbl.ctrl("ipcp-close", **{"session-id": 1})
    wait_until(lambda: ppp.session()["ipcp-state"] == "Closed", 10, message="IPCP closed")
    assert len(ppp.received("ipcp", TERM_REQ)) == 2
    ppp.bbl.ctrl("ipcp-open", **{"session-id": 1})
    wait_until(lambda: ppp.session()["ipcp-state"] == "Opened", 10, message="IPCP opened again")


def test_ipv4_disabled(ppp):
    """Access interface ipv4 false: IPCP is not negotiated."""
    ppp.start_server()
    ppp.start_bbl(access={"ipv4": False})
    ppp.wait_state("Established")
    assert ppp.received("ipcp", CONF_REQ) == []
    assert ppp.session()["ipcp-state"] == "Disabled"


def test_ipcp_disabled_on_interface(ppp):
    """Access interface ipcp false (globally enabled): IPCP requests of the
    server are answered with protocol-reject."""
    ppp.start_server()
    ppp.start_bbl(access={"ipcp": False})
    ppp.wait_state("Established")
    wait_until(lambda: [p for p in ppp.received("lcp", PROT_REJ) if p.get("protocol") == IPCP], 10,
               message="IPCP protocol-reject")


def test_pado_validation(ppp):
    """A PADO of another AC with wrong host-uniq is ignored, PADI is sent
    again as broadcast and the valid PADO is requested with its cookie."""
    ppp.start_server("--bad-pado-first")
    ppp.start_bbl(pppoe={"host-uniq": True, "discovery-timeout": 1})
    ppp.wait_state("Established")
    padi = ppp.received("padi")
    assert len(padi) >= 2 and all(p["dst"] == "ff:ff:ff:ff:ff:ff" for p in padi), padi
    padr = ppp.received("padr")[0]
    assert padr["dst"] == "02:00:00:00:01:01" and padr["cookie"] == [b"good-cookie".hex()], padr


def test_pado_service_names(ppp):
    """A PADO with several Service-Name tags is accepted if one of them is
    the configured service name (RFC 2516 section 5.2)."""
    ppp.start_server("--service-names", "wanted,other")
    ppp.start_bbl(pppoe={"service-name": "wanted"})
    ppp.wait_state("Established")
    assert ppp.received("padr")[0]["service_names"] == ["wanted"]


def test_chap_no_challenge(ppp):
    """CHAP negotiated, but the server never sends a challenge: the session
    is terminated after the authentication timeout and retries."""
    ppp.start_server("--auth", "chap", "--chap-no-challenge")
    ppp.start_bbl(access={"authentication-protocol": "CHAP"},
                  ppp={"authentication": {"timeout": 1, "retry": 2}})
    ppp.wait_state("Terminated", 20)


def test_protocol_reject_in_auth(ppp):
    """LCP protocol-reject for IPCP during authentication does not
    establish the IPv4 only session before PAP and IPCP are completed."""
    ppp.start_server("--prot-reject-ipcp-in-auth", "--pap-delay", "3")
    ppp.start_bbl(access={"ipv6": False})
    time.sleep(2)
    assert ppp.state() == "PPP Authentication"
    ppp.wait_state("Established")
    assert ppp.session()["ipcp-state"] == "Opened"


def test_unknown_protocol(ppp):
    """A packet of an unsupported PPP protocol (CCP) is answered with LCP
    protocol-reject (RFC 1661 section 5.7)."""
    ppp.start_server("--actions", "1:unknown-protocol")
    ppp.start_bbl()
    ppp.wait_state("Established")
    wait_until(lambda: [p for p in ppp.received("lcp", PROT_REJ) if p.get("protocol") == CCP], 10,
               message="CCP protocol-reject")


def test_unsolicited_term_ack(ppp):
    """An unsolicited LCP terminate-ack restarts LCP (RFC 1661 section 4.1)
    instead of terminating the session."""
    ppp.start_server("--actions", "1:lcp-term-ack")
    ppp.start_bbl()
    ppp.wait_state("Established")
    before = len(ppp.received("lcp", CONF_REQ))
    wait_until(lambda: len(ppp.received("lcp", CONF_REQ)) > before, 10, message="LCP restart")
    ppp.wait_state("Established")
    assert ppp.received("padt") == []
    assert ppp.session()["flapped"] == 0


def test_own_mru_limited(ppp):
    """The own MRU (1500) is limited to 1492 without PPP-Max-Payload (RFC 4638)."""
    ppp.start_server()
    ppp.start_bbl(ppp={"mru": 1500})
    ppp.wait_state("Established")
    assert ppp.received("lcp", CONF_REQ)[0]["mru"] == 1492


def test_outstanding_after_lcp_restart(ppp):
    """A session restarted with lcp-restart is outstanding until it is
    established again."""
    ppp.start_server("--actions", "1:lcp-hold")
    ppp.start_bbl()
    ppp.wait_state("Established")
    assert ppp.counters()["sessions-outstanding"] == 0
    time.sleep(1.5)
    ppp.bbl.ctrl("lcp-restart", **{"session-id": 1})
    wait_until(lambda: ppp.state() == "PPP Link", 5, message="PPP link")
    assert ppp.counters()["sessions-outstanding"] == 1
    ppp.wait_state("Established")
    assert ppp.counters()["sessions-outstanding"] == 0


def test_lcp_reject_after_eighth_option(ppp):
    """An unknown LCP option after the 8th option is rejected alone
    (RFC 1661 section 5.4), the session is established afterwards."""
    ppp.start_server("--lcp-extra")
    ppp.start_bbl()
    ppp.wait_state("Established")
    rejects = ppp.received("lcp", CONF_REJ)
    assert rejects and rejects[0]["options"] == [0x88], rejects


def test_ip6cp_reject_unknown_option(ppp):
    """IP6CP rejects the IPv6-Compression-Protocol option instead of
    acknowledging it (RFC 5072 section 4)."""
    ppp.start_server("--ip6cp-compression")
    ppp.start_bbl(access={"ipv6": True})
    wait_until(lambda: ppp.session()["ip6cp-state"] == "Opened", 20, message="IP6CP opened")
    rejects = ppp.received("ip6cp", CONF_REJ)
    assert rejects and rejects[0]["options"] == [2], rejects
    acks = [p for p in ppp.received("ip6cp", CONF_ACK) if 2 in p["options"]]
    assert not acks, acks


def test_ipcp_oversized_request(ppp):
    """An IPCP request with more option bytes than can be echoed is not
    acknowledged with other options (RFC 1661 section 5.2)."""
    ppp.start_server("--ipcp-oversized")
    ppp.start_bbl()
    wait_until(lambda: len([p for p in ppp.received("ipcp", CONF_REQ)]) >= 2, 20, message="IPCP requests")
    time.sleep(3)
    assert not ppp.received("ipcp", CONF_ACK), ppp.received("ipcp")


def test_ncp_unknown_code(ppp):
    """An unknown IPCP code is answered with Code-Reject (RFC 1661
    section 5.6)."""
    ppp.start_server("--actions", "1:ipcp-unknown-code")
    ppp.start_bbl()
    ppp.wait_state("Established")
    wait_until(lambda: ppp.received("ipcp", CODE_REJ), 10, message="IPCP code-reject")


def test_pap_identifier(ppp):
    """Retransmitted PAP requests have a new Identifier (RFC 1334
    section 2.2.1)."""
    ppp.start_server("--pap-delay", "3")
    ppp.start_bbl(ppp={"authentication": {"timeout": 1, "retry": 10}})
    wait_until(lambda: len(ppp.received("pap", 1)) >= 2, 10, message="PAP retransmission")
    ids = [p["id"] for p in ppp.received("pap", 1)]
    assert len(set(ids)) == len(ids), ids


def test_relay_session_id(ppp):
    """The Relay-Session-Id of the PADO is returned in the PADR (RFC 2516
    appendix A)."""
    ppp.start_server("--relay-session-id")
    ppp.start_bbl()
    ppp.wait_state("Established")
    padr = ppp.received("padr")
    assert padr and padr[0]["relay_session_id"] == ["relay-012345"], padr
