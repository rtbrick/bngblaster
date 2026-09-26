"""
Shared setup for BNG Blaster against GoBGP tests

Namespace A runs the BNG Blaster (10.0.0.1, fc00::1), namespace B
runs GoBGP on the kernel interface (10.0.0.2, fc00::2).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import base64

import helpers
from helpers import BngBlaster, GoBgp, wait_until

BBL_ADDRESS = "10.0.0.1"
BBL_ADDRESS6 = "fc00::1"
BBL_AS = 65000
GOBGP_ADDRESS = "10.0.0.2"
GOBGP_ADDRESS6 = "fc00::2"
GOBGP_AS = 4200000001  # 4-octet AS to verify the capability parsing

GOBGP_FAMILIES = {
    "ipv4-unicast": "ipv4-unicast",
    "ipv6-unicast": "ipv6-unicast",
    "evpn": "l2vpn-evpn",
}


def gobgp_config(families=("ipv4-unicast", "ipv6-unicast"), passive=True,
                 router_id=GOBGP_ADDRESS, md5=None, ao=None):
    """Return GoBGP TOML config. The ao dict contains algorithm, key,
    send_id (GoBGP KeyID) and receive_id (KeyID expected from BNG Blaster)."""
    lines = [
        "[global.config]",
        "  as = %d" % GOBGP_AS,
        '  router-id = "%s"' % router_id,
        '  local-address-list = ["%s"]' % GOBGP_ADDRESS,
    ]
    if ao:
        lines += [
            "[[keychains]]",
            "  [keychains.config]",
            '    name = "bbl"',
            "  [[keychains.keys]]",
            "    [keychains.keys.config]",
            "      key-id = %d" % ao["send_id"],
            "      receive-id = %d" % ao["receive_id"],
            '      crypto-algorithm = "%s"' % ao["algorithm"],
            '      secret-key = "%s"' % base64.b64encode(ao["key"].encode()).decode(),
        ]
    lines += [
        "[[neighbors]]",
        "  [neighbors.config]",
        '    neighbor-address = "%s"' % BBL_ADDRESS,
        "    peer-as = %d" % BBL_AS,
    ]
    if md5:
        lines.append('    auth-password = "%s"' % md5)
    lines += [
        "  [neighbors.transport.config]",
        '    local-address = "%s"' % GOBGP_ADDRESS,
        "    passive-mode = %s" % ("true" if passive else "false"),
        "  [neighbors.timers.config]",
        "    connect-retry = 1",
    ]
    if ao:
        lines += [
            "  [neighbors.tcp-ao.config]",
            '    keychain = "bbl"',
            "    send-id = %d" % ao["send_id"],
        ]
    for family in families:
        lines += [
            "  [[neighbors.afi-safis]]",
            "    [neighbors.afi-safis.config]",
            '      afi-safi-name = "%s"' % GOBGP_FAMILIES[family],
        ]
    return "\n".join(lines) + "\n"


def bbl_config(ifname, families=("ipv4-unicast", "ipv6-unicast"), bgp=None, streams=None):
    session = {
        "local-address": BBL_ADDRESS,
        "peer-address": GOBGP_ADDRESS,
        "local-as": BBL_AS,
        "peer-as": GOBGP_AS,
        "id": BBL_ADDRESS,
        "hold-time": 30,
        "learn-routes": True,
        "family": list(families),
    }
    session.update(bgp or {})
    config = {
        "interfaces": {
            "network": {
                "interface": ifname,
                "address": BBL_ADDRESS + "/24",
                "gateway": GOBGP_ADDRESS,
                "address-ipv6": BBL_ADDRESS6 + "/64",
                "gateway-ipv6": GOBGP_ADDRESS6
            }
        },
        "bgp": [session]
    }
    if streams:
        config["streams"] = streams
        config["traffic"] = {"autostart": False}
    return config


class BgpSetup:
    """Start GoBGP in namespace B and the BNG Blaster in namespace A."""

    def __init__(self, topology, processes, tmp_path):
        self.topology = topology
        self.processes = processes
        self.tmp_path = tmp_path
        self.gobgp = None
        self.bbl = None
        helpers.kernel_address(topology.b, topology.if_b,
                               GOBGP_ADDRESS + "/24", GOBGP_ADDRESS6 + "/64")

    def start(self, gobgp=None, bbl=None, families=("ipv4-unicast", "ipv6-unicast")):
        self.gobgp = GoBgp(self.topology.b, self.tmp_path).start(
            gobgp_config(families=families, **(gobgp or {})))
        self.processes.append(self.gobgp)
        self.bbl = BngBlaster(self.topology.a, self.tmp_path).start(
            bbl_config(self.topology.if_a, families=families, **(bbl or {})),
            logging=("info", "bgp"))
        self.processes.append(self.bbl)
        return self

    def bbl_session(self):
        return self.bbl.ctrl("bgp-sessions")["bgp-sessions"][0]

    def established(self):
        return (self.bbl_session()["state"] == "established" and
                self.gobgp.session_established(BBL_ADDRESS))

    def wait_established(self, timeout=30):
        wait_until(self.established, timeout, message="BGP session established")

    def assert_not_established(self, duration=15):
        """Session must not come up within duration."""
        try:
            wait_until(lambda: self.bbl_session()["state"] == "established" or
                       self.gobgp.session_established(BBL_ADDRESS),
                       duration, message="BGP session")
        except TimeoutError:
            return
        raise AssertionError("BGP session established unexpectedly")

    def bbl_routes(self, family):
        sessions = self.bbl.ctrl("bgp-routes", family=family)["bgp-routes"]
        return sessions[0]["routes"] if sessions else []

    def bbl_evpn_routes(self, **arguments):
        sessions = self.bbl.ctrl("bgp-evpn-routes", **arguments)["bgp-evpn-routes"]
        return sessions[0]["routes"] if sessions else []

    def teardown(self):
        assert self.bbl.terminate(30) == 0
        wait_until(lambda: not self.gobgp.session_established(BBL_ADDRESS), 10,
                   message="GoBGP session down after BNG Blaster teardown")
