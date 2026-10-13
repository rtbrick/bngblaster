"""
BNG Blaster DHCPv6 over PPPoE

A single BNG Blaster instance runs an A10NSP server and PPPoE clients
on both ends of a veth pair. The A10NSP server answers DHCPv6 IA_NA and
IA_PD with fixed mock values.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import ipaddress

import pytest

from helpers import BngBlaster, wait_until

SESSIONS = 10
EXIT_TIMEOUT = 30
IA_NA_ADDRESS = "fc01:100::2"  # mock_ipv6_ia_na
IA_PD_PREFIX = "fc01:200::/56"  # mock_ipv6_ia_pd


@pytest.fixture
def bbl(local_veth, processes, tmp_path):
    def start(config):
        instance = BngBlaster(local_veth.ns, tmp_path).start(config, logging=("info", "dhcp", "ip"))
        processes.append(instance)
        return instance
    return start


def pppoe_config(veth, access):
    return {
        "interfaces": {
            "a10nsp": [{"interface": veth.if1}],
            "access": [dict({
                "interface": veth.if2,
                "type": "pppoe",
                "outer-vlan-min": 1,
                "outer-vlan-max": 4000,
                "inner-vlan": 7
            }, **access)]
        },
        "sessions": {"count": SESSIONS},
        "dhcpv6": {"enable": True},
        "session-traffic": {"ipv4-pps": 1, "ipv6-pps": 1, "ipv6pd-pps": 1}
    }


def counters(bbl):
    return bbl.ctrl("session-counters")["session-counters"]


def wait_established(bbl):
    wait_until(lambda: counters(bbl)["sessions-established"] == SESSIONS and
               counters(bbl)["dhcpv6-sessions-established"] == SESSIONS, 30,
               message="all sessions and DHCPv6 established")
    # IPv4, IPv6 and IPv6PD session traffic in both directions
    wait_until(lambda: counters(bbl)["session-traffic-flows-verified"] == 6 * SESSIONS, 15,
               message="session traffic verified")


def session_info(bbl, session_id):
    return bbl.ctrl("session-info", **{"session-id": session_id})["session-info"]


def test_ia_na(local_veth, bbl):
    """IA_NA address replaces the SLAAC address."""
    instance = bbl(pppoe_config(local_veth, {"dhcpv6-ia-na": True}))
    wait_established(instance)

    for session_id in range(1, SESSIONS + 1):
        info = session_info(instance, session_id)
        assert info["dhcpv6-state"] == "Bound"
        assert info["ipv6-address"] == IA_NA_ADDRESS
        assert info["ipv6-delegated-prefix"] == IA_PD_PREFIX
    assert instance.terminate(EXIT_TIMEOUT) == 0


def test_ia_na_default_disabled(local_veth, bbl):
    """Without dhcpv6-ia-na, PPPoE requests IA_PD only and uses SLAAC."""
    instance = bbl(pppoe_config(local_veth, {}))
    wait_established(instance)

    for session_id in range(1, SESSIONS + 1):
        info = session_info(instance, session_id)
        assert info["dhcpv6-state"] == "Bound"
        assert info["ipv6-address"] != IA_NA_ADDRESS
        assert ipaddress.ip_address(info["ipv6-address"]) in ipaddress.ip_network(info["ipv6-prefix"])
        assert info["ipv6-delegated-prefix"] == IA_PD_PREFIX
    assert instance.terminate(EXIT_TIMEOUT) == 0
