.. _pppoe:

PPPoE
-----

Emulating PPP over Ethernet (PPPoE) sessions was initial
use case of the BNG Blaster supporting 1:1 and N:1 VLAN
mode.

The BNG Blaster concept is leaned to the idea of fail-fast.
Therefore PPPoE sessions may not be established if not all 
expected conditions are fulfilled. PPPoE sessions become 
established only if all enabled network protocols
(IPCP and IP6CP) are negotiated successfully. 
If IPCP is configured to request two DNS servers, 
it fails if only one is returned.

The BNG Blaster is not optimized for robustness. The opposite is 
the case, to ensure it failed if the device under test behaves faulty. 

Configuration
~~~~~~~~~~~~~

Following is a basic PPPoE configuration example.

.. code-block:: json

    {
        "interfaces": {
            "network": {
                "interface": "eth2",
                "address": "10.0.0.1/24",
                "gateway": "10.0.0.2",
                "address-ipv6": "fc66:1337:7331::1/64",
                "gateway-ipv6": "fc66:1337:7331::2"
            },
            "access": [
                {
                    "interface": "eth1",
                    "type": "pppoe",
                    "outer-vlan-min": 1000,
                    "outer-vlan-max": 1999,
                    "inner-vlan-min": 1,
                    "inner-vlan-max": 4049,
                    "authentication-protocol": "PAP"
                },
                {
                    "interface": "eth1",
                    "type": "pppoe",
                    "outer-vlan-min": 2000,
                    "outer-vlan-max": 2999,
                    "inner-vlan-min": 1,
                    "inner-vlan-max": 4049,
                    "authentication-protocol": "CHAP"
                }
            ]
        },
        "sessions": {
            "count": 1000,
            "session-time": 0,
            "max-outstanding": 800,
            "start-rate": 400,
            "stop-rate": 400
        },
        "pppoe": {
            "reconnect": true,
            "discovery-timeout": 3,
            "discovery-retry": 10
        },
        "ppp": {
            "mru": 1492,
            "authentication": {
                "username": "user{session-global}@rtbrick.com",
                "password": "test",
                "timeout": 5,
                "retry": 30
            },
            "lcp": {
                "conf-request-timeout": 1,
                "conf-request-retry": 10,
                "keepalive-interval": 30,
                "keepalive-retry": 3
            },
            "ipcp": {
                "enable": true,
                "request-ip": true,
                "request-dns1": true,
                "request-dns2": true,
                "conf-request-timeout": 1,
                "conf-request-retry": 10
            },
            "ip6cp": {
                "enable": true,
                "conf-request-timeout": 1,
                "conf-request-retry": 10
            }
        },
        "dhcpv6": {
            "enable": true,
            "rapid-commit": true
        },
        "access-line": {
            "agent-remote-id": "DEU.RTBRICK.{session-global}",
            "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:{session-global}",
            "rate-up": 1024,
            "rate-down": 16384
        },
        "session-traffic": {
            "ipv4-pps": 1,
            "ipv6-pps": 1,
            "ipv6pd-pps": 1
        }
    }

PPPoE
^^^^^
.. include:: ../configuration/pppoe.rst

PPP
^^^
.. include:: ../configuration/ppp.rst

PPP Authentication
^^^^^^^^^^^^^^^^^^
.. include:: ../configuration/ppp_authentication.rst

PPP LCP
^^^^^^^
.. include:: ../configuration/ppp_lcp.rst

PPP IPCP (IPv4)
^^^^^^^^^^^^^^^
.. include:: ../configuration/ppp_ipcp.rst

PPP IP6CP (IPv6)
^^^^^^^^^^^^^^^^
.. include:: ../configuration/ppp_ip6cp.rst

LCP Vendor Extension
~~~~~~~~~~~~~~~~~~~~

This chapter refers to RFC 2153 PPP vendor extensions.

Per default, all LCP vendor-specific requests will be rejected sending a
LCP code-reject message. With the LCP option ``ignore-vendor-specific`` 
enabled in the configuration, those messages will be ignored as required 
to emulate different CPE behaviors.

The LCP option ``connection-status-message`` allows to accept LCP vendor requests
with any OUI if kind is set to ``1`` by responding with vendor request of
kind ``2``. The OUI from the request is copied to the response in this case.
The value from the request is stored in the session as ``connection-status-message``.

PPPoE Commands
~~~~~~~~~~~~~~

The :ref:`command <api>` ``session-info session-id <id>`` provides
detailed information for PPPoE sessions.

``$ sudo bngblaster-cli run.sock session-info session-id 1 | jq .``

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "session-information": {
            "type": "pppoe",
            "session-id": 1,
            "session-state": "Established",
            "interface": "eth1",
            "outer-vlan": 1000,
            "inner-vlan": 1,
            "mac": "02:00:00:00:00:01",
            "username": "user1@rtbrick.com",
            "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:1",
            "agent-remote-id": "DEU.RTBRICK.1",
            "lcp-state": "Opened",
            "ipcp-state": "Opened",
            "ip6cp-state": "Opened",
            "ipv4-address": "10.100.128.0",
            "ipv4-dns1": "10.0.0.3",
            "ipv4-dns2": "10.0.0.4",
            "ipv6-prefix": "fc66:1000:1::/64",
            "ipv6-delegated-prefix": "fc66:2000::/56",
            "ipv6-dns1": "fc66::3",
            "ipv6-dns2": "fc66::4",
            "dhcpv6-state": "Bound",
            "dhcpv6-dns1": "fc66::3",
            "dhcpv6-dns2": "fc66::4",
            "tx-packets": 10036,
            "rx-packets": 10083,
            "rx-fragmented-packets": 0,
            "session-traffic": {
                "total-flows": 6,
                "verified-flows": 6,
                "downstream-ipv4-flow-id": 2,
                "downstream-ipv4-tx-packets": 13,
                "downstream-ipv4-rx-packets": 13,
                "downstream-ipv4-rx-first-seq": 1,
                "downstream-ipv4-loss": 0,
                "downstream-ipv4-wrong-session": 0,
                "upstream-ipv4-flow-id": 1,
                "upstream-ipv4-tx-packets": 13,
                "upstream-ipv4-rx-packets": 13,
                "upstream-ipv4-rx-first-seq": 1,
                "upstream-ipv4-loss": 0,
                "upstream-ipv4-wrong-session": 0,
                "downstream-ipv6-flow-id": 4,
                "downstream-ipv6-tx-packets": 13,
                "downstream-ipv6-rx-packets": 13,
                "downstream-ipv6-rx-first-seq": 1,
                "downstream-ipv6-loss": 0,
                "downstream-ipv6-wrong-session": 0,
                "upstream-ipv6-flow-id": 3,
                "upstream-ipv6-tx-packets": 13,
                "upstream-ipv6-rx-packets": 13,
                "upstream-ipv6-rx-first-seq": 1,
                "upstream-ipv6-loss": 0,
                "upstream-ipv6-wrong-session": 0,
                "downstream-ipv6pd-flow-id": 6,
                "downstream-ipv6pd-tx-packets": 13,
                "downstream-ipv6pd-rx-packets": 13,
                "downstream-ipv6pd-rx-first-seq": 1,
                "downstream-ipv6pd-loss": 0,
                "downstream-ipv6pd-wrong-session": 0,
                "upstream-ipv6pd-flow-id": 5,
                "upstream-ipv6pd-tx-packets": 13,
                "upstream-ipv6pd-rx-packets": 13,
                "upstream-ipv6pd-rx-first-seq": 1,
                "upstream-ipv6pd-loss": 0,
                "upstream-ipv6pd-wrong-session": 0
            }
        }
    }