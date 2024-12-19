.. _icmp:

ICMP
====

The BNG Blaster responds to ICMP echo-requests (PING) on all interfaces,
allowing you to ping PPPoE and IPoE sessions, as well as network interfaces. 
When it comes to network interfaces, the BNG Blaster replies to any request 
with matching MAC address. This means you can ping all advertised prefixes 
over those interfaces.

Beyond simply responding to echo-requests, the BNG Blaster also includes 
an ICMP client. With this client, you can initiate ICMP echo-requests (PING) 
from PPPoE and IPoE sessions and network interfaces. Each client instance 
maintains its result tracking. Consequently, if the client receives 
ICMP unreachable, TTL exceeded, or fragmentation needed messages, these are 
properly logged and made accessible through the associated ICMP commands.

ICMP Client
-----------

Following is a basic ICMP client configuration example.

.. code-block:: json

    {
        "interfaces": {
            "network": [
                {
                    "interface": "eth1",
                    "address": "10.0.1.2/24",
                    "gateway": "10.0.1.1",
                    "vlan": 10
                }
            ],
            "access": [
                {
                    "interface": "eth2",
                    "outer-vlan": 7,
                    "icmp-client-group-id": 1
                }
            ]
        },
        "icmp-client": [
            {
                "__comment__": "ping from session"
                "icmp-client-group-id": 1,
                "destination-address": "10.10.10.10"
            },
            {
                "__comment__": "ping from network interface"
                "network-interface": "eth1:10",
                "destination-address": "10.0.1.1"
            }
        ]
    }

.. include:: configuration/icmp_client.rst

The association between the ICMP client and sessions is established through 
the use of the ICMP client group identifier (icmp-client-group-id). Multiple 
ICMP clients can be defined with the same ICMP client group identifier. 

For instance, if you define 4 ICMP clients with the same ICMP client group 
identifier and bind them to 100 sessions each, the BNG Blaster will generate 
a total of 400 ICMP client instances.

It is also possible to setup ICMP clients over network interfaces, in this
case the network interface name (network-interface) must be defined instead 
of the ICMP client group identifier (icmp-client-group-id). 

It is mandatory to set either ICMP client group identifier or network interface
but only one as those attributes are mutually exclusive. 

