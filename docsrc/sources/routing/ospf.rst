.. _ospf:

OSPF
----

OSPF (Open Shortest Path First) is a dynamic Interior Gateway Protocol (IGP) 
widely used in large computer networks. It efficiently determines the best paths 
for data transmission, adapting to network changes in real-time. OSPF's link-state 
algorithm builds a detailed network map, optimizing data delivery and 
ensuring network stability.

There are two versions of OSPF: OSPFv2 and OSPFv3. OSPFv2 is used for IPv4 networks, 
while OSPFv3 is designed specifically for IPv6 networks.

The BNG Blaster can emulate multiple OSPF instances of both versions, OSPFv2 and OSPFv3. 

An OSPF instance is a virtual OSPF node with one or more network interfaces attached. Such a
node behaves like a "real router" including database synchronization and  flooding. Every 
instance generates a ``self`` originated type 1 router LSA describing the node itself. 


Configuration
~~~~~~~~~~~~~

Following an example OSPF configuration with two instances 
attached to two network interfaces.

.. code-block:: json

    {
        "interfaces": {
            "network": [
                {
                    "interface": "eth1",
                    "address": "10.0.1.2/30",
                    "gateway": "10.0.1.1",
                    "address-ipv6": "fc66:1337:7331:1::2/64",
                    "gateway-ipv6": "fc66:1337:7331:1::1",
                    "ospfv2-instance-id": 1,
                    "ospfv2-type": "p2p",
                    "ospfv3-instance-id": 2,
                    "ospfv3-type": "p2p"
                },
                {
                    "interface": "eth2",
                    "address": "10.0.2.2/24",
                    "gateway": "10.0.2.1",
                    "ospfv2-instance-id": 1,
                    "ospfv2-type": "broadcast"
                }
            ]
        },
        "ospf": [
            {
                "instance-id": 1,
                "version": 2,
                "router-id": "1.1.1.1",
                "hostname": "BBLv4"
            },
            {
                "instance-id": 2,
                "version": 3,
                "router-id": "1.1.1.1",
                "hostname": "BBLv6"
            }
        ]
    }

.. include:: ../configuration/ospf.rst

Interfaces
~~~~~~~~~~~

Neighbors
~~~~~~~~~

Database
~~~~~~~~

Flooding
~~~~~~~~

Limitations
~~~~~~~~~~~

MRT Files
~~~~~~~~~

The BNG Blaster can load LSA updates from a MRT file as defined in 
[RFC6396](https://datatracker.ietf.org/doc/html/rfc6396).

.. code-block:: none

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Timestamp                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             Type              |            Subtype            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             Length                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Message... (variable)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The message field contains the complete OSPF LS Update PDU including 
the OSPF common header starting with version field. 

Those files can be loaded at startup via the configuration option 
``"ospf": { "external": { "mrt-file": "<file>" } }`` or alternative
via ``ospf-load-mrt`` :ref:`command <api>`. 

``$ sudo bngblaster-cli run.sock ospf-load-mrt file test.mrt instance 1``

LSA Update Command
~~~~~~~~~~~~~~~~~~

LSA Update via Scapy 
~~~~~~~~~~~~~~~~~~~~

LSPGEN
~~~~~~