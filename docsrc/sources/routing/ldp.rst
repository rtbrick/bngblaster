.. _ldp:

LDP
---

The Label Distribution Protocol (LDP) is a protocol defined for
distributing labels.

Configuration
~~~~~~~~~~~~~

Following an example LDP configuration with one instance 
attached to two network interfaces.

.. code-block:: json

    {
        "interfaces": {
            "network": [
                {
                    "interface": "eth1",
                    "address": "10.0.1.2/24",
                    "gateway": "10.0.1.1",
                    "address-ipv6": "fc66:1337:7331:1::2/64",
                    "gateway-ipv6": "fc66:1337:7331:1::1",
                    "ldp-instance-id": 1,
                },
                {
                    "interface": "eth2",
                    "address": "10.0.2.2/24",
                    "gateway": "10.0.2.1",
                    "address-ipv6": "fc66:1337:7331:2::2/64",
                    "gateway-ipv6": "fc66:1337:7331:2::1",
                    "ldp-instance-id": 2
                }
            ]
        },
        "ldp": [
            {
                "instance-id": 1,
                "lsr-id": "10.10.10.11",
                "hostname": "R1",
            },
            {
                "instance-id": 1,
                "lsr-id": "10.10.10.12",
                "hostname": "R2",
            }
        ]
    }

.. include:: ../configuration/ldp.rst

Limitations
~~~~~~~~~~~

LDP authentication is currently not supported but already 
planned as an enhancement in one of the next releases. 

RAW Update Files
~~~~~~~~~~~~~~~~

The BNG Blaster can inject LDP PDU from a pre-compiled 
RAW update file into the defined sessions. A RAW update file is not
more than a pre-compiled binary stream of LDP PDU.

.. code-block:: none

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Version                      |         PDU Length            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         LDP Identifier                        |
    +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .                         LDP Messages
    .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Version                      |         PDU Length            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         LDP Identifier                        |
    +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .                         LDP Messages
    .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
