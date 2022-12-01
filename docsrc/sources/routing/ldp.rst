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
                    "ldp-instance-id": 1
                }
            ]
        },
        "ldp": [
            {
                "instance-id": 1,
                "lsr-id": "10.10.10.10",
                "hostname": "R1",
            }
        ]
    }

.. include:: ../configuration/ldp.rst

The support for multiple instances allows different use cases. One example might 
be to create two instances connected to the device or network under test. Now 
inject an LSP on one instance and check if learned over the tested network on 
the other instance. 

Peers
~~~~~

Database
~~~~~~~~

Limitations
~~~~~~~~~~~

