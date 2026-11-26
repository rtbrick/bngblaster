ANCP adjacencies are configured under **ancp-sessions**. Each adjacency uses a
network interface with a static IPv4 address and connects to an ANCP peer over TCP
(default port 6068). For a VLAN sub-interface, use the generated interface name
``<interface>:<vlan>`` (for example, ``eth0:16``).

.. code-block:: json

    {
        "interfaces": {
            "network": [
                { "interface": "eth0", "vlan": 16, "address": "192.0.2.2/30" },
                { "interface": "eth0", "vlan": 17, "address": "192.0.2.6/30" }
            ]
        },
        "ancp-sessions": [
            {
                "ancp-session-id": 1,
                "network-interface": "eth0:16",
                "peer-address": "192.0.2.1"
            },
            {
                "ancp-session-id": 2,
                "network-interface": "eth0:17",
                "peer-address": "192.0.2.5"
            }
        ],
        "ancp-line-profiles": [
            {
                "ancp-line-profile-id": 1,
                "pon-access-line-version": "DRAFT-LIHAWI-01",
                "dsl-type": 5,
                "act-up": 2000,
                "act-down": 16000
            },
            {
                "ancp-line-profile-id": 2,
                "pon-access-line-version": "DRAFT-LIHAWI-04",
                "dsl-type": 5,
                "act-up": 4000,
                "act-down": 32000
            }
        ]
    }

An IPoE access entry selects an adjacency with **ancp-session-id** and its
attributes with **ancp-line-profile-id**:

.. code-block:: json

    {
        "interfaces": {
            "access": [{
                "interface": "eth1",
                "type": "ipoe",
                "outer-vlan": 100,
                "address": "10.0.1.1",
                "gateway": "10.0.0.1",
                "agent-circuit-id": "ANCP-{session-global}",
                "ancp-session-id": 1,
                "ancp-line-profile-id": 1
            }]
        }
    }

The access entry's rendered
**agent-circuit-id** is sent unchanged as the ANCP Access-Loop-Circuit-ID; no
separate ANCP circuit identifier is configured. Multiple access entries can select
different adjacencies, including adjacencies on different VLANs of the same
physical interface.

The attributes supported by **ancp-line-profiles** are the same as those listed
for **access-line-profiles**, including the PON extension attributes. Draft 01 and
Draft 04 are selectable through **pon-access-line-version**.
