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

An IPoE or PPPoE access entry selects an adjacency with **ancp-session-id** and
its attributes with **ancp-line-profile-id**:

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

The access entry's rendered **agent-circuit-id** is sent unchanged as the ANCP
Access-Loop-Circuit-ID; no separate ANCP circuit identifier is configured.
Access sessions bound to an adjacency start only after this adjacency is
established. **port-up-trigger** in **ancp-sessions** selects when Port-Up
is sent for the bound sessions:

``adjacency`` (default)
    Port-Up for all bound sessions directly after adjacency up; each session
    starts (e.g. PPPoE PADI) only after its Port-Up was sent.
``established``
    Port-Up per session when it is established, Port-Down when it leaves that
    state.
``all-established``
    Port-Up for all bound sessions once all of them are established.
``count``
    Port-Up for all bound sessions once **port-up-count** of them are established.
``delay``
    Port-Up for all bound sessions **port-up-delay** seconds after adjacency up.

Except for ``established``, a port stays up if its session is terminated and
reconnects. On teardown, Port-Down is sent for all ports that are up. If the
adjacency fails, all ports are considered down; after the adjacency is up
again, the trigger is evaluated again.

The subscriber IP may be assigned dynamically by
RADIUS; ANCP uses the configured Circuit-ID and line profile, not a static
access IP. Multiple access entries can select different adjacencies, including
adjacencies on different VLANs of the same physical interface.

The attributes supported by **ancp-line-profiles** are the same as those listed
for **access-line-profiles**, including the PON extension attributes. Draft 01 and
Draft 04 are selectable through **pon-access-line-version**.

The access node also advertises RFC 6320 capability **0x0004** for DSL remote
loopback. A Port Management request using function **9** is matched to an established
IPoE or PPPoE session by its Access-Loop-Circuit-ID and ANCP session. A
successful response is simulated locally and explicitly states that no physical
loopback was performed; the OAM-Loopback-Test-Parameters TLV is removed as
required by RFC 6320. Requests for an unknown circuit ID or invalid loop count
receive the corresponding failure response. This supports the RFC 6320 DSL
technology type; PON-specific OAM is not emulated. For interoperability with
BNGJ08, OAM requests also accept its observed wire encodings: a zero-valued
repeated Port Management message-type subfield, a general-header length of 12,
and zero alignment padding counted in the Access-Loop-Circuit-ID and
OAM-Loopback-Test-Parameters TLV lengths.
