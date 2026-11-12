.. _bfd:

BFD
---

Bidirectional Forwarding Detection (BFD) detects failures of the forwarding
path between two systems within milliseconds. Routing protocols use BFD to
detect a failed neighbor much faster than with their own hello and hold
timers, which is required for fast convergence and failover.

The BNG Blaster implements BFD in asynchronous mode as defined in
:rfc:`5880` for single-hop sessions (:rfc:`5881`, UDP port 3784) and
multi-hop sessions (:rfc:`5883`, UDP port 4784) over IPv4 and IPv6.
BFD sessions are either configured statically or created by the routing
protocols ISIS, OSPFv2, OSPFv3, BGP and LDP. This allows testing of the
BFD implementation of the device under test (DUT) and of its failover
behavior, triggered by disabling BFD sessions or changing timers via
control commands.

The echo function and demand mode are not supported.

Configuration
~~~~~~~~~~~~~

BFD timers and authentication are defined in BFD profiles,
which are referenced by static sessions and routing protocols.
The following example shows a static single-hop session with
100 ms intervals and a multi-hop session with the default profile
(1000 ms intervals, multiplier 3).

.. code-block:: json

    {
        "interfaces": {
            "network": [
                {
                    "interface": "eth1",
                    "address": "10.0.1.2/24",
                    "gateway": "10.0.1.1"
                }
            ]
        },
        "bfd": [
            {
                "bfd-profile-id": 1,
                "tx-interval": 100,
                "rx-interval": 100,
                "multiplier": 3
            }
        ],
        "bfd-sessions": [
            {
                "network-interface": "eth1",
                "peer-ipv4-address": "10.0.1.1",
                "bfd-profile-id": 1,
                "name": "DUT"
            },
            {
                "network-interface": "eth1",
                "local-ipv4-address": "10.0.1.2",
                "peer-ipv4-address": "10.10.10.1",
                "multihop": true
            }
        ]
    }

**BFD Profile**

.. include:: ../configuration/bfd.rst

**BFD Session**

.. include:: ../configuration/bfd_sessions.rst

Routing Protocols
~~~~~~~~~~~~~~~~~

BFD is enabled for a routing protocol by referencing a BFD profile.
The BFD session is created when the adjacency or session of the protocol
comes up and deleted when it goes down. If the BFD session goes from Up to
Down, the protocol is brought down immediately. A BFD session going down
because the peer signals AdminDown does not bring the protocol down
(:rfc:`5882`).

+-------------+-----------------------------------+----------------------+-------------------------------------+
| Protocol    | Configuration                     | BFD Session          | BFD Down                            |
+=============+===================================+======================+=====================================+
| ISIS        | ``isis-bfd-profile-id``           | Adjacency up,        | Adjacency down                      |
|             | (network interface)               | single-hop           |                                     |
+-------------+-----------------------------------+----------------------+-------------------------------------+
| OSPFv2      | ``ospfv2-bfd-profile-id``         | Neighbor 2-Way       | Neighbor down                       |
|             | (network interface)               | or higher,           |                                     |
|             |                                   | single-hop           |                                     |
+-------------+-----------------------------------+----------------------+-------------------------------------+
| OSPFv3      | ``ospfv3-bfd-profile-id``         | Neighbor 2-Way       | Neighbor down                       |
|             | (network interface)               | or higher,           |                                     |
|             |                                   | single-hop           |                                     |
+-------------+-----------------------------------+----------------------+-------------------------------------+
| BGP         | ``bfd-profile-id``,               | Established,         | NOTIFICATION Cease with subcode     |
|             | ``bfd-multihop`` (BGP session)    | single- or multi-hop | BFD Down (:rfc:`9384`)              |
+-------------+-----------------------------------+----------------------+-------------------------------------+
| LDP         | ``ldp-bfd-profile-id``            | Operational,         | Session closed with                 |
|             | (network interface)               | single-hop           | Shutdown notification               |
+-------------+-----------------------------------+----------------------+-------------------------------------+
| LDP         | ``bfd-profile-id``                | Operational,         | Session closed with                 |
| (targeted)  | (targeted neighbor)               | multi-hop            | Shutdown notification               |
+-------------+-----------------------------------+----------------------+-------------------------------------+

The peer address of the BFD session is:

* ISIS: one session per address family (:rfc:`6213`) to the IPv4 interface address
  of the neighbor (hello TLV 132, if the network interface has an IPv4 address) and
  to the IPv6 link-local address of the neighbor (hello TLV 232). Implementations
  using only one address family for BFD (e.g. FRR uses IPv6 on dual-stack circuits)
  leave the other session down, which does not affect the adjacency.
* OSPFv2: the interface address of the neighbor.
* OSPFv3: the link-local address of the neighbor.
* BGP: the peer address of the session. Without ``bfd-multihop``, the session is
  single-hop if the peer address is in a connected network of the network interface
  (or an IPv6 link-local address), otherwise multi-hop.
* LDP: the source address of the hello which initialized the LDP session (link
  hellos) or the targeted neighbor address (targeted hellos, multi-hop).

Multiple protocols may share one BFD session to the same peer, for example
OSPFv2 and ISIS or ISIS level 1 and level 2. A shared session uses the profile
of the protocol which created it, and all protocols are brought down if it goes
down. A static session to the same peer is shared as well.

.. code-block:: json

    {
        "interfaces": {
            "network": [
                {
                    "interface": "eth1",
                    "address": "10.0.1.2/24",
                    "gateway": "10.0.1.1",
                    "isis-instance-id": 1,
                    "isis-bfd-profile-id": 1,
                    "ldp-instance-id": 1,
                    "ldp-bfd-profile-id": 1
                }
            ]
        },
        "bfd": [
            {
                "bfd-profile-id": 1,
                "tx-interval": 50,
                "rx-interval": 50,
                "multiplier": 3
            }
        ],
        "isis": [
            {
                "instance-id": 1,
                "system-id": "1921.6800.1001"
            }
        ],
        "ldp": [
            {
                "instance-id": 1,
                "lsr-id": "10.10.10.11"
            }
        ],
        "bgp": [
            {
                "network-interface": "eth1",
                "local-ipv4-address": "10.0.1.2",
                "peer-ipv4-address": "10.0.1.1",
                "local-as": 65001,
                "peer-as": 65001,
                "bfd-profile-id": 1
            }
        ]
    }

Behavior
~~~~~~~~

* Each session has a unique non-zero local discriminator. Received packets are
  demultiplexed by the your discriminator field, or by interface, source and
  destination address if it is zero (:rfc:`5880#section-6.3`).
* All reception checks of :rfc:`5880#section-6.8.6` are applied. Single-hop
  packets are accepted with TTL or hop limit 255 only, multi-hop packets with
  at least ``min-ttl`` (default 254). All packets are sent with TTL or hop limit 255
  and a source port between 49152 and 65535, which is unique per session.
* While a session is not Up, the desired min TX interval is at least one second.
  Changed timers of a session in state Up (e.g. after the session came up or via
  ``bfd-session-update``) start a poll sequence. The new TX interval is used after
  the poll sequence terminated if it is longer, a shorter one immediately
  (:rfc:`5880#section-6.8.3`).
* The TX interval is reduced by a random jitter of 0 to 25 % (10 to 25 % with
  multiplier 1), the detection time is the remote multiplier times the larger of
  the local required min RX interval and the remote desired min TX interval.
* The local diagnostic is set to *control detection time expired* (1),
  *neighbor signaled session down* (3) or *administratively down* (7).
* With authentication, the sequence number of keyed MD5 and SHA1 is incremented
  with every packet. Packets with an unexpected authentication type, key ID,
  key or a sequence number outside of the window of :rfc:`5880#section-6.7`
  are dropped and counted as ``rx-auth-errors``.
* At the end of the test, all sessions are set to AdminDown, which is signaled
  to the peers before the routing protocols are torn down.

Interoperability notes:

* BIRD sends multi-hop packets with TTL 64, which requires ``min-ttl`` 64 or lower.
  BIRD and FRR (when deleting dynamic sessions) do not signal AdminDown, so the
  BNG Blaster detects a timeout.
* FRR requires ``local-address`` for single-hop sessions to IPv6 link-local peers,
  otherwise it sends from its global address, which does not match the session.
* FRR ignores packets with your discriminator zero, which the BNG Blaster sends after
  a detection timeout (:rfc:`5880#section-6.8.1`), so FRR detects a timeout as well.

BFD runs in the main thread of the BNG Blaster with one TX and one detection
timer per session. 1000 sessions with 100 ms intervals (10000 packets per second
received and sent) are supported.

Commands
~~~~~~~~

All sessions are listed by the command ``bfd-sessions``,
which accepts the filters ``bfd-session-id``, ``network-interface``,
``peer-address`` and ``state``.

``$ sudo bngblaster-cli run.sock bfd-sessions``

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "bfd-sessions": [
            {
                "bfd-session-id": 1,
                "name": "DUT",
                "network-interface": "eth1",
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "multihop": false,
                "state": "Up",
                "remote-state": "Up",
                "local-diagnostic": "none",
                "local-discriminator": 1720564481,
                "remote-discriminator": 2214,
                "remote-diagnostic": "none",
                "authentication-type": "none",
                "multiplier": 3,
                "remote-multiplier": 3,
                "desired-min-tx-interval-us": 100000,
                "required-min-rx-interval-us": 100000,
                "remote-desired-min-tx-interval-us": 100000,
                "remote-required-min-rx-interval-us": 100000,
                "tx-interval-us": 100000,
                "detection-time-us": 300000,
                "state-seconds": 4,
                "min-ttl": 255,
                "passive": false,
                "poll": false,
                "admin-state": "enabled",
                "clients": [
                    "static"
                ],
                "stats": {
                    "tx-packets": 51,
                    "tx-errors": 0,
                    "rx-packets": 53,
                    "rx-errors": 0,
                    "rx-auth-errors": 0,
                    "up": 1,
                    "down": 0,
                    "timeout": 0,
                    "poll-sequences": 1
                }
            }
        ]
    }

The commands ``bfd-session-disable`` and ``bfd-session-enable`` set all
matching sessions administratively down (AdminDown) or enable them again,
for example to verify the behavior of the DUT if a BFD peer signals AdminDown.

``$ sudo bngblaster-cli run.sock bfd-session-disable bfd-session-id 1``

The timers of matching sessions are changed at runtime with ``bfd-session-update``,
which starts a poll sequence for sessions in state Up.

``$ sudo bngblaster-cli run.sock bfd-session-update tx-interval 50 rx-interval 50 multiplier 5``

.. include:: ../api/bfd.rst

The final JSON report contains the section ``bfd`` with the totals
of all sessions and the session details (``bfd-sessions``).
