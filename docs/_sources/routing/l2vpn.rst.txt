.. _l2vpn:

BGP L2VPN
---------

The BNG Blaster supports BGP auto-discovery and signaling for Layer 2 VPNs
(:rfc:`6624`), also known as BGP L2VPN, Kompella L2VPN or BGP VPWS, where
point-to-point pseudowires between the CEs of an L2VPN are signaled with
label blocks using the BGP NLRI of :rfc:`4761` (AFI 25, SAFI 65).

* Learn the label blocks received from the DUT
* Advertise label blocks of an emulated PE using :ref:`RAW update files <bgp>`
  generated with ``bgpupdate --l2vpn``
* Send traffic streams as Ethernet over MPLS with the pseudowire label
  resolved from the label block of the remote CE
* Verify the traffic received from the DUT including the label
  advertised by the BNG Blaster
* Reply to ARP, IPv6 neighbor solicitation and ICMP echo requests of a real CE

Label Blocks
~~~~~~~~~~~~

Each CE of an L2VPN has a unique CE ID (site identifier). The PE advertises
for each local CE one or more label blocks, where a label block with label
block offset ``O``, label block size ``S`` and label base ``L`` contains the
labels ``L`` to ``L + S - 1`` for the remote CE IDs ``O`` to ``O + S - 1``.

A PE with local CE ``W`` sends traffic to the remote CE ``V`` with the label
``L + W - O`` of the label block of CE ``V`` which covers CE ``W`` and
expects traffic from CE ``V`` with the label of its own label block
covering CE ``V`` (:rfc:`4761` section 3.2.3).

The label blocks are advertised with the route targets of the L2VPN and
the Layer2 Info extended community, which signals the encapsulation type
(e.g. 4 for Ethernet VLAN or 5 for Ethernet), the control flags (control
word and sequenced delivery) and the Layer 2 MTU. The circuit status vector
TLV (:rfc:`6624`) signals the status of the pseudowire to each remote CE
of the label block.

Routes
~~~~~~

BGP sessions with ``learn-routes`` enabled and the family ``l2vpn`` learn all
label blocks received from the peer, which can be displayed with the
``bgp-l2vpn-routes`` :ref:`command <api>`. Withdrawn routes and routes of
sessions which went down are kept as inactive entries.

.. code-block:: none

    $ sudo bngblaster-cli run.sock bgp-l2vpn-routes
    {
        "status": "ok",
        "code": 200,
        "bgp-l2vpn-routes": [
            {
                "interface": "eth1",
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "routes": [
                    {
                        "rd": "10.0.0.1:300",
                        "ce-id": 1,
                        "active": true,
                        "version": 1,
                        "label-block-offset": 1,
                        "label-block-size": 2,
                        "label-base": 29,
                        "nexthop": "10.0.1.1",
                        "route-targets": [
                            "65000:300"
                        ],
                        "layer2-info": {
                            "encapsulation-type": 4,
                            "encapsulation": "ethernet-vlan",
                            "flags": 2,
                            "control-word": true,
                            "sequencing": false,
                            "mtu": 0
                        },
                        "circuit-status": [
                            true,
                            true
                        ]
                    }
                ]
            }
        ]
    }

Traffic Streams
~~~~~~~~~~~~~~~

Traffic streams with ``bgp-l2vpn-rd``, ``bgp-l2vpn-ce-id`` (remote CE) and
``bgp-l2vpn-local-ce-id`` (local CE emulated by the BNG Blaster) resolve the
pseudowire label from the active label block of the remote CE which covers
the local CE ID and send the stream packets as Ethernet frames over MPLS to
the ``destination-mac`` of the remote CE. The control word is added if requested
by the remote PE (control word flag) or enabled with ``tx-control-word``.

Streams wait until a matching label block is learned and are rebuilt
automatically if the label block changes. The ``stream-info`` :ref:`command <api>`
shows if the label is resolved (``l2vpn-resolved``), the resolved label
(``l2vpn-label``) and the circuit status signaled by the remote PE for the
local CE (``l2vpn-circuit-up``). The circuit status is only displayed, streams
are sent independent of the status.

The options ``vpws-vlan``, ``vpws-inner-vlan``, ``vpws-qinq``, ``vpws-arp`` and
``rx-control-word`` are supported as for :ref:`EVPN VPWS <evpn>`. Received traffic
can be verified with ``rx-label1`` (or ``rx-label2`` with transport label).

.. code-block:: json

    {
        "name": "L2VPN-PE-CE",
        "type": "ipv4",
        "direction": "downstream",
        "network-interface": "eth1",
        "network-ipv4-address": "192.0.2.1",
        "destination-ipv4-address": "192.0.2.2",
        "destination-mac": "02:00:00:00:00:02",
        "bgp-l2vpn-rd": "10.0.0.1:300",
        "bgp-l2vpn-ce-id": 1,
        "bgp-l2vpn-local-ce-id": 2,
        "vpws-vlan": 300
    }

The label blocks of the emulated PE are generated with ``bgpupdate --l2vpn``,
with one label block for the local CE ``--ce-id`` per L2VPN instance
(``--service-num``). The label block covers the remote CE IDs
``--label-block-offset`` (default 1) to ``--label-block-offset`` +
``--label-block-size`` (default 8) - 1, where the label block of instance ``n``
starts with label ``--label-base`` + ``n`` * ``--label-block-size``. The
encapsulation type is set with ``--encapsulation`` (``ethernet-vlan`` or
``ethernet``), the control word flag with ``--control-word`` and the MTU with
``--mtu``. All circuits are signaled up in the circuit status vector.

The option ``--streams`` generates the corresponding streams named
``l2vpn-<n>-pe-ce`` and ``l2vpn-<n>-ce-pe``, where ``--stream-l2vpn-rd`` is the
route distinguisher and ``--stream-l2vpn-ce-id`` the CE ID of the DUT. The
CE to PE streams expect the label of the label block of the BNG Blaster which
covers the CE ID of the DUT. All other stream options (``--stream-*``) are the
same as for EVPN VPWS.

.. code-block:: none

    bgpupdate --l2vpn -n 10.0.1.2 -l 100 --rd 10.0.1.2:300 --rt 65000:300 \
        -m 7000 --ce-id 2 --label-block-size 2 --control-word --end-of-rib -f l2vpn.bgp \
        -s streams.json --stream-direction both --stream-pps 1000 \
        --stream-interface eth1 --stream-ce-interface eth2 --stream-ce-vlan 300 \
        --stream-l2vpn-rd 10.0.0.1:300 --stream-l2vpn-ce-id 1 \
        --stream-destination-mac 02:00:00:00:00:02 --stream-vpws-vlan 300 --stream-vpws-arp

Testing BGP L2VPN
~~~~~~~~~~~~~~~~~

The test setup is the same as for :ref:`EVPN services <evpn>`, where the
BNG Blaster emulates the remote PE with an internal BGP session (family ``l2vpn``)
and an MPLS network interface, and the CE connected to the attachment
circuit of the DUT with a second network interface.

.. code-block:: none

    +----------------------------------+                         +-------------------+
    |           BNG Blaster            |                         |        DUT        |
    |                                  |                         |       (PE)        |
    |  remote PE    eth1  10.0.1.2/24  |--- BGP L2VPN + MPLS ----| 10.0.1.1          |
    |  CE ID 2      02:00:00:00:00:01  |                         | CE ID 1           |
    |                                  |                         |                   |
    |  CE           eth2  VLAN 300     |--- L2VPN (VLAN 300) ----| AC                |
    |               02:00:00:00:00:02  |                         |                   |
    +----------------------------------+                         +-------------------+

**Step 1: Configure the DUT**

* Internal BGP session to the emulated PE (``10.0.1.2``) with family L2VPN
  (AFI 25, SAFI 65)
* MPLS on the interface to the emulated PE and an MPLS path to the BGP next-hop
  of the emulated PE (e.g. LDP, segment routing or a static route)
* L2VPN instance with route distinguisher ``10.0.0.1:300``, route target
  ``65000:300`` and Ethernet VLAN encapsulation
* Local CE with CE ID (site identifier) 1 and the attachment circuit on VLAN 300
  of the CE interface connected to the remote CE ID 2

**Step 2: Generate the label block and streams of the emulated PE**

Generate the RAW update file and streams with the ``bgpupdate`` command shown
above. The label block of the BNG Blaster (CE ID 2) must cover the CE ID of
the DUT (1) and the encapsulation, control word and MTU must match the
configuration of the DUT.

**Step 3: Configure the BNG Blaster**

The generated streams are added to the BNG Blaster configuration. The CE
interface resolves the gateway address ``192.0.2.1`` of the emulated PE via ARP
through the L2VPN, which is answered by the BNG Blaster (``vpws-arp``). The option
``gateway-resolve-wait`` must be disabled for the CE interface because the
gateway is only reachable after the BGP session is established.

.. code-block:: json

    {
        "interfaces": {
            "network": [
                {
                    "interface": "eth1",
                    "address": "10.0.1.2/24",
                    "gateway": "10.0.1.1"
                },
                {
                    "interface": "eth2",
                    "vlan": 300,
                    "address": "192.0.2.2/24",
                    "gateway": "192.0.2.1",
                    "gateway-resolve-wait": false
                }
            ]
        },
        "bgp": [
            {
                "network-interface": "eth1",
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "local-as": 65000,
                "peer-as": 65000,
                "learn-routes": true,
                "family": [ "l2vpn" ],
                "raw-update-file": "l2vpn.bgp"
            }
        ],
        "streams": [
            {
                "name": "l2vpn-1-pe-ce",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth1",
                "destination-ipv4-address": "192.0.2.2",
                "network-ipv4-address": "192.0.2.1",
                "bgp-l2vpn-rd": "10.0.0.1:300",
                "bgp-l2vpn-ce-id": 1,
                "bgp-l2vpn-local-ce-id": 2,
                "destination-mac": "02:00:00:00:00:02",
                "vpws-arp": true,
                "vpws-vlan": 300
            },
            {
                "name": "l2vpn-1-ce-pe",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth2:300",
                "destination-ipv4-address": "192.0.2.1",
                "network-ipv4-address": "192.0.2.2",
                "rx-label1": 7000,
                "rx-control-word": true
            }
        ]
    }

**Step 4: Verify the control plane**

Verify that the BGP session is established and the label block of the DUT
is learned (``bgp-l2vpn-routes``). On the DUT, the pseudowire to the remote
CE ID 2 should be up, using the label 7000 of the BNG Blaster to send traffic
and expecting the label of its own label block which covers CE ID 2.

**Step 5: Verify the traffic**

The ``stream-info`` :ref:`command <api>` shows the resolved label of the PE to
CE stream, which must be the label expected by the DUT.

.. code-block:: none

    $ sudo bngblaster-cli run.sock stream-info flow-id 1
    {
        "status": "ok",
        "code": 200,
        "stream-info": {
            "name": "l2vpn-1-pe-ce",
            ...
            "l2vpn-resolved": true,
            "l2vpn-label": 30,
            "l2vpn-circuit-up": true
        }
    }

All streams should be received without loss. Further tests can withdraw
the label block of the emulated PE with a RAW update file generated with
``--withdraw`` (``bgp-raw-update`` :ref:`command <api>`) or scale the number
of L2VPN instances with ``--service-num``.

Troubleshooting
~~~~~~~~~~~~~~~

+------------------------------------+-----------------------------------------------------------------+
| Problem                            | Possible Cause and Solution                                     |
+====================================+=================================================================+
| Stream ``l2vpn-resolved`` is false | The ``bgp-l2vpn-rd`` and ``bgp-l2vpn-ce-id`` must be the route  |
|                                    | distinguisher and CE ID of the DUT, and the label block of the  |
|                                    | DUT must cover ``bgp-l2vpn-local-ce-id``. Check the learned     |
|                                    | label blocks with ``bgp-l2vpn-routes``.                         |
+------------------------------------+-----------------------------------------------------------------+
| Pseudowire is down on the DUT      | The label block of the BNG Blaster must cover the CE ID of the  |
|                                    | DUT and the encapsulation type, control word flag and MTU must  |
|                                    | match the configuration of the DUT (:rfc:`6624` section 5.1).   |
|                                    | Routes of internal BGP sessions require the local preference    |
|                                    | (``bgpupdate -l 100``).                                         |
+------------------------------------+-----------------------------------------------------------------+
| PE to CE frames are received by    | Control word mismatch. Generate the label blocks with           |
| the CE with 4 additional bytes or  | ``--control-word`` if the DUT uses the control word and enable  |
| are dropped by the DUT             | ``rx-control-word`` for the CE to PE streams.                   |
+------------------------------------+-----------------------------------------------------------------+
| PE to CE frames are dropped by     | With Ethernet VLAN encapsulation, the DUT may expect the        |
| the DUT                            | customer VLAN within the pseudowire, add ``vpws-vlan``.         |
+------------------------------------+-----------------------------------------------------------------+
| BNG Blaster does not start traffic | The CE interface waits for the gateway, which is only reachable |
| (resolve network interfaces)       | through the L2VPN. Disable ``gateway-resolve-wait``.            |
+------------------------------------+-----------------------------------------------------------------+
