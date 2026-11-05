.. _evpn:

EVPN
----

The BNG Blaster can be used to test BGP EVPN services of a device under
test (DUT), where the BNG Blaster emulates the remote provider edge
router (PE) and the customer edge router (CE) at the same time.

* Learn all EVPN routes received from the DUT (route types 1 to 5)
* Advertise EVPN routes of the emulated PE using :ref:`RAW update files <bgp>`
  generated with ``bgpupdate`` (EVPN VPWS and E-LAN)
* Send traffic streams with labels dynamically resolved from the
  EVPN routes of the DUT (L3 EVPN, EVPN VPWS and E-LAN)
* Verify the traffic received from the DUT including the labels
  advertised by the BNG Blaster
* Reply to ARP, IPv6 neighbor solicitation and ICMP echo requests
  of a real CE within EVPN VPWS and E-LAN services

The following services are supported for MPLS encapsulation. Routes with
VNI based encapsulation like VXLAN are learned and displayed, but not used
for traffic streams.

+---------------+-------------------------------+-----------------------------+---------------------------+
| Service       | DUT route used by streams     | Routes of the emulated PE   | Stream options            |
+===============+===============================+=============================+===========================+
| EVPN VPWS     | Ethernet A-D per EVI          | ``bgpupdate --evpn-vpws``   | ``bgp-evpn-rd``           |
| (E-LINE)      | (type 1), Ethernet tag is     | Ethernet A-D per EVI        | ``bgp-evpn-ethernet-tag`` |
|               | the DUT local service ID      | (type 1)                    |                           |
+---------------+-------------------------------+-----------------------------+---------------------------+
| EVPN E-LAN    | MAC/IP advertisement (type 2) | ``bgpupdate --evpn-elan``   | ``bgp-evpn-rd``           |
|               | of the CE MAC, otherwise      | IMET (type 3) and           | ``bgp-evpn-elan``         |
|               | IMET (type 3) ingress         | MAC/IP advertisement        | ``destination-mac``       |
|               | replication label             | (type 2)                    |                           |
+---------------+-------------------------------+-----------------------------+---------------------------+
| L3 EVPN       | MAC/IP advertisement          | not generated (e.g. use     | ``bgp-evpn-rd``           |
| (IRB, IP-VRF) | (type 2) label2 or            | a :ref:`RAW update file     | ``bgp-evpn-mac``          |
|               | IP prefix (type 5)            | <bgp>` from another source) | ``bgp-evpn-prefix``       |
+---------------+-------------------------------+-----------------------------+---------------------------+

Test Setup
~~~~~~~~~~

In a typical setup, the BNG Blaster is connected with two network interfaces
to the DUT. The first network interface emulates the remote PE with an
internal BGP session (family ``evpn``) and MPLS encapsulated traffic. The second
network interface emulates the CE connected to the attachment circuits of the
EVPN services of the DUT, usually with one VLAN per service.

.. code-block:: none

    +----------------------------------+                         +-------------------+
    |           BNG Blaster            |                         |        DUT        |
    |                                  |                         |       (PE)        |
    |  remote PE    eth1  10.0.1.2/24  |--- BGP EVPN + MPLS -----| 10.0.1.1          |
    |               02:00:00:00:00:01  |                         |                   |
    |                                  |                         |                   |
    |  CE           eth2  VLAN 100     |--- E-LINE (VLAN 100) ---| AC                |
    |               02:00:00:00:00:02  |--- E-LAN (VLAN 200) ----| AC                |
    +----------------------------------+                         +-------------------+

Traffic is tested in both directions:

* **PE to CE** streams are sent from the emulated PE interface with the
  label resolved from the EVPN route of the DUT. The DUT forwards the
  customer frames to the attachment circuit where the streams are received
  by the CE interface.
* **CE to PE** streams are sent from the CE interface to the MAC address of
  the emulated PE interface (``gateway-mac``). The DUT forwards those frames
  with the label advertised by the BNG Blaster, which can be verified with
  ``rx-label1`` (``rx-label2`` with transport label).

The DUT must be able to resolve the BGP next-hop of the emulated PE to an MPLS
path, for example using :ref:`LDP <ldp>`, ISIS segment routing or a static
route. If the DUT is directly connected and pops the transport label (implicit
null), the EVPN label is the only label in both directions. Otherwise, the
transport label towards the DUT can be set with ``tx-label1`` or resolved
with ``ldp-ipv4-lookup-address``.

The emulated PE requires a BGP session with ``learn-routes`` and the family
``evpn``. The routes of the emulated PE are sent with the ``raw-update-file``
as soon as the session is established.

.. code-block:: json

    {
        "bgp": [
            {
                "network-interface": "eth1",
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "local-as": 65000,
                "peer-as": 65000,
                "learn-routes": true,
                "family": [ "evpn" ],
                "raw-update-file": "evpn.bgp"
            }
        ]
    }

EVPN Routes
~~~~~~~~~~~

With ``learn-routes`` enabled, the BNG Blaster learns all EVPN routes
(:rfc:`7432`, :rfc:`9136`) received from the peer. This includes Ethernet
auto-discovery (type 1), MAC/IP advertisement (type 2), inclusive multicast
Ethernet tag (type 3), Ethernet segment (type 4) and IP prefix routes (type 5)
together with the route targets, encapsulation, PMSI tunnel, router's MAC,
MAC mobility, ESI label and EVPN Layer 2 attributes. Other route types are
ignored.

Labels are decoded as 20 bit MPLS labels unless the encapsulation extended
community signals a VNI based encapsulation like VXLAN (:rfc:`8365`).

EVPN routes are stored per session (Adj-RIB-In), like IPv4 and IPv6 routes,
and can be displayed with the ``bgp-evpn-routes`` :ref:`command <api>`.
Withdrawn routes and routes of sessions which went down are kept as
inactive entries.

``$ sudo bngblaster-cli run.sock bgp-evpn-routes route-type 2``

Streams wait until a matching active route with an MPLS label is learned
and are rebuilt automatically if the label changes. If the same route is
received from multiple sessions (e.g. redundant route reflectors), streams
use the route of the first session in configuration order and keep using it
as long as it is active. If this route is withdrawn or the session goes down,
streams switch to the same route of the next session.

The ``stream-info`` :ref:`command <api>` shows for EVPN streams if the route
is resolved (``evpn-resolved``), the resolved label (``evpn-label``) and the
type of the used route (``evpn-route-type``). The route is resolved when the
stream is scheduled for sending, so stopped streams show ``evpn-resolved`` false.

L3 EVPN
~~~~~~~

Traffic streams can dynamically resolve the inner (VPN) label of IP traffic
from learned EVPN routes. The label2 of a MAC/IP advertisement route (symmetric IRB)
is used if ``bgp-evpn-mac`` is set, or the label of an IP prefix route
if ``bgp-evpn-prefix`` is set. The outer transport label can be set
statically with ``tx-label1`` or resolved via LDP. Without outer label,
the EVPN label is sent as the only label.

.. code-block:: json

    {
        "streams": [
            {
                "name": "EVPN-T2",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth1",
                "destination-ipv4-address": "10.1.1.10",
                "tx-label1": 100,
                "bgp-evpn-rd": "65001:100",
                "bgp-evpn-mac": "00:11:22:33:44:55",
                "bgp-evpn-ip": "10.1.1.10"
            },
            {
                "name": "EVPN-T5",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth1",
                "destination-ipv4-address": "192.168.10.1",
                "tx-label1": 100,
                "bgp-evpn-rd": "65001:100",
                "bgp-evpn-prefix": "192.168.10.0/24"
            }
        ]
    }

EVPN VPWS (E-LINE)
~~~~~~~~~~~~~~~~~~

EVPN VPWS (:rfc:`8214`) services are signaled with per-EVI Ethernet
auto-discovery routes (type 1) with the local VPWS service identifier
as Ethernet tag, the VPWS label and the EVPN Layer 2 Attributes extended
community (control word, primary and backup flags and L2 MTU).

The routes of the emulated PE are generated with ``bgpupdate --evpn-vpws``.
The Ethernet tag advertised by the BNG Blaster (``--service-id``) is the
remote service identifier configured on the DUT and the stream uses the route
of the DUT with its local service identifier (``--stream-evpn-service-id``).

Traffic streams with ``bgp-evpn-rd`` and ``bgp-evpn-ethernet-tag`` (optionally
``bgp-evpn-esi``) but without ``bgp-evpn-mac`` or ``bgp-evpn-prefix`` resolve
the VPWS label of the DUT and send the stream packets as Ethernet frames
over MPLS to the ``destination-mac`` of the CE. The control word is added if
requested by the DUT or enabled with ``tx-control-word``. Customer VLAN tags
within the VPWS service can be added with ``vpws-vlan`` and ``vpws-inner-vlan``.

Received Ethernet over MPLS traffic is accepted on network interfaces with and
without control word, where ``rx-label1`` or ``rx-label2`` can be used to verify
the advertised VPWS label. Streams expecting a control word (control word flag
advertised by the BNG Blaster) should enable ``rx-control-word``. This is
required to decode frames correctly where the presence of the control word is
ambiguous (e.g. VLAN tagged frames with destination MAC address 00:...).

With ``vpws-arp`` enabled, the BNG Blaster replies to ARP, IPv6 neighbor
solicitation and ICMP/ICMPv6 echo requests for the ``network-ipv4-address``
or ``network-ipv6-address`` of the stream, received within the VPWS service
with the customer VLAN tags of the stream. This allows a real CE router to
resolve and ping the emulated PE side. Replies are sent with the labels,
control word and customer VLAN tags of the stream and the MAC address of
the network interface. If ``destination-mac`` is not configured, the stream
learns the CE MAC address from those requests and starts sending once the
MAC address is learned (``vpws-mac`` in ``stream-info``, ``null`` until learned).

.. code-block:: json

    {
        "name": "VPWS-1000-PE-CE",
        "type": "ipv4",
        "direction": "downstream",
        "network-interface": "eth1",
        "network-ipv4-address": "192.0.2.1",
        "destination-ipv4-address": "192.0.2.2",
        "bgp-evpn-rd": "10.0.0.1:100",
        "bgp-evpn-ethernet-tag": 1000,
        "vpws-arp": true
    }

Without control word, CE frames with a destination MAC address starting
with 4 or 6 in the first nibble can be misinterpreted as IPv4 or IPv6 over
MPLS. The control word should be used if the network interface MAC address
starts with such a nibble.

The RAW update file and streams can be generated with ``bgpupdate``, where
``--stream-evpn-rd`` is the route distinguisher of the DUT routes. The generated
streams are named ``vpws-<service-id>-pe-ce`` and ``vpws-<service-id>-ce-pe``.
The ``--stream-direction`` selects PE to CE (downstream, default), CE to PE
(upstream) or both streams.

.. code-block:: none

    bgpupdate --evpn-vpws -n 10.0.1.2 -l 100 --rd 10.0.1.2:100 --rt 65001:100 \
        --service-id 1000 -m 5000 --mtu 1500 --primary --end-of-rib -f vpws.bgp \
        -s streams.json --stream-direction both --stream-pps 1000 \
        --stream-interface eth1 --stream-tx-label 16001 \
        --stream-ce-interface eth2 --stream-ce-vlan 100 \
        --stream-evpn-rd 10.0.0.1:100 --stream-destination-mac 02:00:00:00:00:02 \
        --stream-pe-address 192.0.2.1 --stream-ce-address 192.0.2.2

Multiple services are generated with ``--service-num`` where the service
identifier, CE VLAN (``--stream-ce-vlan``) and customer VLAN within the VPWS
service (``--stream-vpws-vlan``) are incremented per service. Different labels per
service require ``-M`` (label count), different route distinguishers and
route targets per service ``--rd-increment`` and ``--rt-increment``.
The option ``--stream-vpws-arp`` enables ``vpws-arp`` for the PE to CE
streams, where ``--stream-destination-mac`` becomes optional. Withdraw
updates (``--withdraw``) require only ``--rd`` besides the
mandatory ``--next-hop-base``.

EVPN E-LAN
~~~~~~~~~~

EVPN E-LAN (:rfc:`7432`) services with MPLS encapsulation are signaled
with inclusive multicast Ethernet tag routes (IMET, type 3) with a PMSI
tunnel attribute of type ingress replication for broadcast, unknown
unicast and multicast (BUM) traffic and MAC/IP advertisement routes
(type 2) for known unicast traffic.

The routes of the emulated PE are generated with ``bgpupdate --evpn-elan``,
which includes an IMET route and MAC/IP routes for all MAC addresses
given with ``--mac`` (e.g. the MAC address of the PE network interface)
per EVI with the same label for unicast and BUM traffic. The DUT learns the
MAC address of the emulated PE from those routes and forwards CE to PE
traffic as known unicast.

Traffic streams with ``bgp-evpn-elan``, ``bgp-evpn-rd`` and ``destination-mac``
(optionally ``bgp-evpn-ethernet-tag``) send the stream packets as Ethernet
frames over MPLS to the CE. The label1 of the MAC/IP route of the DUT for the
``destination-mac`` (known unicast) is used if learned, otherwise the ingress
replication label of the IMET route of the DUT with the same route distinguisher
and Ethernet tag (unknown unicast flooded by the DUT). Streams switch automatically
between both labels if the MAC/IP route is learned or withdrawn, where
``evpn-route-type`` in ``stream-info`` shows the used route type
(2 for known unicast, 3 for unknown unicast).

The control word is not signaled for EVPN E-LAN and must be enabled with
``tx-control-word`` and ``rx-control-word`` if used by the DUT. The options
``vpws-vlan``, ``vpws-inner-vlan``, ``vpws-qinq`` and ``vpws-arp`` are
supported as for EVPN VPWS, where ``vpws-arp`` replies to requests received
with the ingress replication label (e.g. ARP broadcast) using the labels of
the stream. EVPN E-LAN streams require ``destination-mac``.

.. code-block:: json

    {
        "name": "ELAN-PE-CE",
        "type": "ipv4",
        "direction": "downstream",
        "network-interface": "eth1",
        "network-ipv4-address": "198.51.100.1",
        "destination-ipv4-address": "198.51.100.2",
        "destination-mac": "02:00:00:00:00:02",
        "bgp-evpn-rd": "10.0.0.1:200",
        "bgp-evpn-elan": true,
        "tx-control-word": true
    }

The RAW update file and streams can be generated with ``bgpupdate``
similar to EVPN VPWS, where the streams are named ``elan-<n>-pe-ce`` and
``elan-<n>-ce-pe``. The option ``--control-word`` adds ``tx-control-word`` to the
PE to CE streams and ``rx-control-word`` to the CE to PE streams. The Ethernet
tag can be set with ``--ethernet-tag`` (default 0 for VLAN-based services).

.. code-block:: none

    bgpupdate --evpn-elan -n 10.0.1.2 -l 100 --rd 10.0.1.2:200 --rt 65001:200 \
        -m 6000 --mac 02:00:00:00:00:01 --control-word --end-of-rib -f elan.bgp \
        -s streams.json --stream-direction both --stream-pps 1000 \
        --stream-interface eth1 --stream-tx-label 16001 \
        --stream-ce-interface eth2 --stream-ce-vlan 200 \
        --stream-evpn-rd 10.0.0.1:200 --stream-destination-mac 02:00:00:00:00:02 \
        --stream-pe-address 198.51.100.1 --stream-ce-address 198.51.100.2

Testing EVPN Services
~~~~~~~~~~~~~~~~~~~~~

The following steps describe how to test EVPN VPWS and E-LAN services
of a DUT. The example tests one E-LINE and one E-LAN service against a
directly connected DUT with the setup shown above.

+---------------+-------------------------------+-------------------------------+
|               | E-LINE                        | E-LAN                         |
+===============+===============================+===============================+
| DUT           | RD 10.0.0.1:100,              | RD 10.0.0.1:200,              |
|               | RT 65000:100,                 | RT 65000:200,                 |
|               | local service ID 1000,        | VLAN-based service,           |
|               | remote service ID 2000,       | AC VLAN 200                   |
|               | AC VLAN 100                   |                               |
+---------------+-------------------------------+-------------------------------+
| BNG Blaster   | RD 10.0.1.2:100,              | RD 10.0.1.2:200,              |
| (remote PE)   | service ID 2000, label 5000   | label 6000,                   |
|               |                               | MAC 02:00:00:00:00:01         |
+---------------+-------------------------------+-------------------------------+
| BNG Blaster   | 192.0.2.2/24 (VLAN 100)       | 198.51.100.2/24 (VLAN 200)    |
| (CE)          |                               |                               |
+---------------+-------------------------------+-------------------------------+

**Step 1: Configure the DUT**

Configure the following on the DUT with the parameters shown in the
table above.

* Internal BGP session to the emulated PE (``10.0.1.2``) with family EVPN
* MPLS on the interface to the emulated PE and an MPLS path to the BGP next-hop
  of the emulated PE (e.g. LDP, segment routing or a static route)
* EVPN VPWS service with the attachment circuit on VLAN 100 of the CE interface
* VLAN-based EVPN E-LAN service with MPLS encapsulation and the attachment
  circuit on VLAN 200 of the CE interface

**Step 2: Generate the routes and streams of the emulated PE**

The RAW update file ``evpn.bgp`` and the streams are generated with
``bgpupdate``, where the second call appends the E-LAN routes and streams
(``--append`` and ``--stream-append``). Only the last call should add the
end-of-RIB marker.

.. code-block:: none

    bgpupdate -l 100 -f evpn.bgp -s streams.json -n 10.0.1.2 --evpn-vpws \
        --rd 10.0.1.2:100 --rt 65000:100 -m 5000 --service-id 2000 --control-word \
        --stream-evpn-rd 10.0.0.1:100 --stream-evpn-service-id 1000 \
        --stream-destination-mac 02:00:00:00:00:02 --stream-vpws-vlan 100 \
        --stream-interface eth1 --stream-ce-interface eth2 --stream-ce-vlan 100 \
        --stream-direction both --stream-pps 1000

    bgpupdate -l 100 -f evpn.bgp -s streams.json --append --stream-append \
        -n 10.0.1.2 --evpn-elan --rd 10.0.1.2:200 --rt 65000:200 -m 6000 \
        --mac 02:00:00:00:00:01 --control-word --stream-vpws-arp \
        --stream-evpn-rd 10.0.0.1:200 --stream-destination-mac 02:00:00:00:00:02 \
        --stream-interface eth1 --stream-ce-interface eth2 --stream-ce-vlan 200 \
        --stream-pe-address 198.51.100.1 --stream-ce-address 198.51.100.2 \
        --stream-direction both --stream-pps 1000 --end-of-rib

**Step 3: Configure the BNG Blaster**

The generated streams are added to the BNG Blaster configuration. The E-LINE
CE interface uses the MAC address of the emulated PE interface as
``gateway-mac``. The E-LAN CE interface resolves the gateway address
``198.51.100.1`` of the emulated PE via ARP through the E-LAN service,
which is answered by the BNG Blaster (``vpws-arp``). The option
``gateway-resolve-wait`` must be disabled for both CE interfaces because the
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
                    "vlan": 100,
                    "address": "192.0.2.2/24",
                    "gateway": "192.0.2.1",
                    "gateway-mac": "02:00:00:00:00:01",
                    "gateway-resolve-wait": false
                },
                {
                    "interface": "eth2",
                    "vlan": 200,
                    "address": "198.51.100.2/24",
                    "gateway": "198.51.100.1",
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
                "family": [ "evpn" ],
                "raw-update-file": "evpn.bgp"
            }
        ],
        "streams": [
            {
                "name": "vpws-2000-pe-ce",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth1",
                "destination-ipv4-address": "192.0.2.2",
                "network-ipv4-address": "192.0.2.1",
                "destination-mac": "02:00:00:00:00:02",
                "bgp-evpn-rd": "10.0.0.1:100",
                "bgp-evpn-ethernet-tag": 1000,
                "vpws-vlan": 100
            },
            {
                "name": "vpws-2000-ce-pe",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth2:100",
                "destination-ipv4-address": "192.0.2.1",
                "network-ipv4-address": "192.0.2.2",
                "rx-label1": 5000,
                "rx-control-word": true
            },
            {
                "name": "elan-1-pe-ce",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth1",
                "destination-ipv4-address": "198.51.100.2",
                "network-ipv4-address": "198.51.100.1",
                "destination-mac": "02:00:00:00:00:02",
                "bgp-evpn-rd": "10.0.0.1:200",
                "bgp-evpn-ethernet-tag": 0,
                "bgp-evpn-elan": true,
                "tx-control-word": true,
                "vpws-arp": true
            },
            {
                "name": "elan-1-ce-pe",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth2:200",
                "destination-ipv4-address": "198.51.100.1",
                "network-ipv4-address": "198.51.100.2",
                "rx-label1": 6000,
                "rx-control-word": true
            }
        ]
    }

**Step 4: Verify the control plane**

Start the BNG Blaster and verify that the BGP session is established
and the EVPN routes of the DUT are learned. The DUT advertises the
Ethernet A-D route of the E-LINE service with its local service ID as
Ethernet tag, the IMET route of the E-LAN service and, as soon as the CE
MAC address is learned on the attachment circuit, the MAC/IP routes.

.. code-block:: none

    $ sudo bngblaster -C evpn.json -S run.sock -I
    $ sudo bngblaster-cli run.sock bgp-sessions
    $ sudo bngblaster-cli run.sock bgp-evpn-routes route-type 1
    $ sudo bngblaster-cli run.sock bgp-evpn-routes route-type 3

On the DUT, the routes of the emulated PE must be active with a resolved
next-hop. A route hidden by the DUT is often caused by a missing attribute
(e.g. local preference) or an unresolved BGP next-hop.

**Step 5: Verify the traffic**

The ``stream-info`` :ref:`command <api>` shows if the PE to CE streams are resolved
and which label and route type are used.

.. code-block:: none

    $ sudo bngblaster-cli run.sock stream-info flow-id 3
    {
        "status": "ok",
        "code": 200,
        "stream-info": {
            "name": "elan-1-pe-ce",
            ...
            "tx-packets": 100,
            "rx-packets": 100,
            "rx-loss": 0,
            ...
            "evpn-resolved": true,
            "evpn-label": 17,
            "evpn-route-type": 2
        }
    }

All streams should be received without loss. The CE to PE streams verify the
labels advertised by the BNG Blaster (``rx-label1``). For a lossless measurement,
reset the stream counters after the services are established.

.. code-block:: none

    $ sudo bngblaster-cli run.sock traffic-stop
    $ sudo bngblaster-cli run.sock stream-reset
    $ sudo bngblaster-cli run.sock traffic-start
    $ sudo bngblaster-cli run.sock stream-summary

Further tests can be built on this setup, for example withdrawing the routes of
the emulated PE with a RAW update file generated with ``--withdraw`` (``bgp-raw-update``
:ref:`command <api>`) to verify that the DUT stops forwarding, scaling the number
of services with ``--service-num``, or measuring the convergence of the DUT.

Troubleshooting
~~~~~~~~~~~~~~~

+------------------------------------+-----------------------------------------------------------------+
| Problem                            | Possible Cause and Solution                                     |
+====================================+=================================================================+
| Routes of the BNG Blaster are      | Internal BGP sessions require the local preference, generate    |
| hidden by the DUT as malformed     | the routes with ``bgpupdate -l 100``.                           |
+------------------------------------+-----------------------------------------------------------------+
| Routes of the BNG Blaster are      | The DUT can't resolve the BGP next-hop of the emulated PE to an |
| hidden by the DUT as unusable      | MPLS path (e.g. missing LDP label or inet.3 route).             |
+------------------------------------+-----------------------------------------------------------------+
| Stream ``evpn-resolved`` is false  | The ``bgp-evpn-rd`` must be the route distinguisher of the DUT  |
|                                    | and ``bgp-evpn-ethernet-tag`` the local service ID of the DUT   |
|                                    | (E-LINE). Check the learned routes with ``bgp-evpn-routes``.    |
|                                    | Routes with VXLAN encapsulation are not supported for streams.  |
+------------------------------------+-----------------------------------------------------------------+
| PE to CE frames are received by    | Control word mismatch. Some implementations (e.g. Junos) use    |
| the CE with 4 additional bytes or  | the control word for EVPN VPWS only if both PEs set the         |
| are dropped by the DUT             | control word flag (``bgpupdate --control-word``). EVPN E-LAN    |
|                                    | requires ``tx-control-word`` and ``rx-control-word`` if the     |
|                                    | DUT uses the control word.                                      |
+------------------------------------+-----------------------------------------------------------------+
| E-LINE PE to CE frames are dropped | The DUT may expect the customer VLAN within the service         |
| by the DUT                         | (e.g. Junos ``vlan-ccc``), add ``vpws-vlan``.                   |
+------------------------------------+-----------------------------------------------------------------+
| E-LAN stream uses route type 3     | The DUT has not learned the CE MAC address yet (no traffic      |
| instead of 2                       | from the CE). Start the CE to PE stream or enable ``vpws-arp``. |
+------------------------------------+-----------------------------------------------------------------+
| E-LAN stream to an unknown MAC     | Flooded frames are only counted by the CE interface if the      |
| address is not received            | ``destination-mac`` is the MAC address of this interface.       |
+------------------------------------+-----------------------------------------------------------------+
| DUT originates no E-LAN routes     | The attachment circuit is down in the EVPN instance of the DUT. |
|                                    | Junos PTX requires ``family ethernet-switching`` instead of     |
|                                    | ``encapsulation vlan-bridge`` for the attachment circuit.       |
+------------------------------------+-----------------------------------------------------------------+
| BNG Blaster does not start traffic | The CE interfaces wait for the gateway, which is only reachable |
| (resolve network interfaces)       | through the EVPN service. Disable ``gateway-resolve-wait``.     |
+------------------------------------+-----------------------------------------------------------------+
| Frames received over MPLS are      | Without control word, frames with a MAC address starting with 4 |
| decoded as IPv4 or IPv6            | or 6 are ambiguous. Use the control word or other MAC addresses.|
+------------------------------------+-----------------------------------------------------------------+

Virtual Lab
~~~~~~~~~~~

EVPN services can be tested against virtual routers, for example with
`containerlab <https://containerlab.dev>`_, where the BNG Blaster runs on
the host connected to the virtual DUT using ``host`` links. The example above
was verified with Juniper vJunosEvolved (PTX10001-36MR) which is available
for free without license and supports EVPN VPWS and E-LAN with MPLS
encapsulation (license alarms can be ignored in the lab).
The container image is built with `vrnetlab <https://containerlab.dev/manual/vrnetlab/>`_.

.. code-block:: yaml

    name: evpn
    topology:
      nodes:
        pe1:
          kind: juniper_vjunosevolved
          image: vrnetlab/juniper_vjunosevolved:26.2R1.7-EVO
          startup-config: pe1.cfg
      links:
        - endpoints: ["pe1:et-0/0/0", "host:eth1"]
        - endpoints: ["pe1:et-0/0/1", "host:eth2"]

The MAC addresses of the host interfaces can be set as used in the example
above, and IPv6 should be disabled on those interfaces as the BNG Blaster
interfaces must not have IP addresses configured in the host OS.

.. code-block:: none

    sudo containerlab deploy -t evpn.clab.yml
    sudo ip link set eth1 address 02:00:00:00:00:01
    sudo ip link set eth2 address 02:00:00:00:00:02
    sudo sysctl -w net.ipv6.conf.eth1.disable_ipv6=1 net.ipv6.conf.eth2.disable_ipv6=1

The free container images of Nokia SR Linux support EVPN only with VXLAN
encapsulation, while the BNG Blaster supports EVPN traffic streams only with
MPLS encapsulation.
