.. _bgp:

BGP
---

The Border Gateway Protocol (BGP) is a standardized exterior gateway protocol
designed to exchange routing and reachability information among autonomous systems
(AS) on the internet. BGP is classified as a path-vector routing protocol, and it 
makes routing decisions based on paths, network policies, or rule sets configured 
by a network operator.

Configuration
~~~~~~~~~~~~~

Following is an example of a BGP configuration with one session.

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
        "bgp": [
            {
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "raw-update-file": "test.bgp",
                "local-as": 65001,
                "peer-as": 65001,
                "family": [ "ipv4-unicast",  "ipv6-unicast" ]
            }
        ]
    }

.. include:: ../configuration/bgp.rst


BGP Sessions
~~~~~~~~~~~~

BGP sessions are opened with the capabilities for the following
address families:

+ IPv4 unicast
+ IPv4 labeled unicast
+ IPv6 unicast
+ IPv6 labeled unicast

This can be changed using the ``family`` configuration option.

Authentication
~~~~~~~~~~~~~~

BGP sessions can be authenticated with the TCP Authentication Option
(TCP-AO, :rfc:`5925` and :rfc:`5926`) using the algorithms hmac-sha-1-96,
hmac-sha-256-128 or aes-128-cmac-96, or with the legacy TCP MD5 signature
option (:rfc:`2385`) using the algorithm md5.

.. code-block:: json

    {
        "bgp": [
            {
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "local-as": 65001,
                "peer-as": 65001,
                "tcp-ao-algorithm": "hmac-sha-1-96",
                "tcp-ao-key": "BNGBlasterTCPAOKey01",
                "tcp-ao-key-id": 1,
                "tcp-ao-rnext-key-id": 1
            }
        ]
    }

The ``tcp-ao-key-id`` is sent as KeyID (SendID) and the ``tcp-ao-rnext-key-id``
as RNextKeyID, which is also the KeyID (RecvID) expected in received segments.
Both are equal by default. Authentication applies to connections initiated by
the BNG Blaster and to connections accepted from the peer, including the
initial SYN. Only a single static key per session is supported (no key rollover).

Route Learning
~~~~~~~~~~~~~~

Received routes are not stored by default. With ``learn-routes`` enabled,
the BNG Blaster stores all IPv4 and IPv6 unicast and labeled unicast routes
per session (Adj-RIB-In) together with next-hop, origin, AS path, MED,
local preference, communities, large communities and extended communities.
Routes are added, replaced or deleted with every received update or withdraw
and removed if the session goes down. Equal path attributes are stored
once and shared between routes.

.. code-block:: json

    {
        "bgp": [
            {
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "local-as": 65001,
                "peer-as": 65001,
                "learn-routes": true,
                "family": [ "ipv4-unicast", "ipv6-unicast", "evpn" ]
            }
        ]
    }

The learned routes and counters can be displayed with the ``bgp-routes``
and ``bgp-routes-stats`` :ref:`commands <api>`.

``$ sudo bngblaster-cli run.sock bgp-routes family ipv4-unicast``

All routes matching a prefix are listed by adding ``prefix`` with ``match``
set to ``exact`` (default) or ``longer`` (exact and longer prefixes).

``$ sudo bngblaster-cli run.sock bgp-routes prefix 10.0.0.0/8 match longer``

``$ sudo bngblaster-cli run.sock bgp-routes-stats``

AS numbers are shown as received. For peers without 4-octet AS capability,
the AS4_PATH attribute is not merged and 4-octet AS numbers are shown
as AS_TRANS (23456).

EVPN
~~~~

With ``learn-routes`` enabled, the BNG Blaster learns all EVPN routes
(RFC 7432, RFC 9136) received from the peer. This includes Ethernet
auto-discovery (type 1), MAC/IP advertisement (type 2), inclusive multicast
Ethernet tag (type 3), Ethernet segment (type 4) and IP prefix routes (type 5)
together with the route targets, encapsulation, PMSI tunnel, router's MAC,
MAC mobility and ESI label attributes. Other route types are ignored.

Labels are decoded as 20 bit MPLS labels unless the encapsulation extended
community signals a VNI based encapsulation like VXLAN (RFC 8365).

EVPN routes are stored per session (Adj-RIB-In), like IPv4 and IPv6 routes,
and can be displayed with the ``bgp-evpn-routes`` :ref:`command <api>`.
Withdrawn routes and routes of sessions which went down are kept as
inactive entries.

``$ sudo bngblaster-cli run.sock bgp-evpn-routes route-type 2``

Traffic streams can dynamically resolve the inner (VPN) label from learned
EVPN routes. The label2 of a MAC/IP advertisement route (symmetric IRB)
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

Streams wait until a matching active route with an MPLS label is learned
and are rebuilt automatically if the label changes. If the same route is
received from multiple sessions (e.g. redundant route reflectors), streams
use the route of the first session in configuration order and keep using it
as long as it is active. If this route is withdrawn or the session goes down,
streams switch to the same route of the next session.

EVPN streams require at least one BGP session with ``learn-routes`` and
family ``evpn``. The ``stream-info`` :ref:`command <api>` shows
``evpn-resolved`` for those streams and the resolved ``evpn-label``. The route
is resolved when the stream is scheduled for sending, so stopped streams show
``evpn-resolved`` false.

EVPN VPWS (E-LINE)
~~~~~~~~~~~~~~~~~~

EVPN VPWS (:rfc:`8214`) services are signaled with per-EVI Ethernet
auto-discovery routes (type 1) with the local VPWS service identifier
as Ethernet tag, the VPWS label and the EVPN Layer 2 Attributes extended
community (control word, primary and backup flags and L2 MTU).

In a typical setup, the BNG Blaster emulates the remote PE with a BGP
session to the device under test (DUT) and an MPLS network interface, while a
second network interface emulates the CE connected to the attachment circuit
of the DUT. The routes of the emulated PE are advertised using a
:ref:`RAW update file <bgp>` generated with ``bgpupdate --evpn-vpws``.
The Ethernet tag advertised by the BNG Blaster is the remote service identifier
configured on the DUT and the stream uses the route of the DUT with its local
service identifier.

Traffic streams with ``bgp-evpn-rd`` and ``bgp-evpn-ethernet-tag`` (optionally
``bgp-evpn-esi``) but without ``bgp-evpn-mac`` or ``bgp-evpn-prefix`` resolve
the VPWS label of the DUT and send the stream packets as Ethernet frames
over MPLS to the ``destination-mac`` of the CE. The control word is added if
requested by the DUT. Customer VLAN tags within the VPWS service can be added
with ``vpws-vlan`` and ``vpws-inner-vlan``.

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

The CE interface uses the MAC address of the emulated PE interface as
``gateway-mac`` so that CE to PE traffic is received by the PE interface.
The following example assumes the MAC addresses 02:00:00:00:00:01 for
``eth1`` (PE) and 02:00:00:00:00:02 for ``eth2`` (CE) and a directly
connected DUT without transport label towards the BNG Blaster.

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
                    "gateway-mac": "02:00:00:00:00:01"
                }
            ]
        },
        "bgp": [
            {
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "local-as": 65001,
                "peer-as": 65001,
                "learn-routes": true,
                "raw-update-file": "vpws.bgp",
                "family": [ "evpn" ]
            }
        ],
        "streams": [
            {
                "name": "VPWS-1000-PE-CE",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth1",
                "network-ipv4-address": "192.0.2.1",
                "destination-ipv4-address": "192.0.2.2",
                "destination-mac": "02:00:00:00:00:02",
                "tx-label1": 16001,
                "bgp-evpn-rd": "10.0.0.1:100",
                "bgp-evpn-ethernet-tag": 1000
            },
            {
                "name": "VPWS-1000-CE-PE",
                "type": "ipv4",
                "direction": "downstream",
                "pps": 1000,
                "network-interface": "eth2:100",
                "network-ipv4-address": "192.0.2.2",
                "destination-ipv4-address": "192.0.2.1",
                "rx-label1": 5000
            }
        ]
    }

The RAW update file and streams for the example above can be generated
with ``bgpupdate``, where ``--stream-evpn-rd`` is the route distinguisher
of the DUT routes. The generated streams are named ``vpws-<service-id>-pe-ce``
and ``vpws-<service-id>-ce-pe``. The ``--stream-direction`` selects PE to CE
(downstream, default), CE to PE (upstream) or both streams.

.. code-block:: none

    bgpupdate --evpn-vpws -n 10.0.1.2 --rd 10.0.1.2:100 --rt 65001:100 \
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
updates (``--withdraw``) require only ``--rd``.

RAW Update Files
~~~~~~~~~~~~~~~~

The BNG Blaster can inject BGP messages from a pre-compiled
RAW update file into the defined sessions. A RAW update file is nothing
more than a pre-compiled binary stream of BGP messages, typically
but not limited to update messages.

.. code-block:: none

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                                                               +
    |                           Marker                              |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Length               |      Type     | ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .
    .
    .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                                                               +
    |                           Marker                              |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Length               |      Type     | ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Those files can be created using the included BGP RAW update generator
script ``bgpupdate`` or manually using libraries like scapy or converters
from PCAP or MRT files. 

The configured ``raw-update-file`` under the BGP session is loaded
during BNG Blaster startup phase and sent as soon as the session is
established.

The ``bgp-raw-update`` :ref:`command <api>` allows sending further updates during
the session lifetime.

``$ sudo bngblaster-cli run.sock bgp-raw-update file update1.bgp``

This allows loading a full table after the BGP session has
started and manually triggering a series of changes using incremental
update files.

All BGP RAW update files are loaded once and can then be used for
multiple sessions. This means that if two or more sessions reference the
same file identified by file name, this file is loaded once into
memory and used by multiple sessions.

Therefore for incremental updates, it may make sense to pre-load
them via the ``bgp-raw-update-files`` configuration option.

.. code-block:: json

    {
        "bgp": [
            {
                "local-address": "10.0.1.2",
                "peer-address": "10.0.1.1",
                "raw-update-file": "start.bgp",
                "local-as": 65001,
                "peer-as": 65001
            }
        ],
        "bgp-raw-update-files": [
            "update1.bgp",
            "update2.bgp"
        ]
    }

Incremental updates not listed here will be loaded dynamically as soon
as referenced by the first session.

BGP RAW Update Generator
~~~~~~~~~~~~~~~~~~~~~~~~

The BGP RAW update generator is a simple tool to generate BGP RAW update
streams for use with the BNG Blaster. 

.. code-block:: none

    $ bgpupdate --help
    usage: bgpupdate [-h] [-a ASN] -n ADDRESS [-N N] [-p PREFIX] [-P N] [-m LABEL]
                     [-M N] [-l LOCAL_PREF] [-f FILE] [-w] [-s STREAMS]
                     [--med MED] [--stream-tx-label LABEL]
                     [--stream-tx-inner-label LABEL] [--stream-rx-label LABEL]
                     [--stream-rx-label-num N] [--stream-pps N]
                     [--stream-interface IFACE] [--stream-group-id N]
                     [--stream-direction {upstream,downstream,both}]
                     [--stream-append] [--end-of-rib] [--append] [--pcap FILE]
                     [--log-level {warning,info,debug}] [--evpn-vpws] [--rd RD]
                     [--rd-increment] [--rt RT] [--rt-increment] [--esi ESI]
                     [--service-id ID] [--service-num N] [--mtu MTU]
                     [--control-word] [--primary] [--backup] [--encap-mpls]
                     [--stream-ce-interface IFACE] [--stream-ce-vlan VLAN]
                     [--stream-vpws-vlan VLAN] [--stream-vpws-inner-vlan VLAN]
                     [--stream-vpws-qinq] [--stream-vpws-arp]
                     [--stream-evpn-rd RD] [--stream-evpn-service-id ID]
                     [--stream-destination-mac MAC] [--stream-pe-address ADDRESS]
                     [--stream-ce-address ADDRESS]

    The BGP RAW update generator is a simple tool to generate BGP RAW update
    streams for use with the BNG Blaster.

    options:
      -h, --help            show this help message and exit
      -a ASN, --asn ASN     autonomous system number
      -n ADDRESS, --next-hop-base ADDRESS
                            next-hop base address (IPv4 or IPv6)
      -N N, --next-hop-num N
                            next-hop count
      -p PREFIX, --prefix-base PREFIX
                            prefix base network (IPv4 or IPv6)
      -P N, --prefix-num N  prefix count
      -m LABEL, --label-base LABEL
                            label base
      -M N, --label-num N   label count
      -l LOCAL_PREF, --local-pref LOCAL_PREF
                            local preference
      -f FILE, --file FILE  output file
      -w, --withdraw        withdraw prefixes
      -s STREAMS, --streams STREAMS
                            generate BNG Blaster traffic stream file
      --med MED             MED
      --stream-tx-label LABEL
                            stream TX outer label
      --stream-tx-inner-label LABEL
                            stream TX inner label
      --stream-rx-label LABEL
                            stream RX label
      --stream-rx-label-num N
                            stream RX label count
      --stream-pps N        stream packets per seconds
      --stream-interface IFACE
                            stream interface
      --stream-group-id N   stream group identifier
      --stream-direction {upstream,downstream,both}
                            stream direction
      --stream-append       append to stream file if exist
      --end-of-rib          add end-of-rib message
      --append              append to file if exist
      --pcap FILE           write BGP updates to PCAP file
      --log-level {warning,info,debug}
                            logging Level

    EVPN VPWS (E-LINE):
      --evpn-vpws           generate EVPN VPWS per-EVI Ethernet A-D routes (route
                            type 1)
      --rd RD               route distinguisher (ASN:N, ASNL:N or IPv4:N)
      --rd-increment        increment route distinguisher per service
      --rt RT               route target (ASN:N, ASNL:N or IPv4:N)
      --rt-increment        increment route targets per service
      --esi ESI             ethernet segment identifier (default 0)
      --service-id ID       local VPWS service identifier base (ethernet tag)
      --service-num N       VPWS service count
      --mtu MTU             L2 MTU (default 0)
      --control-word        request control word (C flag)
      --primary             set primary flag (P flag)
      --backup              set backup flag (B flag)
      --encap-mpls          add MPLS encapsulation extended community
      --stream-ce-interface IFACE
                            stream CE interface (CE to PE streams)
      --stream-ce-vlan VLAN
                            stream CE interface VLAN base (incremented per
                            service)
      --stream-vpws-vlan VLAN
                            customer VLAN within VPWS base (incremented per
                            service, PE to CE streams)
      --stream-vpws-inner-vlan VLAN
                            customer inner VLAN within VPWS (PE to CE streams)
      --stream-vpws-qinq    customer outer VLAN ethertype 0x88a8 (PE to CE
                            streams)
      --stream-vpws-arp     reply to ARP, ND and ICMP echo and learn CE MAC (PE to
                            CE streams)
      --stream-evpn-rd RD   route distinguisher of DUT routes (PE to CE streams)
      --stream-evpn-service-id ID
                            DUT local VPWS service identifier base (default
                            --service-id)
      --stream-destination-mac MAC
                            CE interface MAC address (PE to CE streams)
      --stream-pe-address ADDRESS
                            PE side stream IPv4 address
      --stream-ce-address ADDRESS
                            CE side stream IPv4 address

The Python BGP RAW update generator is a Python script that uses
scapy to build BGP messages. Therefore this tool can be easily
modified, extended, or used as a blueprint for your own tools to generate
valid BGP update streams.

The following example shows how to generate a BGP update stream 
with IPv4 and labeled IPv6 prefixes (6PE).

* 100000 x IPv4 prefixes over 1000 next-hops
* 50000 x IPv6 prefixes over 1000 next-hops with 1000 different labels (label per next-hop)
* 50000 x IPv6 prefixes over 1000 next-hops with label 2 

.. code-block:: none

    bgpupdate -f test.bgp -a 65001 -l 100 -n 10.0.0.1 -N 1000 -p 10.1.0.0/24 -P 100000
    bgpupdate -f test.bgp -a 65001 -l 100 -n 10.0.0.1 -N 1000 -m 20001 -M 1000 -p fc66:1::/48 -P 50000 --append
    bgpupdate -f test.bgp -a 65001 -l 100 -n 10.0.0.1 -N 1000 -m 2 -p fc66:2::/48 -P 50000 --append --end-of-rib

By default, the file is replaced but the option ``--append`` allows it to append to an existing file.
The last update to a file should include the option ``--end-of-rib`` (optional).

The option ``--streams <file>`` (``-s``) automatically generates corresponding traffic streams
for all prefixes. By default, this file is replaced but the option ``--stream-append`` allows
appending to an existing file.

.. code-block:: none

    bgpupdate -f test.bgp -a 65001 -l 100 -n 10.0.0.1 -N 1000 -p 10.1.0.0/24 -P 100000 -s streams.json
    bgpupdate -f test.bgp -a 65001 -l 100 -n 10.0.0.1 -N 1000 -m 20001 -M 1000 -p fc66:1::/48 -P 50000 --append -s streams.json --stream-append
    bgpupdate -f test.bgp -a 65001 -l 100 -n 10.0.0.1 -N 1000 -m 2 -p fc66:2::/48 -P 50000 --append --end-of-rib -s streams.json --stream-append

There are several options supported to further define the traffic streams like PPS and expected RX labels.

BGP Convergence Testing
~~~~~~~~~~~~~~~~~~~~~~~

The following project demonstrates how to measure the convergence between the BGP Control-Plane (CP) 
and the Data-Plane (DP) using the BNG Blaster. By utilizing BNG Blaster, we can analyze and monitor 
the time it takes for routing changes to propagate from the control-plane, where BGP updates occur, 
to the data-plane, where actual data packet forwarding happens.

https://github.com/rtbrick/BGP-CP-DP-Testing
