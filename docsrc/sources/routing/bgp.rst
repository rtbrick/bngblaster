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

TCP options other than TCP-AO are included in the MAC by default. Some
implementations exclude them by default (e.g. Junos without ``tcp-ao-option``
enabled), which requires ``tcp-ao-exclude-options`` to be enabled. Otherwise,
both sides reject the segments of the other side (MAC verification failed).

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
received from the peer, which can be displayed with the ``bgp-evpn-routes``
:ref:`command <api>`. EVPN routes are used to resolve the labels of traffic
streams for L3 EVPN, EVPN VPWS (E-LINE) and EVPN E-LAN services. The routes
of an emulated PE are generated with ``bgpupdate --evpn-vpws`` or
``bgpupdate --evpn-elan``. See :ref:`EVPN <evpn>` for details and how
to test EVPN services.

BGP L2VPN
~~~~~~~~~

With ``learn-routes`` enabled and the family ``l2vpn``, the BNG Blaster learns
the BGP L2VPN label blocks (:rfc:`6624`) received from the peer, which can be
displayed with the ``bgp-l2vpn-routes`` :ref:`command <api>` and used to resolve
the pseudowire labels of traffic streams. The label blocks of an emulated PE are
generated with ``bgpupdate --l2vpn``. See :ref:`BGP L2VPN <l2vpn>` for details
and how to test BGP L2VPN services.

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

The ``bgp-sessions`` :ref:`command <api>` shows the progress of the RAW
update file in ``raw-update-state`` (``wait``, ``sending`` or ``done``).
The update counters (``update-tx``) are incremented once the whole file
is sent and acknowledged. The bytes of the file acknowledged by the peer
so far are shown in ``raw-update-bytes-acked`` (of ``raw-update-bytes``).
The ``tcp`` object shows the bytes sent but not yet acknowledged
(``send-queue``), the free TCP send buffer (``send-buffer-free``) and
the receive window of the peer (``peer-window``). A ``peer-window`` of
zero means that the peer does not accept further data at the moment
(receiver backpressure).

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
                     [--stream-ce-address ADDRESS] [--evpn-elan]
                     [--ethernet-tag TAG] [--mac MAC] [--l2vpn] [--ce-id ID]
                     [--label-block-offset N] [--label-block-size N]
                     [--encapsulation {ethernet-vlan,ethernet}]
                     [--stream-l2vpn-rd RD] [--stream-l2vpn-ce-id ID]

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
      --control-word        request control word (C flag), E-LAN streams send and
                            expect control word
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

    EVPN E-LAN:
      EVPN E-LAN routes use the --rd, --rt, --esi, --service-num, --encap-mpls,
      --control-word and --stream-* options of EVPN VPWS, where --stream-vpws-*
      sets the customer VLAN

      --evpn-elan           generate EVPN E-LAN IMET (route type 3) and MAC/IP
                            routes (route type 2)
      --ethernet-tag TAG    ethernet tag (default 0)
      --mac MAC             MAC address advertised per EVI (e.g. PE interface MAC)

    BGP L2VPN (RFC 6624):
      BGP L2VPN routes use the --rd, --rt, --rd-increment, --rt-increment,
      --service-num (instances), --mtu, --control-word and --stream-* options of
      EVPN VPWS, where --stream-vpws-* sets the customer VLAN

      --l2vpn               generate BGP L2VPN label blocks (RFC 6624)
      --ce-id ID            local CE ID (default 1)
      --label-block-offset N
                            label block offset, first remote CE ID (default 1)
      --label-block-size N  label block size (default 8)
      --encapsulation {ethernet-vlan,ethernet}
                            encapsulation type (default ethernet-vlan)
      --stream-l2vpn-rd RD  route distinguisher of DUT routes (PE to CE streams)
      --stream-l2vpn-ce-id ID
                            DUT CE ID

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
