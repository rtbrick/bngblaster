.. _bgp:

BGP
---

The Border Gateway Protocol (BGP) is a standardized exterior gateway protocol
designed to exchange routing and reachability information among autonomous systems
(AS) on the internet. BGP is classified as a path-vector routing protocol, and it 
makes routing decisions based on paths, network policies, or rule-sets configured 
by a network operator.

Configuration
~~~~~~~~~~~~~

Following an example BGP configuration with one session.

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
                "local-ipv4-address": "10.0.1.2",
                "peer-ipv4-address": "10.0.1.1",
                "raw-update-file": "test.bgp",
                "local-as": 65001,
                "peer-as": 65001
            }
        ]
    }

.. include:: ../configuration/bgp.rst


BGP Sessions
~~~~~~~~~~~~

Every BGP session is opened with the capabilities for the following
address families:

+ IPv4 unicast
+ IPv4 labelled unicast
+ IPv6 unicast
+ IPv6 labelled unicast

Limitations
~~~~~~~~~~~

BGP authentication is currently not supported but already 
planned as enhancement in one of the next releases. 

RAW Update Files
~~~~~~~~~~~~~~~~

The BNG Blaster is able to inject BGP messages from a pre-compiled 
RAW update file into the defined sessions. A RAW update file is not
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
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++++
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
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++++

Those files can be created using the included BGP RAW update generator
script ``bgpupdate`` or manually using libraries like scapy or converters
from PCAP or MRT files. 

The configured ``raw-update-file`` under the BGP session is loaded 
during Blaster startup phase and send as soon as the session is 
established. 

The ``bgp-raw-update`` :ref:`command <api>` allows to send further updates during
the session lifetime.

``$ sudo bngblaster-cli run.sock bgp-raw-update file update1.bgp``

This allows in example to load a full table after session has
started and manually trigger a series of changes using incremental
updates files.

All BGP RAW update files are loaded once and can than be used by 
multiple sessions. Meaning if two or more sessions reference the 
same file identified by file name, this file is loaded once into 
memory and used by multiple sessions. 

Therefore for incremental updates, it may makes sense to pre-load
via ``bgp-raw-update-files`` configuration. 

.. code-block:: json

    {
        "bgp": [
            {
                "local-ipv4-address": "10.0.1.2",
                "peer-ipv4-address": "10.0.1.1",
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
as referenced by first session.

BGP RAW Update Generator
~~~~~~~~~~~~~~~~~~~~~~~~

The BGP RAW update generator is a simple tool to generate BGP RAW update
streams for use with the BNG Blaster. 

.. code-block:: none

    $ bgpupdate --help
    usage: bgpupdate [-h] [-a ASN] -n ADDRESS [-N N] -p PREFIX [-P N] [-m LABEL]
                    [-M N] [-l LOCAL_PREF] [-f FILE] [-w] [-s STREAMS]
                    [--stream-tx-label LABEL] [--stream-tx-inner-label LABEL]
                    [--stream-rx-label LABEL] [--stream-rx-label-num N]
                    [--stream-threads N] [--stream-pps N]
                    [--stream-interface IFACE] [--stream-append] [--end-of-rib]
                    [--append] [--pcap FILE] [--log-level {warning,info,debug}]

    The BGP RAW update generator is a simple tool to generate BGP RAW update
    streams for use with the BNG Blaster.

    optional arguments:
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
    --stream-tx-label LABEL
                            stream TX outer label
    --stream-tx-inner-label LABEL
                            stream TX inner label
    --stream-rx-label LABEL
                            stream RX label
    --stream-rx-label-num N
                            stream RX label count
    --stream-threads N    stream TX threads
    --stream-pps N        stream packets per seconds
    --stream-interface IFACE
                            stream interface
    --stream-append       append to stream file if exist
    --end-of-rib          add end-of-rib message
    --append              append to file if exist
    --pcap FILE           write BGP updates to PCAP file
    --log-level {warning,info,debug}
                            logging Level



The python BGP RAW update generator is a python script which uses
scapy to build BGP messages. Therefore this tool can be easily 
modified, extend or used as blueprint for your own tools to generate
valid BGP update streams. 

The following example shows how to generate a BGP update stream 
with IPv4 and labelled IPv6 prefixes (6PE).

* 100000 x IPv4 prefixes over 1000 next-hops
* 50000 x IPv6 prefixes over 1000 next-hops with 1000 different labels (label per next-hop)
* 50000 x IPv6 prefixes over 1000 next-hops with label 2 

.. code-block:: none

    bgpupdate -f test.bgp -a 65001 -n 10.0.0.1 -N 1000 -p 10.1.0.0/24 -P 100000
    bgpupdate -f test.bgp -a 65001 -n 10.0.0.1 -N 1000 -m 20001 -M 1000 -p fc66:1::/48 -P 50000 --append
    bgpupdate -f test.bgp -a 65001 -n 10.0.0.1 -N 1000 -m 2 -p fc66:2::/48 -P 50000 --append --end-of-rib

Per default the file is replaced but the option `--append` allows to append to an existing file. 
The last update to an file should include the option `--end-of-rib` (optional). 

The option `--streams <file>` (`-s`) automatically generates corresponding traffic streams
for all prefixes. Per default this file is replaced but the option `--stream-append` allows
to append to an existing file. 

.. code-block:: none

    bgpupdate -f test.bgp -a 65001 -n 10.0.0.1 -N 1000 -p 10.1.0.0/24 -P 100000 -s streams.json
    bgpupdate -f test.bgp -a 65001 -n 10.0.0.1 -N 1000 -m 20001 -M 1000 -p fc66:1::/48 -P 50000 --append -s streams.json --stream-append
    bgpupdate -f test.bgp -a 65001 -n 10.0.0.1 -N 1000 -m 2 -p fc66:2::/48 -P 50000 --append --end-of-rib -s streams.json --stream-append

There are several options supported to further define the traffic streams like PPS and expected RX labels.