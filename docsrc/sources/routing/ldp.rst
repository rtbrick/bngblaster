.. _ldp:

LDP
---

Label Distribution Protocol (LDP) is a protocol in which routers capable 
of Multiprotocol Label Switching (MPLS) exchange label mapping information. 
Two routers with an established session are called LDP peers and the exchange 
of information is bi-directional. LDP is used to build and maintain LSP databases 
that are used to forward traffic through MPLS networks.

LDP discovery runs on UDP port 646 and the session is built on TCP port 646. During 
the discovery phase hello packets are sent on UDP port 646 to the 'all routers on this subnet' 
group multicast address (224.0.0.2).

LDP is defined by the IETF (RFC 5036).

Configuration
~~~~~~~~~~~~~

Following an example LDP configuration with one instance
attached to a network interface function.

.. code-block:: json

    {
        "interfaces": {
            "network": [
                {
                    "interface": "eth1",
                    "address": "10.0.1.2/24",
                    "gateway": "10.0.1.1",
                    "ldp-instance-id": 1,
                }
            ]
        },
        "ldp": [
            {
                "instance-id": 1,
                "lsr-id": "10.10.10.11"
            }
        ]
    }

.. include:: ../configuration/ldp.rst

Limitations
~~~~~~~~~~~

The following LDP functionalities are currently 
not supported:

+ Targeted LDP
+ LDP TCP authentication
+ LDP sessions between IPv6 addresses 
+ Learn IPv6 label mappings
+ Multiple links between LDP instance and DUT (ECMP)

LDP Adjacencies
~~~~~~~~~~~~~~~~

When the BNG Blaster receives an LDP discovery hello message, 
an LDP adjacency is set up between the two peers.

``$ sudo bngblaster-cli run.sock ldp-adjacencies``

.. code-block:: json
    {
        "status": "ok",
        "code": 200,
        "ldp-adjacencies": [
            {
                "ldp-instance-id": 1,
                "interface": "eth0",
                "state": "up"
            }
        ]
    }

LDP Sessions
~~~~~~~~~~~~

LDP peers exchange messages over a TCP session which is initiated by 
the peer with the larger transport IP address (active peer). 

The LDP transport IP address can be explicitly configured for the 
LDP instance using the option `ipv4-transport-address`. The `lsr-id`
is used as a transport IP address if not explicitly configured.

.. note:: 
    
    It is currently not supported to setup multiple links between 
    a single LDP instance and the device under test (ECMP).

``$ sudo bngblaster-cli run.sock ldp-sessions``

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "ldp-sessions": [
            {
                "ldp-instance-id": 1,
                "interface": "eth0",
                "local-address": "10.2.3.1",
                "local-identifier": "10.2.3.1:0",
                "peer-address": "10.2.3.2",
                "peer-identifier": "10.2.3.2:0",
                "state": "operational",
                "raw-update-state": "done",
                "raw-update-file": "out.ldp",
                "stats": {
                    "pdu-rx": 23,
                    "pdu-tx": 32,
                    "messages-rx": 24,
                    "messages-tx": 34,
                    "keepalive-rx": 21,
                    "keepalive-tx": 21
                }
            }
        ]
    }

LDP Traffic Streams
~~~~~~~~~~~~~~~~~~~

Traffic streams send from network interface functions (downstream)
can be configured to dynamically resolve the outer MPLS 
label using the learned label mappings.

The traffic stream configuration option `ldp-ipv4-lookup-address`
specifies the lookup IPv4 address. This means that traffic
will not start until this address is found in the corresponding
label database of the sending network interface function. 

.. code-block:: json

    {
        "streams": [
            {
                "name": "S1",
                "type": "ipv4",
                "direction": "downstream",
                "priority": 128,
                "network-interface": "eth1",
                "destination-ipv4-address": "10.0.0.1",
                "ldp-ipv4-lookup-address": "13.37.0.1",
                "pps": 1
            }
        ]
    }

``$ sudo bngblaster-cli run.sock ldp-database instance 1``

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "ldp-database": [
            {
                "direction": "ipv4",
                "prefix": "10.0.0.0/24",
                "label": 3,
                "source-identifier": "10.2.3.1:0"
            },
            {
                "direction": "ipv4",
                "prefix": "13.37.0.0/32",
                "label": 10000,
                "source-identifier": "10.2.3.1:0"
            },
            {
                "direction": "ipv4",
                "prefix": "13.37.0.1/32",
                "label": 10001,
                "source-identifier": "10.2.3.1:0"
            }
        ]
    }

The `ldp-ipv4-lookup-address` must exactly match the prefix address
as shown in the LDP database. 

.. note::

    There is currently no longest prefix match supported, 
    meaning that the actual prefix length is ignored! 

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

Those files can be created using the included LDP RAW update generator
script ``ldpupdate`` or manually using libraries like scapy. 

The configured ``raw-update-file`` under the LDP instance is loaded 
during BNG Blaster startup phase and send it as soon as the session is 
established. 

The ``ldp-raw-update`` :ref:`command <api>` allows to send further updates during
the session lifetime.

``$ sudo bngblaster-cli run.sock ldp-raw-update file update1.ldp``

This allows loading label mappings after the LDP session has
started and manually trigger a series of changes using incremental
updates files.

All LDP RAW update files are loaded once and can then be used for 
multiple sessions. Meaning if two or more sessions reference the 
same file identified by file name, this file is loaded once into 
memory and used by multiple sessions. 

LDP RAW Update Generator
~~~~~~~~~~~~~~~~~~~~~~~~

The LDP RAW update generator is a simple tool to generate LDP RAW update
streams for use with the BNG Blaster. 

.. code-block:: none

    $ ldpupdate --help
    usage: ldpupdate [-h] -l ADDRESS [-i N] -p PREFIX [-P N] [-m LABEL] [-M N]
                    [-f FILE] [--append] [--pcap FILE]
                    [--log-level {warning,info,debug}]

    The LDP RAW update generator is a simple tool to generate LDP RAW update
    streams for use with the BNG Blaster.

    optional arguments:
    -h, --help            show this help message and exit
    -l ADDRESS, --lsr-id ADDRESS
                            LSR identifier
    -i N, --message-id-base N
                            message identifier base
    -p PREFIX, --prefix-base PREFIX
                            prefix base network
    -P N, --prefix-num N  prefix count
    -m LABEL, --label-base LABEL
                            label base
    -M N, --label-num N   label count
    -f FILE, --file FILE  output file
    --append              append to file if exist
    --pcap FILE           write LDP updates to PCAP file
    --log-level {warning,info,debug}
                            logging Level

The python LDP RAW update generator is a python script that uses
scapy to build LDP PDU. Therefore this tool can be easily 
modified, extend or used as a blueprint for your own tools to generate
valid LDP update streams. 