BNG Blaster Traffic
-------------------

.. _bbl_header:

Blaster Header and Fast Decode Signature
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The 48 Byte fixed size BNG Blaster Header is added to all data packets
for traffic validation and fast decoding. The header is expected on the
last 48 bytes of the packet.

The type is set to 1 for all unicast session traffic and 2 for
IPv4 multicast traffic.

Unicast Session Traffic
^^^^^^^^^^^^^^^^^^^^^^^

The 64 bit session key is used for all traffic from access (upstream)
and to access (downstream) interfaces to identify the corresponding
session which has sent or should receive the packet.

.. code-block:: none

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | BNG Blaster Magic Sequence                                    |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Type          | Sub-Type      | Direction     | TX TOS        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Session Identifier                                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Session Access Interface Index                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Session Outer VLAN            | Session Inner VLAN            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Flow Identifier                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Flow Sequence Number                                          |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Nanosecond Send Timestamp                                     |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

.. image:: ../images/bbl_header.png
    :alt: BNG Blaster Header

Multicast Traffic
^^^^^^^^^^^^^^^^^

.. code-block:: none

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | BNG Blaster Magic Sequence                                    |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Type          | Sub-Type      | Direction     | TX TOS        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Reserved                                                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Source                                                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Group                                                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Flow Identifier                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Flow Sequence Number                                          |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Nanosecond Send Timestamp                                     |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

.. note:: 
    All attributes except IP addresses in the Blaster Header are
    stored in host byte order for faster processing
    (LE or BE depending on test system).

BNG Blaster Magic Sequence
^^^^^^^^^^^^^^^^^^^^^^^^^^

The 64 bit magic sequence is the word ``RtBrick!`` decoded as ASCII:

.. code-block:: none

    0x5274427269636b21

Storing the magic number on a fixed offset allows fast identification 
of blaster traffic. 

Flow Identifier
^^^^^^^^^^^^^^^

The 64 bit flow identifier is a globally unique number that identifies
the flow.

Flow Sequence Number
^^^^^^^^^^^^^^^^^^^^

The 64 bit flow sequence number is a sequential number starting with 1
and incremented per packet primary used to identify packet loss.

This number 0 means that sequencing is disabled.

Nanosecond Send Timestamps
^^^^^^^^^^^^^^^^^^^^^^^^^^

The 64 bit nanoseconds send timestamp is used for optional latency and
jitter calculations.

.. code-block:: none

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Seconds                                                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Nano Seconds                                                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The timestamp 0 means that timestamps are disabled.