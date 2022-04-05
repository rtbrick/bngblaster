.. _multicast:

Multicast and IPTV
------------------

The BNG Blaster provides advanced functionalities for testing multicast
over PPPoE sessions with focus on IPTV. Therefore IGMP version 1, 2 and 3
is implemented with support for up to 8 group records per session and 3
sources per group.

Multicast testing is supported using external multicast traffic like real
world IPTV traffic or by generating multicast traffic on the network interface.

Generate Multicast Traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~

The BNG Blaster supports different ways to generate multicast traffic. The first 
one is via igmp configuration and second one using raw streams.

The following example shows how to generate traffic for 100 multicast groups
with one packet per millisecond for every group. 

.. code-block:: json

    {
        "interfaces": {
            "tx-interval": 1.0,
            "rx-interval": 1.0,
            "network": {
                "interface": "eth2",
                "address": "100.0.0.10",
                "gateway": "100.0.0.2"
            }
        },
        "igmp": {
            "group": "239.0.0.1",
            "group-iter": "0.0.0.1",
            "group-count": 100,
            "source": "100.0.0.10",
            "send-multicast-traffic": true
        }
    }

It is recommended to send multicast traffic with 1000 PPS per group 
to measure the join and leave delay in milliseconds. Therefore the 
``tx-interval`` and ``rx-interval`` should be set to at to at least 
`1.0` (1ms) for more precise IGMP join/leave delay measurements.

It is also possible to generate multicast traffic using RAW streams as shown in the
example below:

.. code-block:: json

    {
        "streams": [
            {
                "name": "MC1",
                "type": "ipv4",
                "direction": "downstream",
                "priority": 128,
                "network-ipv4-address": "1.1.1.1",
                "destination-ipv4-address": "239.0.0.1",
                "length": 256,
                "pps": 1,
                "network-interface": "eth1"
            },
            {
                "name": "MC2",
                "type": "ipv4",
                "direction": "downstream",
                "priority": 128,
                "network-ipv4-address": "2.2.2.2",
                "destination-ipv4-address": "239.0.0.2",
                "length": 256,
                "pps": 1,
                "network-interface": "eth2"
            }
        ]
    }

Using RAW streams allows to generate streams distributed over multiple network interfaces
with higher transmit rate using threaded streams if needed.

Setting the ``destination-ipv4-address`` to an multicast IPv4 address is enough to generate
proper multicast streams. All headers including the BNG Blaster header will be automatically
set for multicast. Therefore such streams can be also used to measure the IGMP join and leave
delay.

The BNG Blaster is recognizing loss using the :ref:`BNG Blaster header <bbl_header>` 
sequence numbers. After first multicast traffic is received for a particular group, 
for every further packet it checks if there is a gap between last and new sequence number 
which is than reported as loss. The argument option ``-l loss`` enables loss logging which
allows to search for the missing packets in the corresponding capture files.

.. tip:: 
    It is also possible to start a dedicated BNG Blaster instance to generate multicast
    traffic which can be consumed by multiple BNG Blaster instances. The BNG Blaster
    header allows to do the same measurements on traffic generated from same or different
    BNG Blaster instance.

Manual Join/Leave Testing
~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to join and leave multicast groups manually using the :ref:`command <api>`
``igmp-join``.

``$ sudo bngblaster-cli run.sock igmp-join session-id 1 group 232.1.1.1 source1 202.11.23.101 source2 202.11.23.102 source3 202.11.23.103``

.. code-block:: json

    {
        "status": "ok"
    }

``$ sudo bngblaster-cli run.sock igmp-info session-id 1``

.. code-block:: json

    {
        "status": "ok",
        "igmp-groups": [
            {
                "group": "232.1.1.1",
                "igmp-sources": [
                    "202.11.23.101",
                    "202.11.23.102",
                    "202.11.23.103"
                ],
                "packets": 1291,
                "loss": 0,
                "state": "active",
                "join-delay-ms": 139
            }
        ]
    }

``$ sudo bngblaster-cli run.sock igmp-leave session-id 1 group 232.1.1.1``

.. code-block:: json

    {
        "status": "ok"
    }

``$ sudo bngblaster-cli run.sock igmp-info session-id 1``

.. code-block:: json

    {
        "status": "ok",
        "igmp-groups": [
            {
                "group": "232.1.1.1",
                "igmp-sources": [
                    "202.11.23.101",
                    "202.11.23.102",
                    "202.11.23.103"
                ],
                "packets": 7456,
                "loss": 0,
                "state": "idle",
                "leave-delay-ms": 114
            }
        ]
    }

IPTV Zapping Test
~~~~~~~~~~~~~~~~~

A key element of IPTV services is the delay in changing channels.
How long does it take to change from one channel to another, is
the right channel received and the old channel stopped without overlap
between old and new channel which may leads into traffic congestions if
both channels are send at the same time. Verify that fast channel changes
(zapping) works reliable as well.

The BNG Blaster is able to emulate different client zapping behaviors and
measure the resulting join/leave delays and possible multicast traffic loss.

The join delay is the time in milliseconds between sending join and receiving
first multicast packet of the requested group. The leave delay is the time between
sending leave and the last multicast packet received for this group. Multicast packets
received for the leaved group after first packet of joined group is received are counted
as overlap.

The following configuration shows an example of the ``igmp`` section
for a typical zapping test.

.. code-block:: json

    {
        "igmp": {
            "version": 3,
            "start-delay": 10,
            "group": "239.0.0.1",
            "group-iter": "0.0.0.1",
            "group-count": 20,
            "source": "100.0.0.10",
            "zapping-interval": 5,
            "zapping-count": 5,
            "zapping-view-duration": 30,
            "zapping-wait": false,
            "combined-leave-join": true,
            "send-multicast-traffic": true
        }
    }

.. include:: ../configuration/igmp.rst

Multicast Limitations
~~~~~~~~~~~~~~~~~~~~~

The BNG Blaster IGMP implementation supports up to 3 sources per group record
and 8 group records per session.

The check for overlapping multicast traffic is supported for zapping tests only.
