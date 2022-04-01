.. _session-traffic:

Session Traffic
---------------

The BNG Blaster is able to generate bidirectional unicast
session traffic for all addresses assigned to a session
(IPv4, IPv6 and IPv6PD). 

.. image:: ../images/bbl_session_traffic.png
    :alt: Session Traffic

This is a powerful tool to quickly verify that forwarding
is correctly setup and working. 

Configuration
~~~~~~~~~~~~~

The following example shows how to enable session-traffic. 

.. code-block:: json

    {
        "session-traffic": {
            "ipv4-pps": 1,
            "ipv6-pps": 1,
            "ipv6pd-pps": 1
        }
    }

.. include:: ../configuration/isis.rst

This traffic is generated between the session and a network 
interface. In case of multiple network interfaces, the preferred
network interfaces can be selected using the ``network-interface`` 
option in the corresponding access configuration.

Verification
~~~~~~~~~~~~

The final report includes detailed information 
for session traffic. 

*Example report output for 100 sessions:*

.. code-block:: none 

    Session Traffic:
    Config:
        IPv4    PPS:           1
        IPv6    PPS:           1
        IPv6PD  PPS:           1
    Verified Traffic Flows: 3000/3000
        Access  IPv4:        500
        Access  IPv6:        500
        Access  IPv6PD:      500
        Network IPv4:        500
        Network IPv6:        500
        Network IPv6PD:      500
    First Sequence Number Received:
        Access  IPv4    MIN:        1 ( 1.000s) MAX:        2 ( 2.000s)
        Access  IPv6    MIN:        2 ( 2.000s) MAX:        2 ( 2.000s)
        Access  IPv6PD  MIN:        2 ( 2.000s) MAX:        2 ( 2.000s)
        Network IPv4    MIN:        1 ( 1.000s) MAX:        2 ( 2.000s)
        Network IPv6    MIN:        2 ( 2.000s) MAX:        2 ( 2.000s)
        Network IPv6PD  MIN:        2 ( 2.000s) MAX:        2 ( 2.000s)


The statistics starting with ``Access ...`` correspond to traffic
received on the access interface (network->access) where those 
starting with ``Network ...`` correspond to traffic received on 
the network interface (access->network).

The ``First Sequence Number Received`` is used to measure the forwarding 
convergence. The session traffic starts automatically as soo as the session
is established using the rate configured. All traffic flows in the BNG Blaster
start with the 64bit sequence number 1. Assuming the first sequence number 
received for given flow is 5 combined with a rate of 1 PPS would mean that 
it took between 4 and 5 seconds until forwarding is working.