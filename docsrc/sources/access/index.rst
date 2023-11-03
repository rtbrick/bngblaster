Access Protocols
================

A BNG, or Broadband Network Gateway, is a network device that 
connects customer premises equipment to the service provider's 
broadband network, managing user authentication, traffic routing, 
and quality of service (QoS) for internet services.

.. _sessions:

The BNG Blaster is equipped with versatile support for various 
access protocols, allowing the creation of seubscriber sessions, 
each of which can comprise multiple protocols. For instance, in the 
case of dual-stack IPoE sessions, these are formed by a combination of 
DHCPv4, DHCPv6, as well as ARP/ND protocols. Every session is 
defined by an :ref:`access interface function <access-interface>` 
and identified by a globally unique **session-id**, with the 
numbering starting at 1 and increasing sequentially for each 
new session established. Furthermore, you have the flexibility 
to group multiple sessions together using the optional 
**session-group-id**, which enables the application of commands
:ref:`commands <api>` to an entire group of sessions simultaneously. 

.. code-block:: json

    {
        "access": [
            {
                "interface": "eth1",
                "type": "pppoe",
                "session-group-id": 1,
                "username": "even@rtbrick.com",
                "outer-vlan-min": 1000,
                "outer-vlan-max": 1998,
                "outer-vlan-step": 2,
                "inner-vlan": 7
            },
            {
                "interface": "eth1",
                "type": "pppoe",
                "session-group-id": 2,
                "username": "odd@rtbrick.com",
                "outer-vlan-min": 1001,
                "outer-vlan-max": 1999,
                "outer-vlan-step": 2,
                "inner-vlan": 7
            },
        ]
    }

It is also possible to assign multiple access interface
sections to a single session group. 

.. toctree::
   :maxdepth: 1

   pppoe.rst
   ipoe.rst
   l2tp.rst
   l2bsa.rst
   traffic.rst
   multicast.rst
   li.rst
   monkey.rst
