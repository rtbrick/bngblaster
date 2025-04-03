.. _configuration:

.. raw:: html

   <link rel="stylesheet" type="text/css" href="_static/custom.css">

Configuration
=============

The BNG Blaster configuration is presented as a JSON file. 
This configuration must include at least one interface function.

.. code-block:: json

    {
        "interfaces": {
            "network": {
                "interface": "eth2",
                "address": "10.0.0.10/24",
                "gateway": "10.0.0.2"
            }
        }
    }

In order to minimize the size of this configuration, you have the option 
to relocate the stream definitions to a separate file. However, it's important 
to note that both the streams specified in the main configuration file and 
the additional streams configuration file will be applied. This approach 
proves particularly beneficial when conducting tests that involve an extensive 
number of traffic streams, numbering in the millions. By separating the streams 
into distinct files, you can maintain a more organized and manageable 
configuration while ensuring that the combined streams are effectively utilized 
in your testing scenarios. This flexibility in configuration empowers you to 
handle large-scale traffic simulations with ease.

.. code-block:: bash

    bngblaster -C config.json -T streams.json 

.. _variables:

Variables
---------

Some configuration attributes like **username**, **password**, **agent-remote-id**, 
**agent-circuit-id**, or **cfm-ma-name** support variable substitution. 
The variable **{session-global}** will be replaced with the actual session-id 
starting from 1 and incremented for every new session. The variable **{session}** 
is incremented per-interface section. The variables **{outer-vlan}** and **{inner-vlan}** 
will be replaced with the corresponding VLAN identifier or 0 if not defined. 
The two variables **{i1}** and **{i2}** are configurable per-interface sections 
with user-defined start values and steps. 

.. code-block:: json

    { 
        "username": "user{session-global}@rtbrick.com",
        "agent-circuit-id": "0.0.0.0/0.0.0.0 eth {outer-vlan}:{inner-vlan}",
        "agent-remote-id": "DEU.RTBRICK.{i1}",
        "i1-start": 10000,
        "i1-step": 2
    }

Interfaces
----------

The BNG Blaster interfaces are explained detailed in the 
:ref:`interfaces section <interfaces>`.

.. include:: interfaces.rst

Links
~~~~~
.. include:: interfaces_links.rst

Link Aggregation (LAG)
~~~~~~~~~~~~~~~~~~~~~~
.. include:: interfaces_lag.rst

Network Interfaces
~~~~~~~~~~~~~~~~~~
.. include:: interfaces_network.rst

Access Interfaces
~~~~~~~~~~~~~~~~~
.. include:: interfaces_access.rst

A10NSP Interfaces
~~~~~~~~~~~~~~~~~

The :ref:`L2BSA <l2bsa>` specification defines two interfaces. 
The so-called U interface (User Interface) at the customer location 
and the A10-NSP interface (A10 Network Service Provider) 
between the service provider networks. 

The BNG Blaster A10NSP interface emulates such a layer two provider interface. 
This interface type accepts all DHCPv4 and PPPoE sessions were received to verify 
forwarding and header enrichment.

.. include:: interfaces_a10nsp.rst

Sessions
--------
.. include:: sessions.rst

IPoE
----
.. include:: ipoe.rst

PPPoE
-----
.. include:: pppoe.rst

PPP
---
.. include:: ppp.rst

PPP Authentication
~~~~~~~~~~~~~~~~~~
.. include:: ppp_authentication.rst

PPP LCP
~~~~~~~~~~~~~~~~~~
.. include:: ppp_lcp.rst

PPP IPCP (IPv4)
~~~~~~~~~~~~~~~
.. include:: ppp_ipcp.rst

PPP IP6CP (IPv6)
~~~~~~~~~~~~~~~~
.. include:: ppp_ip6cp.rst

DHCP
----
.. include:: dhcp.rst

DHCPv6
------
.. include:: dhcpv6.rst

IGMP
----
.. include:: igmp.rst

L2TPv2 Server (LNS)
-------------------
.. include:: lns.rst

Traffic
-------
.. include:: traffic.rst

Traffic-Streams
---------------
.. include:: streams.rst

Session-Traffic
---------------
.. include:: session_traffic.rst

Access-Line
-----------
.. include:: access_line.rst

Access-Line-Profiles
--------------------
.. include:: access_line_profiles.rst

ISIS
----
.. include:: isis.rst

ISIS External
~~~~~~~~~~~~~
.. include:: isis_external.rst


ISIS External Connections
~~~~~~~~~~~~~~~~~~~~~~~~~
.. include:: isis_external_connections.rst

OSPF
----
.. include:: ospf.rst

OSPF External
~~~~~~~~~~~~~
.. include:: ospf_external.rst


OSPF External Connections
~~~~~~~~~~~~~~~~~~~~~~~~~
.. include:: ospf_external_connections.rst

LDP
---
.. include:: ldp.rst

BGP
---
.. include:: bgp.rst

HTTP-Client
-----------
.. include:: http_client.rst

HTTP-Server
-----------
.. include:: http_server.rst

ICMP-Client
-----------
.. include:: icmp_client.rst

ARP-Client
-----------
.. include:: arp_client.rst
