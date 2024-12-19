BNG Blaster
===========

**The open network tester for the IP networking community.**

The **BNG Blaster** is an open-source network tester for **access** and **routing** protocols.

Originally developed as an access protocol tester, the BNG Blaster has undergone a 
significant evolution, transforming into a comprehensive network testing tool that 
now encompasses both access and routing functionalities. Its scope has expanded beyond 
the assessment of access protocols and now encompasses a broader spectrum, involving 
the evaluation of network functionalities at large. Contrary to its nomenclature, 
the BNG Blaster isn't restricted only to BNG (Broadband Network Gateway) testing.

It simulates a massive number of PPPoE and IPoE (DHCP) subscribers, encompassing 
IPTV and L2TP (LNS). Additionally, it supports all common routing protocols such 
as IS-IS, OSPF, LDP and BGP. This allows for comprehensive testing of both BNG 
and non-BNG routers, enabling end-to-end evaluations.

The included traffic generator serves various functions. It can be used to verify 
forwarding, conduct QoS tests, and measure convergence times. With the capacity to 
handle millions of separate tracked flows, it allows for thorough verification of 
every forwarding state within a complete internet routing table. Furthermore, it 
enables the transmission of traffic to each specific QoS queue present in 
service edge routers with detailed per-flow statistics like receive rate, loss 
or latency.

The BNG Blaster is used by leading network operators like Deutsche Telekom AG
with their famous Access 4.0 project, network hard- and software vendors like
RtBrick and many more.

.. tabs::

   .. tab:: Modern Software

        * Emulate massive nodes and sessions with low CPU and memory footprint
        * Runs on every modern Linux, virtual machine and containers
        * All protocols implemented in user space and optimized for performance
        * Automation-friendly API
        * Optional DPDK support (experimental)
        * ...

   .. tab:: Access Protocols

        * Emulate massive PPPoE and IPoE (DHCP) clients
        * Emulate L2TPv2 LNS servers with different behaviors
        * Emulate A10NSP interfaces for L2BSA testing
        * Included multicast and IPTV test suite
        * Verify legal interception (LI) traffic
        * Support all access protocols with link aggregation (LAG)
        * ...

   .. tab:: Routing Protocols

        * Setup thousands of BGP sessions with millions of prefixes
        * Verify MPLS labels for millions of flows
        * Emulate ISIS and OSPFv2/3 topologies with thousands of nodes 
        * Support for ISIS and OSPFv2/3 Segment Routing
        * Support for LDP and traffic streams with dynamically resolved labels
        * Support all routing protocols with link aggregation (LAG)
        * ...

   .. tab:: Traffic Generator

        * Generate and track millions of traffic flows
        * Verify your QoS configuration 
        * Verify all forwarding states
        * Measure convergence times and loss
        * Capture traffic
        * Emulate HTTP clients and servers
        * NAT and CGNAT testing
        * ...

A short introduction from `DENOG15 <https://youtu.be/4rmwf6livyI>`_
can be found on YouTube. There are even more videos and articles 
listed below.

.. image:: images/bbl_interactive.png
    :alt: BNG Blaster Interactive

The BNG Blaster has been completely built from scratch in **C**. This includes user-space implementations 
of the entire protocol stack. The core is based on a very simple event loop that serves timers and 
signals. The timers have been built using a lightweight constant time (*O(1)*) library. The 
`timer library <https://github.com/rtbrick/bngblaster/blob/main/code/common/src/timer.h>`_
was built to start, restart and delete the protocol session FSM timers quickly and at scale.

.. image:: images/bbl_arch.png
    :alt: BNG Blaster Architecture

This project will be actively maintained and further evolved by RtBrick. We are fully committed to building 
a project for the community and take issue and enhancement requests seriously. We are looking forward to any 
kind of contributions, new features, bug fixes, or tools. Even contributions to the documentation are more 
than welcome.

If you are interested in the BNG Blaster, or simply looking to find out more about it, we recommend going through 
the examples in the quick start guide.

Our mission is to build better networks with open test suites.

Contents
--------

.. toctree::
   :maxdepth: 1

   install
   quickstart
   interfaces
   access/index
   routing/index
   streams
   icmp
   http
   nat
   reports
   configuration/index
   api/index
   controller
   performance
   troubleshooting
   faq

Contact
-------

* Mail: bngblaster@rtbrick.com
* Chat: `matrix.org #bngblaster <https://matrix.to/#/#bngblaster:matrix.org>`_

Articles
--------

* `APNIC Blog - The open network tester for the IP networking community <https://blog.apnic.net/2022/05/26/bng-blaster-the-open-network-tester-for-the-ip-networking-community/>`_ 

YouTube 
-------

* `DKNOG14 (2024) <https://www.youtube.com/live/WdATdbaveRI?si=lgw1W-HckormViK9&t=13599>`_ 
* `DENOG15 (2023) <https://youtu.be/4rmwf6livyI>`_ 
* `UKNOF49 (2022) <https://youtu.be/HTswAl388Gg>`_ 
* `DENOG13 (2021) <https://youtu.be/LVg6rlVEfNU>`_ 
* `Introduction (2021) <https://youtu.be/EHJ70p0_Sw0>`_

Sources
-------

* https://github.com/rtbrick/bngblaster
* https://github.com/rtbrick/bngblaster-controller

License
-------

BNG Blaster is licensed under the BSD 3-Clause License, which means that you are free to get and use it for
commercial and non-commercial purposes as long as you fulfill its conditions.

See the `LICENSE <https://github.com/rtbrick/bngblaster/blob/main/LICENSE>`_ 
file for more details.

Copyright
---------
.. |copy|   unicode:: U+000A9 .. COPYRIGHT SIGN

Copyright |copy| 2020-2024, RtBrick, Inc.