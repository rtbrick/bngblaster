BNG Blaster
===========

The **BNG Blaster** is an open-source network tester 
for access and routing protocols. It can emulate a huge amount of 
PPPoE and IPoE (DHCP) subscribers including IPTV, and L2TP (LNS). 
There are various routing protocols supported like ISIS and BGP. 
So you can use it for end-to-end BNG and non-BNG router testing.

You can use the included traffic generator for forwarding verification,
QoS testing or to measure convergence times. The traffic generator supports 
millions of separate tracked flows. This allows you to verify every single 
forwarding state of a full-feed internet routing table. You can also send 
traffic to every single QoS queue of your service edge router with detailed 
per-flow statistics like receive rate, loss or latency.

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
        * Emulate ISIS topologies with thousands of nodes 
        * Support for ISIS Segment Routing
        * Support for LDP and traffic streams with dynamically resolved labels
        * Support all routing protocols with link aggregation (LAG)
        * ...

   .. tab:: Traffic Generator

        * Generate and track millions of traffic flows
        * Verify your QoS configuration 
        * Verify all forwarding states
        * Measure convergence times and loss
        * Capture traffic
        * ...

A short `introduction <https://youtu.be/EHJ70p0_Sw0>`_ and a good presentation
from `DENOG13 <https://youtu.be/LVg6rlVEfNU>`_ can be found on YouTube. There is 
also an article in the 
`APNIC blog <https://blog.apnic.net/2022/05/26/bng-blaster-the-open-network-tester-for-the-ip-networking-community/>`_ 
where we explained our motivation for this project. 

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
   reports
   configuration/index
   api/index
   controller
   troubleshooting
   faq

Sources
-------

https://github.com/rtbrick/bngblaster

License
-------

BNG Blaster is licensed under the BSD 3-Clause License, which means that you are free to get and use it for
commercial and non-commercial purposes as long as you fulfill its conditions.

See the `LICENSE <https://github.com/rtbrick/bngblaster/blob/main/LICENSE>`_ 
file for more details.

Copyright
---------
.. |copy|   unicode:: U+000A9 .. COPYRIGHT SIGN

Copyright |copy| 2020-2023, RtBrick, Inc.

Contact
-------

bngblaster@rtbrick.com