# RtBrick - Routing Protocol and BNG Blaster

![Build](https://github.com/rtbrick/bngblaster/actions/workflows/build.yml/badge.svg?branch=main)
[![Linux](https://img.shields.io/badge/OS-linux-lightgrey)](https://rtbrick.github.io/bngblaster/install)
[![License](https://img.shields.io/badge/License-BSD-yellow)](https://github.com/rtbrick/bngblaster/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/Documentation-blue)](https://rtbrick.github.io/bngblaster)
[![Chat](https://img.shields.io/badge/Chat-darkgreen)](https://matrix.to/#/#bngblaster:matrix.org)

**The open network tester for the IP networking community.**

The **Routing Protocol and BNG Blaster** is an open-source network tester for **routing** and **access** protocols.

Originally developed as an access protocol tester, the BNG Blaster has undergone a 
significant evolution, transforming into a comprehensive network testing tool that 
now encompasses both access and routing functionalities. Its scope has expanded beyond 
the assessment of access protocols and now encompasses a broader spectrum, involving 
the evaluation of network functionalities at large. Contrary to its nomenclature, 
the BNG Blaster isn't restricted only to BNG (Broadband Network Gateway) testing.

It simulates a massive number of PPPoE and IPoE (DHCP) subscribers, encompassing 
IPTV and L2TP (LAC and LNS). Additionally, it supports all common routing protocols 
such as IS-IS, OSPF, LDP and BGP, including BGP EVPN and TCP authentication 
(TCP-AO and MD5). This allows for comprehensive testing of both BNG and non-BNG 
routers, enabling end-to-end evaluations.

The included traffic generator serves various functions. It can be used to verify 
forwarding, conduct QoS tests, and measure convergence times. With the capacity to 
handle millions of separate tracked flows, it allows for thorough verification of 
every forwarding state within a complete internet routing table. Furthermore, it 
enables the transmission of traffic to each specific QoS queue present in 
service edge routers with detailed per-flow statistics like receive rate, loss 
or latency. EVPN VPWS services can be verified with Ethernet over MPLS traffic 
streams. For high-rate tests, the BNG Blaster supports DPDK and AF_XDP.

For AF_XDP, promiscuous membership is acquired after queue, RSS and socket
initialization, before packet processing starts. This avoids losing hardware
promiscuity when queue reconfiguration reinitializes an SR-IOV VF (for example,
with the Linux iavf driver).

AF_XDP prepares the hardware RX ring after queue configuration, increasing it
to 4096 descriptors (or the device maximum if lower). Configure `io-slots-rx`
per entry in `interfaces.links` to at least twice the hardware RX ring size,
for example 8192 for a 4096-descriptor ring. Insufficient capacity fails
initialization rather than silently running with an undersized buffer pool.
These slots allocate 4096-byte UMEM frames per RX queue; size memory accordingly.

On orderly shutdown and initialization failure, AF_XDP sockets and UMEM are
released and the saved channel count, RSS table/key, hardware rings and legacy
offload flags are restored before interface locks are released. Cleanup errors
produce a nonzero exit status. Interfaces with existing XDP programs are rejected
instead of sharing or replacing them. Detachment checks the owned program ID and
uses an expected-program FD to avoid removing a replacement program. SIGKILL,
process crashes and concurrent external NIC changes cannot be rolled back
reliably; investigate stale programs instead of unconditionally detaching them.

The BNG Blaster is used by leading network operators like Deutsche Telekom AG
with their famous Access 4.0 project, network hard- and software vendors like
RtBrick and many more.

A short introduction from [DENOG15](https://youtu.be/4rmwf6livyI "DENOG15") 
can be found on YouTube.

Please check out the [documentation](https://rtbrick.github.io/bngblaster/) for details.

![BBL Interactive](docsrc/sources/images/bbl_interactive.png "BNG Blaster (Interactive Mode)")

This project will be actively maintained and further evolved by RtBrick. We are fully committed to 
building a project for the community and take issue and enhancement requests seriously. We are 
looking forward to any kind of contributions, new features, bug fixes, or tools. Even contributions 
to the documentation are more than welcome.

Our mission is to build better networks with open test suites.

## License

BNG Blaster is licensed under the BSD 3-Clause License, which means that you are free to get and use it for
commercial and non-commercial purposes as long as you fulfill its conditions.

See the LICENSE file for more details.

## Copyright

Copyright (C) 2020-2026, RtBrick, Inc.

## Contact

* Mail: bngblaster@rtbrick.com
* Chat: [matrix.org #bngblaster](https://matrix.to/#/#bngblaster:matrix.org)
