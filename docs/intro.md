# Introduction

Building a BNG from scratch requires a lot of testing but commercial BNG test software
is often very expensive, resource intensive and provide a lot of administrative overhead
to maintain such.

Therefore we decided to build an open source network test software initially focused on BNG
and IPTV testing but constantly enhanced and planned for more common (non-BNG) network testing.
The BNG Blaster was completely build from scratch, targeted for max scaling with small
resource footprint, simple to use and easy to integrate in any test automation infrastructure.

The BNG Blaster is able to simulate more than hundred thousand PPPoE and IPoE (DHCP) subscribers including
IPTV, L2TPv2 (LNS emulation), L2BSA, QoS, forwarding verification and convergence testing capabilities.

* *High Scaling:* > 100K sessions, > 1M PPS, and > 1M traffic flows
* *Low CPU and Memory Footprint:* ~300MB memory for 16K sessions
* *Portable:* runs on every modern linux, virtual machines and containers
* *User Space:* all protocols implemented in user-space from scratch and optimized for performance
* *IPTV:* IGMP version 1, 2 and 3 with automated channel zapping test
* *QoS:* define and analyze traffic streams
* *Automation:* the BNG Blaster Controller provides an automation friendly REST API and robot keywords

**Info:** _The BNG Blaster Controller is not yet published but you can send
a mail to bngblaster@rtbrick.com if you are interested to get early access!_

```
$ bngblaster --help


      ____   __   ____         _        __                                  ,/
     / __ \ / /_ / __ ) _____ (_)_____ / /__                              ,'/
    / /_/ // __// __  |/ ___// // ___// //_/                            ,' /
   / _, _// /_ / /_/ // /   / // /__ / ,<                             ,'  /_____,
  /_/ |_| \__//_____//_/   /_/ \___//_/|_|                          .'____    ,'
      ____   _   _  ______   ____   _               _                    /  ,'
     / __ ) / | / // ____/  / __ ) / /____ _ _____ / /_ ___   ____      / ,'
    / __  |/  |/ // / __   / __  |/ // __ `// ___// __// _ \ / ___/    /,'
   / /_/ // /|  // /_/ /  / /_/ // // /_/ /(__  )/ /_ /  __// /       /
  /_____//_/ |_/ \____/  /_____//_/ \__,_//____/ \__/ \___//_/

Usage: bngblaster [OPTIONS]

  -v --version
  -h --help
  -C --config <args>
  -T --stream-config <args>
  -l --logging debug|error|igmp|io|pppoe|info|pcap|timer|timer-detail|ip|loss|l2tp|dhcp
  -L --log-file <args>
  -u --username <args>
  -p --password <args>
  -P --pcap-capture <args>
  -j --json-report-content sessions|streams
  -J --json-report-file <args>
  -c --session-count <args>
  -g --mc-group <args>
  -s --mc-source <args>
  -r --mc-group-count <args>
  -z --mc-zapping-interval <args>
  -S --control-socket <args>
  -I --interactive
  -b --hide-banner
  -f --force

```

The BNG Blaster includes an optional interactive mode (`-I`) with realtime stats and
log viewer as shown below.

![BNG Blaster Interactive](images/bbl_interactive.png)

## Theory Of Operation

The BNG Blaster has been completely built from scratch, including user-space implementations of the entire protocol
stack you need for interfacing with a BNG. It’s core is based on a very simple event loop which serves timers and signals.
The timers have been built using a lightweight constant time (`O(1)`) library which we built purposely to start, restart
and delete the protocol session FSM timers quickly and at scale.

The BNG Blaster expects a Linux kernel network interface which is up, but not configured with any IP addresses or VLAN as it
expects to receive and transmit RAW ethernet packets.

The BNG Blaster does I/O using high-speed polling timers with a mix of Linux
[RAW Packet Sockets](https://man7.org/linux/man-pages/man7/packet.7.html) and
[Packet MMAP](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html).

The second one is a so-called PACKET_RX_RING/PACKET_TX_RING abstraction where a user-space program gets a fast-lane into reading
and writing to kernel interfaces using a shared ring buffer. The shared ring buffer is a memory mapped "window" that is shared
between kernel and user-space. This low overhead abstraction allows to transmit and receive traffic without doing expensive system calls.
Sending and transmitting traffic via Packet MMAP is as easy as just by copying a packet into a buffer and setting a flag.

![BNG Blaster Architecture](images/bbl_arch.png)

The BNG Blaster supports multiple configurable I/O modes listed with `bngblaster -v` but except `packet_mmap_raw` all other modes
are currently considered as experimental. In the default mode (`packet_mmap_raw`) all packets are received in a Packet MMAP ring
buffer and send directly trough RAW packet sockets. This combination was the most efficient in our benchmark tests.

BNG Blasters primary design goal is to simulate thousands of subscriber CPE's with a small hardware resource footprint. Simple
to use and easy to integrate in our robot test automation infrastructure. This allows to simulate more than hundred thousand
PPPoE or IPoE (DHCP) subscribers including IPTV, traffic verification and convergence testing from a single medium scale
virtual machine or to run the blaster directly from a laptop.

The BNG Blaster provides three types of interfaces. The first interface is called the access interface which emulates the PPPoE
sessions. The second interface-type is called network interface. This is used for emulating the core-facing side of the
internet. The last type is called a10nsp interface which emulates an layer two provider interface. The term A10
refers to the end-to-end ADSL network reference model from TR-025.

![BNG Blaster Interfaces](images/bbl_interfaces.png)

This allows to verify IP reachability by sending bidirectional traffic between all PPPoE sessions on access-interface and the
network interface. The network interface is also used to inject downstream multicast test traffic for IPTV tests. It is also
possible to send RAW traffic streams between multiple network interfaces without any access interface defined for non-BNG
testing.

One popular example for non-BNG tests with the BNG Blaster is the verification of a BGP full-table by injecting around 1M
prefixes and setting up traffic streams for all prefixes with at least one PPS (1M PPS). The BNG Blaster is able to verify
and analyze every single flow with detailed per flow statistics (receive rate, loss, latency, ...).
