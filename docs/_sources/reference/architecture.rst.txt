Architecture
------------

The BNG Blaster has been completely built from scratch in **C**. This includes user-space implementations 
of the entire protocol stack. Its core is based on a very simple event loop that serves timers and 
signals. The timers have been built using a lightweight constant time (*O(1)*) library. The timer library 
was built to start, restart and delete the protocol session FSM timers quickly and at scale.

The BNG Blaster expects a Linux kernel network interface that is up but not configured with any IP addresses 
or VLAN as it expects to receive and transmit RAW ethernet packets.

The BNG Blaster does I/O using high-speed polling timers with a mix of Linux
`RAW Packet Sockets <https://man7.org/linux/man-pages/man7/packet.7.html>`_ and
`Packet MMAP <https://www.kernel.org/doc/html/latest/networking/packet_mmap.html>`_.

The second one is a so-called PACKET_RX_RING/PACKET_TX_RING abstraction where a user-space program gets a fast 
lane into reading and writing to kernel interfaces using a shared ring buffer. The shared ring buffer is a 
memory-mapped window shared between the kernel and the user space. This low overhead abstraction allows us to 
transmit and receive traffic without doing expensive system calls. Sending and transmitting traffic via Packet MMAP is 
as easy as copying a packet into a buffer and setting a flag.

.. image:: ../images/bbl_arch.png
    :alt: BNG Blaster Architecture

The BNG Blaster supports many configurable I/O modes listed with ``bngblaster -v`` but except for the default 
mode ``packet_mmap_raw`` all other modes are currently considered experimental. In the default mode, all 
packets are received in a Packet MMAP ring buffer and sent through RAW packet sockets. This combination 
was the most efficient in our benchmark tests.

BNG Blaster's primary design goal is to simulate thousands of subscriber CPE’s with a small hardware resource 
footprint. Simple to use and easy to integrate into our robot test automation infrastructure. This allows for 
the simulation of massive PPPoE or IPoE (DHCP) subscribers including IPTV, traffic verification, and convergence 
testing from a single medium-scale virtual machine or directly from a laptop.

The BNG Blaster provides three types of interface functions. The first interface function is called the access which 
emulates the PPPoE or IPoE sessions. The second interface function is called network. This is used for 
emulating the core-facing side of the internet with optional routing protocols. The last type is called a10nsp 
interface which emulates a layer two provider interface. The term A10 refers to the end-to-end ADSL network 
reference model from TR-025.

.. image:: ../images/bbl_interfaces.png
    :alt: BNG Blaster Interfaces

This allows for verification of IP reachability by sending bidirectional traffic between all sessions 
on the access interface and the network interface. The network interface is also used to inject downstream
multicast test traffic for IPTV tests. It is also possible to send RAW traffic streams between network
interfaces without any access interface defined for non-BNG testing.

One popular example of non-BNG tests with the BNG Blaster is the verification of a BGP full table by injecting
around 1M prefixes and setting up traffic streams for all prefixes with at least 1 PPS (1M PPS).
The BNG Blaster can verify and analyze every single flow with detailed per-flow statistics
(receive rate, loss, latency, …).