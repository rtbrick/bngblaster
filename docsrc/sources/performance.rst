.. _performance:

Performance Guide
=================

The BNG Blaster handles all traffic sent and received (I/O) in the main thread per default.
With this default behavior, you can achieve between 100000 and 250000 PPS bidirectional
traffic in most environments. Depending on the actual setup, this can be even less or much
more, which is primarily driven by the single-thread performance of the given CPU.

Those numbers can be increased by splitting the workload over multiple I/O worker threads.
Every I/O thread will handle only one interface and direction. It is also possible to start
multiple threads for the same interface and direction.

The number of I/O threads can be configured globally for all interfaces or per interface link.

.. code-block:: json

    {
        "interfaces": {
            "rx-threads": 2,
            "tx-threads": 1,
            "links": [
                {
                    "interface": "eth1",
                    "rx-threads": 4,
                    "tx-threads": 2
                }
            ]
        }
    }

The configuration per interface link allows asymmetric thread pools. Assuming you would send
massive unidirectional traffic from eth1 to eth2. In such a scenario, you would set up multiple
TX threads and one RX thread on eth1. For eth2 you would do the opposite, meaning to set up
multiple RX threads but only one TX thread.

It is also possible to start dedicated threads for TX but remain RX in the main thread or
vice versa by setting the number of threads to zero (default).

With multithreading, you should be able to scale up to 8 million PPS bidirectional, depending on
the actual configuration and setup. This allows starting 1 million flows with 1 PPS per flow over
at least 4 TX threads to verify all prefixes of a BGP full table for example.

The configured traffic streams are automatically balanced over all TX threads of the corresponding
interfaces but a single stream can't be split over multiple threads to prevent re-ordering issues.

Enabling multithreaded I/O causes some limitations. First of all, it works only on systems with
CPU cache coherence, which should apply to all modern CPU architectures. TX threads are not allowed
for LAG (Link Aggregation) interfaces but RX threads are supported. It is also not possible to capture
traffic streams send or received on threaded interfaces. All other traffic is still captured on threaded
interfaces.

RX threads handle received traffic streams directly and redirect all other packets to the main
thread. Packets longer than 4074 bytes can't be redirected and are counted as ``rx-to-long``.
Packets dropped because the main thread does not process redirected packets fast enough are
counted as ``rx-dropped``, except with I/O mode ``packet_mmap`` and ``packet_mmap_raw``, which
wait for the main thread instead.

.. note::

    The BNG Blaster is currently tested for 8 million PPS with 10 million flows, which is not a
    hard limitation but everything above should be considered with caution. It is also possible to
    scale far beyond using DPDK-enabled interfaces.

A single stream will be always handled by a single thread to prevent re-ordering.

It is also recommended to increase the hardware and software queue size of your
network interface links to the maximum for higher throughput as explained
in the :ref:`Operating System Settings <interfaces>`.

The packet receives performance can be increased by the number of RX threads and IO slots.

.. code-block:: json

    {
        "interfaces": {
            "rx-threads": 20,
            "io-slots": 32768
        }
    }

The packet receives performance is also limited by the abilities of your network
interfaces to properly distribute the traffic over multiple hardware queues using
receive side scaling (RSS). This is a technology that allows network applications
to distribute the processing of incoming network packets across multiple CPUs,
improving performance, RSS uses a hashing function to assign packets to different
CPUs based on their source and destination addresses and ports. RSS requires
hardware support from the network adapter and the driver.

Some network interfaces are not able to distribute traffic for PPPoE/L2TP or even
MPLS traffic. Even double-tagged VLANs with default the default type 0x8100 is
often not supported. If RSS does not work for the received traffic, all packets
of an interface are received on the same queue and therefore handled by a single
RX thread, regardless of the number of RX threads configured. This can be verified
with the per-queue counters of the network interface while traffic is running.

.. code-block:: none

    ethtool -S <interface> | grep -E "rx-[0-9]+\.packets"

Therefore best results can be reached with single tagged IPoE traffic. Depending
on the actual network adapter, there are different options to address this
limitation. For instance, Intel 700 Series adapters require a Dynamic Device
Personalization (DDP) profile to support RSS for PPPoE traffic as explained in
:ref:`PPPoE RSS on Intel 700 Series <ddp-pppoe>`.

You can also boost the performance by adjusting some driver settings. For example,
we found that the following setting improved the performance for
`Intel 700 Series <https://www.kernel.org/doc/html/v6.6/networking/device_drivers/ethernet/intel/i40e.html>`_
in some of our tests. However, these settings may vary depending on your specific
test environment.

.. code-block:: none

    ethtool -C <interface> adaptive-rx off adaptive-tx off rx-usecs 125 tx-usecs 125

The NIC's own on-card RX descriptor ring is a separate, usually much smaller
buffer than any of the software-side ring/slot settings above (``io-slots``,
AF_XDP's fill ring, DPDK's descriptor count, ...) - it is the actual DMA
ring the driver refills via its NAPI poll. On some drivers/NICs it defaults
far below what the hardware supports (e.g. 512 out of a possible 8160 on an
Intel i40e we tested), so at high line rates any brief delay in the NAPI
poll (e.g. from interrupt moderation, see above) can drain it before the
driver gets to refill it - visible as the ``rx_missed_errors`` counter in
``ethtool -S <interface>`` increasing even though every software-side ring
is comfortably sized. Check and, if needed, raise it towards its maximum:

.. code-block:: none

    ethtool -g <interface>
    ethtool -G <interface> rx 8160 tx 8160

With :ref:`AF_XDP <af-xdp-usage>`, the NIC RX ring is filled with frames of the
AF_XDP socket, defined per RX thread by ``io-slots-rx`` (rounded up to the next
power of two). The NIC RX ring should not exceed half of those frames, otherwise
the frames still waiting to be processed are missing to refill the ring, which
results in even more ``rx_missed_errors``. For example, a NIC RX ring of 8160
requires ``io-slots-rx`` of 16384.

.. _ddp-pppoe:

PPPoE RSS on Intel 700 Series
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Intel 700 Series (X710, XXV710, XL710) can't parse PPPoE with its default
parser, so all PPPoE traffic of an interface is received on the same queue.
The Intel DDP profile *PPPoE and PPPoL2TPv2* adds PPPoE parsing, so that RSS
hashes the IP header inside PPPoE. Please contact Intel if you need this profile.

With the Linux kernel driver (e.g. I/O modes ``af_xdp`` or ``packet_mmap``),
version 1.1.6.1 of this profile (file ``ppp-oe-ol2tpv2.pkg``) is required.
The older version 1.0.0.0 (file ``ppp-oe-ol2tpv2.pkgo``) could be loaded with
the kernel driver in our tests, but PPPoE traffic was still received on a
single queue.

The profile is loaded with ``ethtool`` from the firmware directory
``/lib/firmware/intel/i40e/ddp/``, with the file name only. It applies to all
ports of the adapter, so it is sufficient to load it via one port.

.. code-block:: none

    cp ppp-oe-ol2tpv2.pkg /lib/firmware/intel/i40e/ddp/
    ethtool -f <interface> ppp-oe-ol2tpv2.pkg 100

The profile is not persistent and must be loaded again after every reboot
or reload of the i40e driver. It can be removed with:

.. code-block:: none

    ethtool -f <interface> - 100

In our tests, the profile changed only the distribution of PPPoE traffic.
IPoE and MPLS (single label) traffic was distributed over all queues with
and without the profile, with identical results.

For :ref:`DPDK <dpdk-usage>`, the profile must be loaded via DPDK instead
of the kernel driver.

.. note::

    We are continuously working to increase performance. Contributions, proposals,
    or recommendations on how to further increase performance are welcome!

NUMA
----

NUMA, which stands for Non-Uniform Memory Access, is a computer memory design used in multi-processor systems.
In a NUMA system, each processor, or a group of processors, has its own local memory. The processors can access
their own local memory faster than non-local memory, which is the memory local to another processor or shared
between processors.

On such systems, the best performance can be achieved by manually assigning RX and TX threads to a set of CPU
to ensure that the corresponding threads of an interface are running on the same NUMA node. The NUMA node
of the interface can be derived from the file ``/sys/class/net/<interface>/device/numa_node``.

.. code-block:: none

    cat /sys/class/net/eth0/device/numa_node
    0
    cat /sys/class/net/eth1/device/numa_node
    1


The command ``lscpu`` returns the number of NUMA nodes with the associated
CPU's for each NUMA node.

.. code-block:: none

    ...
    NUMA:
    NUMA node(s):          2
    NUMA node0 CPU(s):     0-17,36-53
    NUMA node1 CPU(s):     18-35,54-71


BNG Blaster supports two approaches:

* Manual pinning with ``rx-cpuset`` and ``tx-cpuset``.
* Automatic pinning with ``rx-auto-cpuset`` and ``tx-auto-cpuset``.

When automatic pinning is enabled, BNG Blaster derives the local CPU list from the interface and tries to
optimize placement as follows:

* Prefer CPUs local to the NIC.
* Prefer one hardware thread per physical core before using SMT siblings.
* Avoid reusing the same CPU across interfaces until the local CPU pool is exhausted.
* Fall back to the NUMA node CPU list and finally to the system online CPU list if no local CPU list is exposed.

Following an example configuration using automatic CPU placement.

.. code-block:: json

    {
        "interfaces": {
            "rx-auto-cpuset": true,
            "tx-auto-cpuset": true,
            "links": [
                {
                    "interface": "eth0",
                    "rx-threads": 4,
                    "tx-threads": 4
                },
                {
                    "interface": "eth1",
                    "rx-threads": 4,
                    "tx-threads": 4
                }
            ]
        }
    }


Following an example configuration with manual pinning.

.. code-block:: json

  {
        "interfaces": {
            "links": [
                {
                    "interface": "eth0",
                    "rx-threads": 4,
                    "rx-cpuset": [0, 36, 1, 37],
                    "tx-threads": 4,
                    "tx-cpuset": [2, 38, 3, 39]
                },
                {
                    "interface": "eth1",
                    "rx-threads": 4,
                    "rx-cpuset": [18, 54, 19, 55],
                    "tx-threads": 4,
                    "tx-cpuset": [20, 56, 21, 57]
                }
            ]
        }
    }


Following a real world example from a system with two CPU sockets (NUMA nodes) and two physical NIC adapters,
each connected to another socket (NUMA node). This example was optimized to send loss free 20G from
ens2f2np2, ens2f3np3 (NUMA node 0) to ens5f2np2, ens5f3np3 (NUMA node 1).

.. code-block:: json

    {
        "interfaces": {
            "links": [
                {
                    "interface": "ens2f2np2",
                    "tx-threads": 4,
                    "tx-cpuset": [0, 36, 1, 37]
                },
                {
                    "interface": "ens2f3np3",
                    "tx-threads": 4,
                    "tx-cpuset": [2, 38, 3, 39]
                },
                {
                    "interface": "ens5f2np2",
                    "rx-threads": 16,
                    "rx-cpuset": [18, 54, 19, 55, 20, 56, 21, 57, 22, 58, 23, 59, 24, 60, 25, 61],
                    "io-slots-rx": 32768
                },
                {
                    "interface": "ens5f3np3",
                    "rx-threads": 16,
                    "rx-cpuset": [26, 62, 27, 63, 28, 64, 29, 65, 30, 66, 31, 67, 32, 68, 33, 69],
                    "io-slots-rx": 32768
                }
            ]
        }
    }


This example shows well that more RX threads are required than TX threads.


.. _dpdk-usage:

DPDK
----

Using the experimental `DPDK <https://www.dpdk.org/>`_ support requires building
the BNG Blaster from sources with DPDK enabled as explained
in the corresponding :ref:`installation <install-dpdk>` section.

.. note::

    The official BNG Blaster Debian release packages do not support
    `DPDK <https://www.dpdk.org/>`_!


For DPDK interfaces, the same automatic CPU placement options are available.
The DPDK backend derives the NIC socket from ``rte_eth_dev_socket_id()`` and
applies the same locality and physical-core-first policy. Manual DPDK pinning
remains available if you need exact CPU control.

.. code-block:: json

    {
        "interfaces": {
            "io-slots": 32768,
            "links": [
                {
                    "interface": "0000:23:00.0",
                    "io-mode": "dpdk",
                    "rx-threads": 8,
                    "rx-auto-cpuset": true,
                    "tx-threads": 3,
                    "tx-auto-cpuset": true
                },
                {
                    "interface": "0000:23:00.2",
                    "io-mode": "dpdk",
                    "rx-threads": 8,
                    "rx-auto-cpuset": true,
                    "tx-threads": 3,
                    "tx-auto-cpuset": true
                }
            ],
            "a10nsp": [
                {
                    "__comment__": "PPPoE Server",
                    "interface": "0000:23:00.0"
                }
            ],
            "access": [
                {
                    "__comment__": "PPPoE Client",
                    "interface": "0000:23:00.2",
                    "type": "pppoe",
                    "outer-vlan-min": 1,
                    "outer-vlan-max": 4000,
                    "inner-vlan-min": 1,
                    "inner-vlan-max": 4000,
                    "stream-group-id": 1
                }
            ]
        },
        "pppoe": {
            "reconnect": true
        },
        "dhcpv6": {
            "enable": false
        },
        "streams": [
            {
                "stream-group-id": 1,
                "name": "S1",
                "type": "ipv4",
                "direction": "both",
                "pps": 1000,
                "a10nsp-interface": "0000:23:00.0"
            }
        ]
    }


DPDK assigns one hardware queue to each RX thread, so you need to increase
the number of threads to utilize more queues and enhance performance.


.. _loopback-usage:

Loopback
--------

The I/O mode ``loopback`` connects two links of the same BNG Blaster instance
back to back via in-memory rings, without any kernel interface, driver or NIC
in between. This allows to measure the I/O performance of the BNG Blaster
itself (packet generation, stream processing, decoding, ...) independent of
the underlying I/O stack, which makes it the upper bound of what the BNG Blaster
can achieve with any other I/O mode. The links do not need to exist in the
host OS and no special privileges are required.

.. code-block:: json

    {
        "interfaces": {
            "io-mode": "loopback",
            "rx-threads": 2,
            "tx-threads": 2,
            "links": [
                { "interface": "lo-a10nsp", "loopback-peer": "lo-access" },
                { "interface": "lo-access" }
            ],
            "a10nsp": [ { "interface": "lo-a10nsp" } ],
            "access": [
                {
                    "interface": "lo-access",
                    "type": "ipoe",
                    "outer-vlan-min": 1,
                    "outer-vlan-max": 4000,
                    "inner-vlan": 7
                }
            ]
        }
    }

Every TX thread (or the main thread if TX threads are disabled) owns one
lock-free single-producer/single-consumer ring to the peer link, which is
read by exactly one RX thread of the peer. If the peer link has fewer RX than
TX threads, the rings are distributed round-robin over the available RX threads.
The ring size is defined by ``io-slots`` of the sending link. Similar to a NIC, a
full ring is reported as ``no-buffer`` and the affected packets are sent later.

The MAC address is generated automatically, if not explicitly configured
per link. The maximum stream packet length is 3952 bytes or 12144 bytes with
``jumbo-frames`` enabled.

.. note::

    Each loopback link runs its own RX and TX threads, so the number of
    threads required for both links of a loopback pair should not exceed
    the number of available CPU cores.

.. _af-xdp-usage:

AF_XDP
------

Using the experimental `AF_XDP <https://www.kernel.org/doc/html/latest/networking/af_xdp.html>`_
support requires building the BNG Blaster from sources with AF_XDP enabled as
explained in the corresponding :ref:`installation <install-af-xdp>` section.

.. note::

    The official BNG Blaster Debian release packages do not support AF_XDP!

Unlike :ref:`DPDK <dpdk-usage>`, AF_XDP interfaces stay attached to the Linux
network stack and keep using the normal kernel driver, which makes it a good
middle ground between the regular ``packet_mmap``/``raw`` modes and DPDK: no
dedicated driver binding or hugepages are required, while still bypassing
most of the kernel networking stack for a lot better performance than
``packet_mmap``.

RX and TX each get their own dedicated, disjoint NIC queues - they are never
combined onto the same queue, so heavy TX load can't delay that same
queue's own RX servicing (they would otherwise share one NAPI/IRQ context).
``rx-threads`` and ``tx-threads`` are fully independent, e.g. more RX than
TX threads to spread out RX-side protocol processing without paying for
extra TX threads.

.. code-block:: json

    {
        "interfaces": {
            "io-slots": 4096,
            "links": [
                {
                    "interface": "eth1",
                    "io-mode": "af_xdp",
                    "rx-threads": 6,
                    "rx-auto-cpuset": true,
                    "tx-threads": 2,
                    "tx-auto-cpuset": true
                }
            ]
        }
    }

.. note::

    AF_XDP frames are limited to 4096 bytes, so ``jumbo-frames`` are not
    supported by this I/O mode and the maximum stream packet length is
    reduced accordingly.

Like DPDK, AF_XDP requires the NIC to actually provide as many hardware
queues as bngblaster needs, i.e. ``rx-threads`` + ``tx-threads`` (each
defaulting to 1 if left unset), since RX and TX never share a queue.
BNG Blaster reconfigures the interface to the required number of combined
queues automatically via ``ethtool``-equivalent ioctls (the same effect as
running ``ethtool -L <interface> combined <n>`` beforehand) - if that fails
(e.g. insufficient privileges, or a driver that splits RX/TX channels
instead of combined ones), it is logged with a hint to configure it
manually. Native (driver) mode additionally requires a driver with native
XDP support; BNG Blaster automatically falls back to generic (SKB) mode -
which works on any interface, including ``veth`` - if native mode is not
available.

.. note::

    If the NIC has more queues configured than bngblaster binds AF_XDP
    sockets to, RSS may hash some flows to a queue nothing is bound to -
    those packets are passed to the normal kernel stack instead of being
    redirected to bngblaster, which looks like silent RX loss for the
    affected flows. This is exactly what the automatic queue
    reconfiguration above avoids.


AF_XDP Tuning
~~~~~~~~~~~~~

The following recommendations are based on tests with PPPoE traffic between
two directly connected 10G ports of an Intel X710 adapter (i40e driver),
using native zero-copy mode.

**RX threads:** The RX performance per thread depends on the CPU and packet
size. In our tests, a single RX thread received up to about 1.9 Mpps per queue
without loss, while loss started at around 2.1 Mpps per queue. RSS does not
distribute traffic perfectly evenly, so plan enough RX threads to keep the
busiest queue below this limit. Typically, more RX than TX threads are
required.

**TX threads:** TX threads permanently poll and therefore use a full CPU core
each, even if not sending at their limit. In our tests, a single TX thread
sent at least 3.2 Mpps (the actual limit was not reached).

**CPU cores:** Each RX and TX thread should have its own physical CPU core,
including SMT siblings. The total number of RX and TX threads of all links
plus the main thread should not exceed the number of physical cores.
Otherwise threads are delayed for short periods, which shows up as bursts of
``rx_missed_errors`` even if the average CPU load looks fine.

**Buffers:** Short delays of RX threads can be absorbed with larger buffers.
In our tests, a NIC RX ring of 8160 with ``io-slots-rx`` of 16384 removed the
remaining loss caused by such delays (see the NIC RX ring requirements above).

**Virtual machines:** The virtual CPUs of a VM may share physical cores with
each other or with the host. In our tests, a VM with 14 virtual CPUs on a host
with 8 physical cores provided only the performance of about 8 cores if all
virtual CPUs were busy. Short interruptions by the host cause bursts of
``rx_missed_errors``. If possible, pin the virtual CPUs to dedicated physical
cores of the host and use the large buffers explained above.

**PCIe:** Small packets require many PCIe transactions per byte. With an
Intel X710 4-port adapter in a PCIe 3.0 x4 slot, two ports with bidirectional
traffic of 128-byte packets reached only about 92% of line rate (6.5 Mpps per
port and direction), independent of the number of threads. Unidirectional
traffic or larger packets (1400 bytes) reached line rate without loss. Check
the negotiated PCIe link width and speed of the adapter, and use a slot with
the full width supported by the adapter for small packets at line rate.

.. code-block:: none

    lspci -vv -s <pci-address> | grep -E "LnkCap:|LnkSta:"

**Monitoring:** The following counters of ``ethtool -S <interface>`` help to
identify the bottleneck. ``rx_missed_errors`` counts packets dropped because no
free RX descriptor was available, which is caused by delayed or overloaded RX
threads. The per-queue counters ``rx-<n>.packets`` show how RSS distributes
the traffic over the RX threads.

The following configuration was tested with 650 PPPoE sessions with one
bidirectional stream of 10 Mbps and 128 bytes per session (6.35 Mpps per port
and direction) without loss, with NIC RX rings set to 8160 and the
:ref:`DDP profile <ddp-pppoe>` loaded.

.. code-block:: json

    {
        "interfaces": {
            "io-mode": "af_xdp",
            "rx-threads": 4,
            "tx-threads": 2,
            "io-slots": 4096,
            "links": [
                {
                    "interface": "eth1",
                    "io-slots-tx": 1024,
                    "io-slots-rx": 16384,
                    "rx-cpuset": [1, 2, 3, 4],
                    "tx-cpuset": [5, 6]
                },
                {
                    "interface": "eth2",
                    "io-slots-tx": 1024,
                    "io-slots-rx": 16384,
                    "rx-cpuset": [7, 8, 9, 10],
                    "tx-cpuset": [11, 12]
                }
            ],
            "a10nsp": [
                {
                    "__comment__": "PPPoE Server",
                    "interface": "eth1"
                }
            ],
            "access": [
                {
                    "__comment__": "PPPoE Client",
                    "interface": "eth2",
                    "type": "pppoe",
                    "outer-vlan-min": 1,
                    "outer-vlan-max": 4000,
                    "ipv6": false,
                    "stream-group-id": 1
                }
            ]
        },
        "sessions": {
            "count": 650
        },
        "dhcpv6": {
            "enable": false
        },
        "streams": [
            {
                "stream-group-id": 1,
                "name": "S1",
                "type": "ipv4",
                "direction": "both",
                "Mbps": 10,
                "length": 128,
                "a10nsp-interface": "eth1"
            }
        ]
    }
