.. _performance:

Performance Guide
=================

This guide explains how to get the most out of the BNG Blaster, from the
configuration of I/O threads to the settings of the NIC, the server and the
operating system.

The BNG Blaster handles all traffic sent and received (I/O) in the main thread per default.
With this default behavior, you can achieve between 100000 and 250000 PPS bidirectional
traffic in most environments. Depending on the actual setup, this can be even less or much
more, which is primarily driven by the single-thread performance of the given CPU.

Those numbers can be increased by splitting the workload over multiple I/O worker threads,
and further with the I/O modes :ref:`AF_XDP <af-xdp-usage>` or :ref:`DPDK <dpdk-usage>`.

Where to Start
--------------

Change one thing at a time and measure after each step. Loss shows up in the
stream statistics of the BNG Blaster, and in the NIC counters
(``ethtool -S <interface>``, e.g. ``rx_missed_errors``).

1. Start with the default I/O mode ``packet_mmap_raw`` and one RX and one TX
   thread per interface.
2. Check if the NIC distributes the received traffic over multiple queues
   (:ref:`RSS <rss>`). If it doesn't, which is common for PPPoE, keep one RX
   thread per interface (see :ref:`If RSS Does Not Work <rss-not-working>`).
3. Add RX threads only as long as the per-queue counters show that the traffic is
   distributed over the corresponding queues.
4. Pin the threads to CPUs of the NUMA node of the NIC, away from the CPUs
   handling the NIC interrupts (:ref:`NUMA and CPU Pinning <cpu-pinning>`).
5. Increase the :ref:`NIC RX ring <nic-rx-ring>`.
6. Check the :ref:`server settings <server-settings>`: BIOS power profile, CPU
   frequency scaling, IOMMU mode, PCIe slot and interrupt placement.
7. For more performance, use :ref:`AF_XDP <af-xdp-usage>` or :ref:`DPDK <dpdk-usage>`.

I/O Threads
-----------

Every I/O thread handles only one interface and direction. It is also possible to start
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

The I/O threads are named by direction, thread index and interface, for example
``rx0-eth1`` or ``tx1-eth2``. Long names are truncated to 15 characters.
This allows to monitor the CPU usage and placement of each thread.

.. code-block:: none

    top -H -p $(pgrep -x bngblaster)

With multithreading and the default I/O mode ``packet_mmap_raw``, you should be able to scale up
to 8 million PPS bidirectional, depending on the actual configuration and setup. This allows
starting 1 million flows with 1 PPS per flow over at least 4 TX threads to verify all prefixes of
a BGP full table for example. With :ref:`AF_XDP <af-xdp-usage>` or :ref:`DPDK <dpdk-usage>`,
a single RX and TX thread can already handle 10G line rate (see :ref:`AF_XDP Tuning <af-xdp-tuning>`).

The configured traffic streams are automatically balanced over all TX threads of the corresponding
interfaces but a single stream can't be split over multiple threads to prevent re-ordering issues.
TX threads are not limited by RSS, so the number of TX threads can be increased independently of
the RX threads.

Enabling multithreaded I/O causes some limitations. First of all, it works only on systems with
CPU cache coherence, which should apply to all modern CPU architectures. TX threads are not allowed
for LAG (Link Aggregation) interfaces but RX threads are supported. Traffic streams sent or received
by I/O threads are captured with ``capture-include-streams``, which copies each stream packet to the
main thread writing the capture. This limits the capture rate (e.g. about 2 million packets per
second to disk in our tests) and packets exceeding it are missing in the capture, which is logged
as ``Incomplete stream capture``.

RX threads handle received traffic streams directly and redirect all other packets to the main
thread. Packets longer than 4074 bytes can't be redirected and are counted as ``rx-to-long``.
Packets dropped because the main thread does not process redirected packets fast enough are
counted as ``rx-dropped``, except with I/O mode ``packet_mmap`` and ``packet_mmap_raw``, which
wait for the main thread instead.

.. note::

    The BNG Blaster is currently tested for 8 million PPS with 10 million flows using the
    ``packet_mmap_raw`` I/O mode, which is not a hard limitation but everything above should
    be considered with caution. It is also possible to scale far beyond using AF_XDP or
    DPDK-enabled interfaces.

The receive performance can be increased by the number of RX threads, if the traffic is
distributed by RSS (see below), and by the number of I/O slots.

.. code-block:: json

    {
        "interfaces": {
            "rx-threads": 4,
            "io-slots": 32768
        }
    }

It is also recommended to increase the hardware and software queue size of your
network interface links to the maximum for higher throughput as explained
in the :ref:`Operating System Settings <interfaces>` and below.

.. _rss:

Receive Side Scaling (RSS)
--------------------------

A modern NIC has multiple receive queues. Each queue has its own ring of
receive buffers and its own interrupt, which is usually handled by a different
CPU. Receive side scaling (RSS) decides which queue a received packet is put
into: the NIC calculates a hash over header fields (typically the source and
destination IP addresses and UDP/TCP ports) and selects the queue via an
indirection table. All packets of a flow get the same hash and therefore the
same queue, so the order within a flow is kept. RSS is done by the NIC
hardware, so it only works for the packet types the NIC can parse.

The BNG Blaster RX threads read from those queues:

+----------------------------+-----------------------------------------------------------+
| I/O mode                   | Distribution over RX threads                              |
+============================+===========================================================+
| ``af_xdp``, ``dpdk``       | Each RX thread reads exactly one NIC queue. An RX thread  |
|                            | whose queue gets no traffic is idle.                      |
+----------------------------+-----------------------------------------------------------+
| ``packet_mmap_raw``,       | The kernel distributes the packets over the RX threads    |
| ``packet_mmap``, ``raw``   | (packet fanout by flow hash), but the kernel receive      |
|                            | processing of each NIC queue runs on the CPU handling     |
|                            | the interrupt of that queue.                              |
+----------------------------+-----------------------------------------------------------+

In both cases, the traffic of one NIC queue is limited by the CPU processing
this queue. Additional RX threads therefore only help if RSS distributes the
traffic over multiple queues.

The number of queues, the indirection table and the hashed fields can be
shown with ``ethtool``. The per-queue counters show how the traffic is
actually distributed while it is running (counter names depend on the driver,
e.g. ``rx-<n>.packets`` or ``rx_queue_<n>_packets``).

.. code-block:: none

    # number of queues (channels)
    ethtool -l <interface>
    # RSS indirection table and hash key
    ethtool -x <interface>
    # hashed fields, e.g. for IPv4/UDP
    ethtool -n <interface> rx-flow-hash udp4
    # per-queue counters
    watch -d 'ethtool -S <interface> | grep -E "rx[-_]([0-9]+|queue_[0-9]+)[._]packets"'

Many NICs can't parse and therefore not hash some encapsulations which are
typical for BNG tests:

* PPPoE and L2TP: the IP header inside PPPoE or L2TP is not visible to the
  NIC, so all PPPoE sessions are hashed the same way, e.g. only on the
  Ethernet type.
* Double-tagged VLANs: even with the default type 0x8100, the inner VLAN and the
  IP header behind it are often not parsed. The outer type 0x88a8 (``qinq``) is
  often not recognized as VLAN at all.
* MPLS: some NICs hash only on the labels, others not at all.

Therefore best results can be reached with single-tagged IPoE traffic.
Depending on the actual network adapter, there are options to extend RSS,
for instance for the Intel 700 Series (see below).

.. _rss-not-working:

If RSS Does Not Work
~~~~~~~~~~~~~~~~~~~~

If all received traffic of an interface ends up in one queue, for example
with PPPoE, start with a single RX thread per interface. This often gives
better results than multiple RX threads:

* All packets of the interface are processed by one CPU anyway. Additional RX
  threads can't add capacity, but add overhead and contention.
* RX threads poll for packets and use CPU even if they receive nothing. With
  DPDK they permanently busy-poll, so each idle RX thread occupies a full CPU
  core. Those cores are then missing for the threads which do the work, or
  compete with them as SMT siblings of the same physical core.
* The CPU handling the interrupt of the active queue is busy with the kernel
  receive processing. With fewer threads, it is easier to keep this CPU free of
  BNG Blaster threads (see :ref:`Interrupts <interrupts>`).

Then increase the number of RX threads step by step, only if the per-queue
counters show that the traffic is distributed over more queues. As a starting
point for the expected rates, a single RX thread received up to 2.4 Mpps of
PPPoE on one queue without loss in our tests with AF_XDP (see
:ref:`AF_XDP Tuning <single-queue>`).

The same applies to the access side of a BNG test in general: downstream
traffic to many PPPoE sessions arrives on the access interface, where RSS is
least likely to work, while upstream traffic arrives as plain IP on the
network interface. An asymmetric configuration with one RX thread on the
access interface and more RX threads on the network interface is therefore
common.

.. code-block:: json

    {
        "interfaces": {
            "links": [
                {
                    "__comment__": "access (PPPoE, single queue)",
                    "interface": "eth1",
                    "rx-threads": 1,
                    "tx-threads": 2
                },
                {
                    "__comment__": "network (IP, distributed by RSS)",
                    "interface": "eth2",
                    "rx-threads": 4,
                    "tx-threads": 1
                }
            ]
        }
    }

NIC Driver Settings
~~~~~~~~~~~~~~~~~~~

You can also boost the performance by adjusting some driver settings. For example,
we found that the following interrupt moderation setting improved the performance for
`Intel 700 Series <https://www.kernel.org/doc/html/v6.6/networking/device_drivers/ethernet/intel/i40e.html>`_
in some of our tests. However, these settings may vary depending on your specific
test environment.

.. code-block:: none

    ethtool -C <interface> adaptive-rx off adaptive-tx off rx-usecs 125 tx-usecs 125

.. _nic-rx-ring:

The NIC RX descriptor ring is a separate, usually much smaller buffer than
any of the software-side ring/slot settings above (``io-slots``, AF_XDP's
fill ring, DPDK's descriptor count, ...). It is the ring of receive buffers
the NIC writes received packets to via DMA, which the driver refills. On some
drivers/NICs it defaults far below what the hardware supports (e.g. 512 out
of a possible 8160 on an Intel i40e we tested), so at high rates any brief
delay in refilling it (e.g. from interrupt moderation, see above) can drain
it. This is visible as the ``rx_missed_errors`` counter in
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
requires ``io-slots-rx`` of 16384. BNG Blaster takes care of both automatically
for AF_XDP, see :ref:`AF_XDP <af-xdp-usage>`.

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

The profile did not distribute double-tagged PPPoE in our tests. Double-tagged
PPPoE, with outer type 0x8100 or 0x88a8 (``qinq``), was still received on a
single queue with the profile loaded, while single-tagged PPPoE was distributed. For double-tagged PPPoE, see
:ref:`RSS by VLAN and MAC on Intel 700 Series <rss-vlan-mac>`.

For :ref:`DPDK <dpdk-usage>`, the profile must be loaded via DPDK instead
of the kernel driver.

.. _rss-vlan-mac:

RSS by VLAN and MAC on Intel 700 Series
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Without the DDP profile, the Intel 700 Series hashes all non-IP traffic,
including PPPoE, only on the Ethernet type. All PPPoE packets have the same
Ethernet type, so they are received on the same queue. The fields used for
this hash can be extended by VLAN and MAC addresses. If each session has its
own VLAN or MAC address, as usual with the BNG Blaster, the traffic is then
distributed over all queues. This works for single-tagged, double-tagged and
QinQ (outer type 0x88a8) PPPoE, without the DDP profile.

.. warning::

    This method writes a NIC register directly via the debugfs interface of
    the i40e driver. It is a lab tweak and not an official interface of the
    driver. The register is global for all ports of the adapter and applies
    to all non-IP traffic. It is not persistent and must be set again after
    a reboot or reset of the adapter.

    Use it at your own risk. There is no guarantee that it works as
    described or that it does not cause damage or malfunction of the NIC.
    Register layout and values may change with firmware or driver versions
    and may differ between models of the same series. The values below were
    tested only with the adapter, firmware and driver used in our tests.

The register ``GLQF_HASH_INSET`` defines the hash fields for the packet type
*L2 payload* (63) in two 32-bit words. The following values were used in our
tests:

+----------------------------------+------------------+------------------+
| Hash fields                      | Low (0x2677F8)   | High (0x2677FC)  |
+==================================+==================+==================+
| Ethernet type (default)          | 0x00004000       | 0x00000000       |
+----------------------------------+------------------+------------------+
| Ethernet type, VLANs             | 0x04004000       | 0x00800000       |
+----------------------------------+------------------+------------------+
| Ethernet type, VLANs, MACs       | 0x04004000       | 0xFC800000       |
+----------------------------------+------------------+------------------+

VLANs means outer and inner VLAN, MACs means source and destination MAC address.
The register is written via the debugfs command file of one port of the
adapter (PCI address), with debugfs mounted. As the register is global, this
applies to all ports of the adapter.

.. code-block:: none

    F=/sys/kernel/debug/i40e/<pci-address>/command

    # hash on Ethernet type, VLANs and MAC addresses
    echo "write 0x2677F8 0x04004000" > $F
    echo "write 0x2677FC 0xFC800000" > $F

    # verify (result is shown in the kernel log)
    echo "read 0x2677F8" > $F
    echo "read 0x2677FC" > $F
    dmesg | tail -2

    # restore default (Ethernet type only)
    echo "write 0x2677F8 0x00004000" > $F
    echo "write 0x2677FC 0x00000000" > $F

For QinQ, the MAC addresses are required. The NIC does not recognize the outer
type 0x88a8 as VLAN by default, so the VLANs are not available for the hash.
The MAC addresses are always at the same position, and each BNG Blaster session
uses its own client MAC address (destination MAC address in downstream and
source MAC address in upstream direction).

In our tests with 650 PPPoE sessions (6.35 Mpps per interface and direction,
128-byte packets, 4 RX threads per interface, :ref:`AF_XDP <af-xdp-usage>`),
the traffic was distributed evenly over all 4 queues without loss for
single-tagged, double-tagged and QinQ PPPoE. With the default hash, all
traffic was received on one queue with up to 0.5% loss.

Unlike the DDP profile, which hashes the IP header inside PPPoE, this method
requires a different VLAN or MAC address per session. The DDP profile and this
method were not tested together.

.. note::

    We are continuously working to increase performance. Contributions, proposals,
    or recommendations on how to further increase performance are welcome!

.. _server-settings:

Server Settings
---------------

The settings of the server, its firmware (BIOS/UEFI) and the Linux kernel have a
large impact on high packet rates. Short interruptions of a thread of a few
microseconds are enough to cause loss at line rate, even if the average CPU
load looks fine.

BIOS/UEFI
~~~~~~~~~

The names of the settings depend on the vendor. Typical settings for a test
server are:

* **Power profile:** select a performance profile (e.g. *Maximum Performance*)
  instead of an energy-saving profile. Deep CPU sleep states (C-states) and
  frequency changes cause short delays when a CPU wakes up.
* **Virtualization for directed I/O:** enable Intel VT-d or AMD-Vi (also
  called AMD IOMMU), which is required for DPDK with ``vfio-pci``, for SR-IOV
  and for passing NICs through to virtual machines (see :ref:`IOMMU <iommu>`).
* **SR-IOV:** enable it if you want to split a NIC into virtual functions,
  e.g. for multiple BNG Blaster instances or virtual machines.

CPU Frequency Scaling
~~~~~~~~~~~~~~~~~~~~~

Linux lowers the CPU frequency of idle CPUs. Check the current scaling governor
and set it to ``performance`` for the duration of the tests (``cpupower``
is part of the ``linux-tools`` package).

.. code-block:: none

    cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c
    sudo cpupower frequency-set -g performance

.. _iommu:

IOMMU
~~~~~

The IOMMU translates the memory addresses a device uses for DMA, like the
MMU does for processes. It isolates devices from memory they do not own,
which is required to pass a device safely to a user-space driver (DPDK with
``vfio-pci``) or to a virtual machine. The kernel uses the IOMMU in one of the
following modes per device:

+---------------------------+----------------------+-----------------------------------------------+
| Mode                      | ``iommu_group/type`` | Description                                   |
+===========================+======================+===============================================+
| Disabled                  | no ``iommu_group``   | No address translation. DPDK with             |
|                           |                      | ``vfio-pci``, SR-IOV passthrough to VMs and   |
|                           |                      | device assignment are not possible.           |
+---------------------------+----------------------+-----------------------------------------------+
| Passthrough               | ``identity``         | Devices used by the kernel driver access      |
| (``iommu=pt``)            |                      | memory directly without translation, while    |
|                           |                      | devices assigned to DPDK or VMs are still     |
|                           |                      | isolated.                                     |
+---------------------------+----------------------+-----------------------------------------------+
| Translation               | ``DMA`` or           | Every DMA buffer of the kernel driver is      |
|                           | ``DMA-FQ``           | mapped and unmapped in the IOMMU, which costs |
|                           |                      | CPU time and can limit the packet rate.       |
+---------------------------+----------------------+-----------------------------------------------+

For a dedicated test server, passthrough is recommended: it keeps the IOMMU
available for DPDK, SR-IOV and VMs, without the overhead of translation for
interfaces used with the kernel driver (``packet_mmap``, ``raw`` and
``af_xdp``). Translation mode has caused severe RX loss with AF_XDP
zero-copy on Intel ice and i40e drivers in our tests (see
:ref:`AF_XDP <af-xdp-usage>`).

The mode of a NIC can be checked via its PCI address (``ethtool -i <interface>``
shows the ``bus-info``), together with the kernel command line:

.. code-block:: none

    cat /proc/cmdline
    cat /sys/bus/pci/devices/<pci-address>/iommu_group/type
    dmesg | grep -i -e DMAR -e IOMMU

The default mode depends on the platform, distribution and kernel. Passthrough
is set with kernel parameters, for example on Debian or Ubuntu via GRUB. On
Intel systems, ``intel_iommu=on`` enables the IOMMU if it isn't enabled by
default. On AMD systems, the IOMMU is enabled by default if enabled in the
BIOS.

.. code-block:: none

    # /etc/default/grub (Intel)
    GRUB_CMDLINE_LINUX_DEFAULT="... intel_iommu=on iommu=pt"
    # /etc/default/grub (AMD)
    GRUB_CMDLINE_LINUX_DEFAULT="... iommu=pt"

    sudo update-grub
    sudo reboot

.. note::

    In a virtual machine, the IOMMU visible to the guest is an emulated one
    (vIOMMU), if any. Devices passed through to the VM are translated by the
    IOMMU of the host, so the host must have it enabled (preferably in
    passthrough mode).

.. _interrupts:

Interrupts
~~~~~~~~~~

The kernel driver processes the received packets of a NIC queue (NAPI) on the
CPU handling the interrupt of this queue. This applies to ``packet_mmap``,
``raw`` and also to AF_XDP, but not to DPDK, which doesn't use interrupts. A BNG
Blaster thread on such a CPU competes with this processing, which can
significantly limit the throughput. BNG Blaster logs a warning for such
threads, and the :ref:`automatic CPU placement <cpu-pinning>` avoids those CPUs.

The interrupts of an interface and their CPUs are shown in ``/proc/interrupts``.
The ``irqbalance`` service moves interrupts to other CPUs at runtime, so the
placement checked at startup may not be valid anymore. Stop ``irqbalance``
during the tests (or exclude the CPUs used for the tests) and pin the
interrupts of the busy queues to CPUs without busy BNG Blaster threads.

.. code-block:: none

    systemctl stop irqbalance
    grep <interface> /proc/interrupts
    echo <cpu> > /proc/irq/<irq>/smp_affinity_list

PCIe
~~~~

Small packets require many PCIe transactions per byte. With an
Intel X710 4-port adapter in a PCIe 3.0 x4 slot, two ports with bidirectional
traffic of 128-byte packets reached only about 92% of line rate (6.5 Mpps per
port and direction), independent of the number of threads. Unidirectional
traffic of 128-byte packets reached line rate, and bidirectional traffic of
1400-byte packets reached line rate without loss. Check
the negotiated PCIe link width and speed of the adapter, and use a slot with
the full width supported by the adapter for small packets at line rate. The
slot also determines the NUMA node of the NIC (see below).

.. code-block:: none

    lspci -vv -s <pci-address> | grep -E "LnkCap:|LnkSta:"

Virtual Machines
~~~~~~~~~~~~~~~~

The virtual CPUs of a VM may share physical cores with each other or with
the host. In our tests, a VM with 14 virtual CPUs on a host with 8 physical
cores provided only the performance of about 8 cores if all virtual CPUs were
busy. Short interruptions by the host cause bursts of ``rx_missed_errors``.
If possible, pin the virtual CPUs to dedicated physical cores of the host,
pass the NIC or an SR-IOV virtual function through to the VM instead of
virtual NICs (requires the :ref:`IOMMU <iommu>` on the host), and use large
:ref:`NIC RX rings <nic-rx-ring>`.

.. _cpu-pinning:

NUMA and CPU Pinning
--------------------

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
* Avoid CPUs handling NIC interrupts of the used interfaces until no other CPU is free.
* Avoid CPUs used by other BNG Blaster instances running in parallel until no other CPU is free.
* Use only CPUs allowed for the process (see below).
* Fall back to the NUMA node CPU list and finally to all allowed CPUs if no local CPU list is exposed
  or none of the local CPUs is allowed.
* Pin the main thread to a free CPU as well, after all RX and TX threads got their CPU.

An RX or TX thread on a CPU handling NIC interrupts permanently competes with the kernel
processing of the NIC queues (see :ref:`Interrupts <interrupts>`), which can significantly limit
the throughput (e.g. AF_XDP TX completions). A warning is logged for each RX or TX thread running on
a CPU which handles NIC interrupts, including manually pinned threads.

Multiple BNG Blaster instances running in parallel (e.g. one per SR-IOV virtual function) coordinate
their automatic CPU placement. Each instance locks every CPU used by its threads with the file
``/run/lock/bngblaster_cpu<N>.<PID>.lock``, so ``ls /run/lock/bngblaster_cpu*`` shows which process
uses which CPU. A CPU locked by another instance is skipped by the automatic CPU placement. If all
local CPUs are used, a thread shares the CPU used by the fewest other instances and a warning is
logged.

Instances started at the same time are initialized one after another, serialized by the file
``/run/lock/bngblaster_startup.lock``, from the interface initialization until all threads are
started. This prevents conflicts during the initialization, for example selecting the same free
CPU, changing the configuration of the same NIC, or attaching AF_XDP sockets at the same time
(libbpf before version 1.0 fails if two processes attach AF_XDP sockets at the same time). With many
instances started at once, an instance can wait several minutes for its startup, which is logged
every 30 seconds. After 30 minutes, it starts without coordination and logs a warning.

.. code-block:: none

    Waiting for the startup of another BNG Blaster instance (process 4711)

The interfaces are locked with ``/run/lock/bngblaster_<interface>.lock``, so that two instances can
not use the same interface. All those are no simple lock files, which would remain after a crash,
but locks held by the kernel (``flock``), which are released when the instance exits, also if it is
killed or crashes. The files are removed on exit. Files left behind by a killed instance are not
locked anymore: interface lock files are simply reused and CPU lock files are removed by the next
instance. Do not remove those files while BNG Blaster is running, as this allows other instances to
use the same interface or CPU. With instances in different containers, ``/run/lock`` must be shared
between the containers for this coordination.

.. code-block:: none

    Warning: No free CPU for RX thread of interface eth1, sharing CPU 4 with another BNG Blaster instance

A warning is also logged for a manually pinned thread running on a CPU used by another instance.

The CPUs used by an instance can be restricted, for example to separate instances explicitly or to
keep CPUs free for other applications. The automatic CPU placement uses only CPUs allowed for the
process, which can be restricted with ``taskset``, the systemd property ``AllowedCPUs`` or the
cpuset of a container.

.. code-block:: none

    taskset -c 8-15 bngblaster -C test.json
    systemd-run --scope -p AllowedCPUs=8-15 bngblaster -C test.json

With ``taskset``, manually pinned threads (``rx-cpuset`` and ``tx-cpuset``) may still use other
CPUs, while a cgroup cpuset (``AllowedCPUs``, containers) is enforced. A thread which can't be
started on its CPU stops BNG Blaster with an error.

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

DPDK drives the NIC from user space with its own poll mode driver (PMD)
instead of the kernel driver. The interface is therefore not visible to Linux
anymore while it is used by DPDK, and is selected by its PCI address instead of
its name. The BNG Blaster initializes DPDK with the default settings for all
DPDK link interfaces, so the server must be prepared as follows.

1. **IOMMU:** enable VT-d or AMD-Vi in the BIOS and the IOMMU in the kernel,
   preferably in passthrough mode (see :ref:`IOMMU <iommu>`).

2. **Hugepages:** DPDK allocates its packet buffers from hugepages, which must
   be reserved before the test, ideally on the NUMA node of the NIC. 2 MB
   pages can be reserved at runtime, 1 GB pages are reserved at boot with
   kernel parameters (e.g. ``default_hugepagesz=1G hugepagesz=1G hugepages=8``).

   .. code-block:: none

       # reserve 2048 x 2 MB pages (4 GB) on NUMA node 0
       echo 2048 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
       grep Huge /proc/meminfo

3. **Driver binding:** most NICs (e.g. Intel) must be bound to the ``vfio-pci``
   driver with ``dpdk-devbind.py`` from the DPDK sources. The interface must be
   down before. NVIDIA (Mellanox) ConnectX NICs are an exception: their DPDK
   driver works together with the kernel driver ``mlx5_core``, which stays
   bound.

   .. code-block:: none

       sudo modprobe vfio-pci
       sudo ip link set <interface> down
       sudo dpdk-devbind.py --bind=vfio-pci <pci-address>
       dpdk-devbind.py --status

   ``dpdk-devbind.py --bind=<kernel driver> <pci-address>`` (e.g. ``i40e``)
   returns the NIC to the kernel after the tests.

See the `DPDK Getting Started Guide <https://doc.dpdk.org/guides/linux_gsg/>`_
for details.


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
the number of threads to utilize more queues and enhance performance, as long
as RSS distributes the received traffic over those queues. DPDK RX threads
permanently poll their queue and use a full CPU core each, even without
traffic (see :ref:`If RSS Does Not Work <rss-not-working>`). Some drivers
require the DDP profile for PPPoE to be loaded via DPDK (see
:ref:`PPPoE RSS on Intel 700 Series <ddp-pppoe>`).


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

Interfaces without RSS indirection table (e.g. ``veth``, which receives on
the TX queue index of the peer) can't keep received traffic off the TX
queues. For those, the TX queues are bound for RX as well and polled by an
additional RX thread (or job in the main loop) per TX queue, which is
logged with ``-l af_xdp``:

.. code-block:: none

    AF_XDP: interface veth1 has no RSS indirection table, TX queues are also used for RX

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

    Each packet is stored in a single AF_XDP frame (buffer) of 4096 bytes,
    so ``jumbo-frames`` are not supported by this I/O mode and the maximum
    stream packet length is reduced accordingly. On receive, the kernel
    reserves 256 bytes of each frame as headroom, so received packets larger
    than 3840 bytes are dropped by the kernel. The interface MTU may be
    larger than this.

Like DPDK, AF_XDP requires the NIC to actually provide as many hardware
queues as bngblaster needs, i.e. ``rx-threads`` + ``tx-threads`` (each
defaulting to 1 if left unset), since RX and TX never share a queue.
Some drivers support AF_XDP on fewer queues than the interface provides,
for example i40e only on as many queues as CPUs are available, which is
relevant for virtual machines with few CPUs. If a queue can't be bound
while the previous queues of the interface were bound, this is logged with
a hint to reduce the threads.
BNG Blaster reconfigures the interface to the required number of combined
queues automatically via ``ethtool``-equivalent ioctls (the same effect as
running ``ethtool -L <interface> combined <n>`` beforehand) - if that fails
(e.g. insufficient privileges, or a driver that splits RX/TX channels
instead of combined ones), it is logged with a hint to configure it
manually. Native (driver) mode additionally requires a driver with native
XDP support; BNG Blaster automatically falls back to generic (SKB) mode -
which works on any interface, including ``veth`` - if native mode is not
available. Some drivers do not support native mode if the interface MTU
exceeds their maximum linear frame size (e.g. i40e with an MTU larger than
3046 bytes), so lower the MTU (e.g. ``ip link set <interface> mtu 2048``)
to get native zero-copy mode, which performs much better than generic mode.

The mode is not selected based on the MTU. Native mode is always tried
first, and BNG Blaster falls back to generic mode only if the driver rejects
it, which is logged once per interface:

.. code-block:: none

    Warning: AF_XDP native mode not available for interface eth1 (Invalid argument), falling back to generic (SKB) mode

The selected mode is then used for all queues of this interface. The mode can be
selected per link with ``af-xdp-mode``: ``auto`` (default) uses native mode with zero-copy if
supported by the driver, ``zero-copy`` fails instead of falling back, ``copy`` uses native mode
without zero-copy and ``generic`` uses generic mode. ``copy-rx`` binds the RX queues in copy mode
and the TX queues like ``auto``, for drivers whose zero-copy RX performs badly while zero-copy TX
works (see below).

Zero-copy mode depends on the driver filling the NIC RX ring from the AF_XDP fill ring. With
the Intel ice (E810) and i40e (X710) drivers and an IOMMU in translation mode (``DMA`` or
``DMA-FQ`` in ``/sys/bus/pci/devices/<pci>/iommu_group/type``), some kernels (e.g. 6.8) fill the
ring only with a few buffers per interrupt, which drops most of the received packets. This is
visible in the kernel log as ``Failed to allocate some buffers on XSK buffer pool enabled Rx ring``
(ice) or ``Failed to allocate some buffers on AF_XDP ZC enabled Rx ring`` (i40e), and as
``rx_dropped`` increasing with only few packets per RX queue (``rx_queue_<n>_packets``). The NIC
may also send pause frames, so control traffic is lost as well. Use ``iommu=pt`` if possible,
otherwise ``af-xdp-mode`` ``copy-rx`` for such interfaces, which keeps zero-copy for TX (see
:ref:`IOMMU <iommu>` and :ref:`AF_XDP Tuning <af-xdp-tuning>`).

A warning is logged at startup if the interface MTU exceeds 3712
bytes (MTU plus 128 bytes of worst-case header overhead does not fit into the
3840 bytes of a received frame). The actual mode of each queue is logged with
``-l af_xdp``:

.. code-block:: none

    AF_XDP: interface eth1 queue 0 bound (native mode, zero-copy, RX only, 4096 RX / 0 TX frames of 4096 byte)
    AF_XDP: interface eth2 queue 0 bound (generic mode, copy, RX only, 4096 RX / 0 TX frames of 4096 byte)

Here, ``4096 RX / 0 TX frames`` is the number of frames (``io-slots``, or
``io-slots-rx`` and ``io-slots-tx`` per link, rounded up to a power of 2) and ``of 4096 byte`` is the size
of each frame, not the maximum packet size.

BNG Blaster increases the NIC RX ring to 4096 descriptors (limited to the NIC
maximum, a larger ring is kept), as the small default of some drivers (e.g. 512
on i40e) causes RX loss at high rates (see :ref:`NIC RX ring <nic-rx-ring>`).
The RX frames are sized to at least twice the NIC RX ring, e.g. 8192 RX frames
for a ring of 4096 or 16384 for a ring of 8160, unless ``io-slots-rx`` is
configured explicitly for the link, in which case a too small value is only
logged as warning. ``io-slots`` is used as minimum. Each frame uses 4096 bytes
of memory, so a ring of 4096 requires 32 MB per RX queue (64 MB for a ring of
8160).

.. code-block:: none

    AF_XDP: interface eth1 NIC RX ring increased to 4096 (was 512)
    AF_XDP: interface eth1 uses 8192 RX frames per queue for NIC RX ring 4096

.. note::

    If the NIC has more queues configured than bngblaster binds AF_XDP
    sockets to, RSS may hash some flows to a queue nothing is bound to -
    those packets are passed to the normal kernel stack instead of being
    redirected to bngblaster, which looks like silent RX loss for the
    affected flows. This is exactly what the automatic queue
    reconfiguration above avoids.

BNG Blaster changes the number of queues, the RSS indirection table, the NIC
RX ring and the RX VLAN offload of the interface. This configuration is saved
before and restored on exit, also if the initialization failed. The queues are
restored before the RSS indirection table, which might reference queues that
do not exist before. An RSS indirection table that was the driver default is
reset to the default (``ethtool -X <interface> default``) before the queues are
restored, so that the driver still adjusts it to later changes of the number of
queues. Some drivers (e.g. i40e) keep also the reset table and apply it again
if the number of queues is increased later, until the number of queues is
decreased. Therefore the number of queues is decreased by one before it is
restored, if restoring does not decrease it anyway. If the configuration can't
be restored completely, this is logged as error and BNG Blaster exits with a
non-zero exit status.

The saved configuration is also written to ``/run/lock/bngblaster_<interface>.af_xdp``
(next to the interface lock) and this file is removed after the configuration
was restored. If BNG Blaster is killed (e.g. ``SIGKILL``) or crashes, the next
test on this interface restores the configuration found by the killed instance
from this file instead of the configuration left behind:

.. code-block:: none

    Warning: AF_XDP interface eth1 was not restored by a previous BNG Blaster (killed or crashed), the NIC configuration saved in /run/lock/bngblaster_eth1.af_xdp is restored on exit

As ``/run/lock`` is writable by all users, this file is only used if it is a
regular file (no symbolic link) owned by the same user and not writable by
group or others, as written by BNG Blaster (mode ``0600``). Otherwise, it is
ignored with a warning and the configuration found at startup is restored.
This means that the configuration left behind by a killed instance of
another user (e.g. a test run without ``sudo`` followed by one with ``sudo``)
is not restored.

BNG Blaster removes its AF_XDP sockets on exit, which also detaches the XDP
program from the interface. An XDP program which is still attached after
the sockets are removed is detached on exit as well, if the interface had no
XDP program attached at startup (e.g. attached via netlink by libbpf before
version 1.0 instead of a BPF link). If BNG Blaster built with libxdp is killed or
crashes, the XDP program stays attached, as libxdp attaches it via netlink
and not via a BPF link that is released with the process. Such a program
does not prevent further tests, but keeps the interface in XDP mode (e.g.
the MTU can't be increased beyond the driver limit). It is removed on exit
by the next test, if the saved configuration of the killed instance (see
above) shows that the interface had no XDP program attached before.
Otherwise, it is not removed by later tests, as it might also be used by
another application. A warning is logged at startup if an XDP program is
already attached:

.. code-block:: none

    Warning: AF_XDP interface eth1 has XDP program 194 already attached (e.g. left behind by a killed BNG Blaster), please remove it if not used by another application (e.g. 'xdp-loader unload eth1 --all')

Remove it manually with ``xdp-loader unload <interface> --all``, which also
removes the files pinned by libxdp in ``/sys/fs/bpf/xdp/``
(``ip link set <interface> xdp off`` detaches the program only).

.. _af-xdp-tuning:

AF_XDP Tuning
~~~~~~~~~~~~~

The following recommendations are based on tests with PPPoE traffic between
two directly connected 10G ports of an Intel X710 adapter (i40e driver),
using native zero-copy mode.

**RX threads:** The RX performance per thread depends on the CPU, packet
size and traffic type. In our tests with PPPoE, a single RX thread received up
to 2.4 Mpps per queue without loss and processed more than 6 Mpps with 0.1% to
0.5% loss. With IPv4 network traffic (76-byte packets), a single RX thread
received 10.9 Mpps (10G line rate) with 0.2% to 0.4% loss. The loss is
caused by short delays of the RX thread, not by its CPU capacity, so
distributing the traffic over more queues reduces loss even if a single thread
could process the full rate. RSS does not distribute traffic perfectly evenly,
so plan enough RX threads to keep the busiest queue well below this limit.
Typically, more RX than TX threads are required.

**TX threads:** TX threads permanently poll and therefore use a full CPU core
each, even if not sending at their limit. In our tests, a single TX thread
sent 10.9 Mpps (10G line rate with 76-byte packets), so one TX thread
per 10G interface was sufficient. Using fewer TX threads leaves more CPU
cores for RX threads.

**CPU cores:** Each RX and TX thread should have its own CPU. The total number
of RX and TX threads of all links plus the main thread must not exceed the
number of available CPUs, otherwise threads are delayed for short periods,
which shows up as bursts of ``rx_missed_errors`` even if the average CPU load
looks fine. Ideally, busy threads run on different physical cores, as SMT
siblings share the resources of one physical core.

**Buffers:** Short delays of RX threads can be absorbed with larger buffers.
In our tests, a NIC RX ring of 8160 with ``io-slots-rx`` of 16384 removed the
remaining loss caused by such delays (see the NIC RX ring requirements above).
BNG Blaster increases the NIC RX ring only to 4096, so set the larger ring
before the test (``ethtool -G <interface> rx 8160``), the RX frames are then
sized automatically.

**Zero-copy or copy mode:** Native zero-copy mode is the fastest mode and used by
default if supported by the driver. Copy mode (``"af-xdp-mode": "copy"``) copies each
packet between the driver and the AF_XDP frames, which limits the packet rate. In our
tests, a single RX and TX thread reached about 4.4 Mpps in copy mode compared to 11 Mpps
(10G line rate with 76-byte packets) in zero-copy mode. Use copy mode only for interfaces where zero-copy
mode performs badly, e.g. the Intel ice or i40e driver with an IOMMU in translation mode (see
above), where copy mode performed much better than zero-copy mode. If only RX is affected,
``"af-xdp-mode": "copy-rx"`` limits copy mode to the RX queues and keeps zero-copy for TX.
On an X710 (i40e) with the IOMMU in ``DMA-FQ`` mode, this reached 4.47 Mpps without loss
with 27,000 double-tagged PPPoE sessions (1.40 Mpps RX on one access queue, 3.07 Mpps TX),
while about half of the sessions never came up with zero-copy RX. Check the actual
mode of each queue with ``-l af_xdp``.

.. _single-queue:

**Single queue:** If RSS can't distribute the received traffic, e.g. PPPoE
without the :ref:`DDP profile <ddp-pppoe>` or
:ref:`RSS by VLAN and MAC <rss-vlan-mac>`, all packets
of an interface are handled by one queue and one RX thread (see
:ref:`If RSS Does Not Work <rss-not-working>`). In our tests, this
worked without loss up to about 2.4 Mpps per interface and with up to 0.5% loss
at 6.35 Mpps. In this case, the CPU handling the interrupt of this queue is
important. The kernel processing of the received packets of the queue (NAPI)
took about a third of a CPU core in our tests. If this is the CPU of the RX
thread of the same queue, both share one core, which increased the loss from
below 0.5% to up to 21% in our tests. Pin the interrupt of the active queue to
a CPU without a busy BNG Blaster thread and stop ``irqbalance`` (see
:ref:`Interrupts <interrupts>`).

**Virtual machines and PCIe:** see :ref:`Server Settings <server-settings>`.

**Monitoring:** The following counters of ``ethtool -S <interface>`` help to
identify the bottleneck. ``rx_missed_errors`` counts packets dropped because no
free RX descriptor was available, which is caused by delayed or overloaded RX
threads. The per-queue counters (e.g. ``rx-<n>.packets``) show how RSS distributes
the traffic over the RX threads (see :ref:`RSS <rss>`).

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
