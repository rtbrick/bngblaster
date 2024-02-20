.. _performance:

Performance Guide
=================

The BNG Blaster handles all traffic sent and received (I/O) in the main thread per default. 
With this default behavior, you can achieve between 100.000 and 250.000 PPS bidirectional 
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
                    "tx-threads": 2,
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
often not supported. 

Therefore best results can be reached with single tagged IPoE traffic. Depending
on the actual network adapter, there are different options to address this 
limitation. For instance, Intel adapters support different 
Dynamic Device Personalization (DDP) to support RSS for PPPoE traffic. 

You can also boost the performance by adjusting some driver settings. For example,
we found that the following setting improved the performance for
`Intel 700 Series <https://www.kernel.org/doc/html/v6.6/networking/device_drivers/ethernet/intel/i40e.html>`_
in some of our tests. However, these settings may vary depending on your specific
test environment.

.. code-block:: none

    ethtool -C <interface> adaptive-rx off adaptive-tx off rx-usecs 125 tx-usecs 125

.. note::

    We are continuously working to increase performance. Contributions, proposals,
    or recommendations on how to further increase performance are welcome!

.. _dpdk-usage:

DPDK
----

Using the experimental `DPDK <https://www.dpdk.org/>`_ support requires building 
the BNG Blaster from sources with DPDK enabled as explained 
in the corresponding :ref:`installation <install-dpdk>` section. 

.. note::

    The official BNG Blaster Debian release packages do not support 
    `DPDK <https://www.dpdk.org/>`_!

.. code-block:: json

    {
        "interfaces": {
            "io-slots": 32768
            "links": [
                {
                    "interface": "0000:23:00.0",
                    "io-mode": "dpdk",
                    "rx-threads": 8,
                    "rx-cpuset": [4,5,6,7],
                    "tx-threads": 3,
                    "tx-cpuset": [1,2,3]
                },
                {
                    "interface": "0000:23:00.2",
                    "io-mode": "dpdk",
                    "rx-threads": 8,
                    "rx-cpuset": [12,13,14,15],
                    "tx-threads": 3,
                    "tx-cpuset": [9,10,11]
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
