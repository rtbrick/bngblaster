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

With multithreading, you should be able to scale up to at least 1 million PPS bidirectional, depending on 
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

    The BNG Blaster is currently tested for 1 million PPS with 1 million flows, which is not a 
    hard limitation but everything above should be considered with caution. It is also possible to 
    scale far beyond using DPDK-enabled interfaces. 

A single stream will be always handled by a single thread to prevent re-ordering. The single stream 
performance is limited by the TX interval multiplied by max bust size (`traffic->max-burst`) which 
is 32 in the default configuration. Therefore each stream is limited to around 32K PPS per default. 
This can be increased by changing the TX interval. With a TX interval of `0.1`, the single stream 
performance increases to 320K PPS. The max burst size is should not be increased to prevent microbursts. 

The following settings are recommended for most tests with 1M PPS or beyond. 

.. code-block:: json

    {
        "interfaces": {
            "tx-threads": 4,
            "tx-interval": 0.01,
            "rx-threads": 4,
            "rx-interval": 0.1,
            "io-slots": 32768
        }
    }

It is also recommended to increase the hardware and software queue size of your
network interface links to the maximum for higher throughput as explained 
in the :ref:`Operating System Settings <interfaces>`. 

The packet receives performance is also limited by the abilities of your network 
interfaces to properly distribute the traffic over multiple hardware queues. Some
network interfaces are not able to distribute traffic based on VLAN or PPPoE session
identifiers. In this case, all traffic is received by the same hardware queue and 
corresponding thread. If CPU utilization is not properly distributed over all
cores, this could be the reason. 

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
            "tx-interval": 0.1,
            "rx-interval": 0.1,
            "links": [
                {
                    "interface": "0000:23:00.0",
                    "io-mode": "dpdk",
                    "rx-threads": 4,
                    "rx-cpuset": [4,5,6,7],
                    "tx-threads": 3,
                    "tx-cpuset": [1,2,3]
                },
                {
                    "interface": "0000:23:00.2",
                    "io-mode": "dpdk",
                    "rx-threads": 4,
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

