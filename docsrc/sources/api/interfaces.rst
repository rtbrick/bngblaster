+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **interfaces**                    | | List all interfaces with index.                                    |
+-----------------------------------+----------------------------------------------------------------------+
| **access-interfaces**             | | List all access interface functions.                               |
+-----------------------------------+----------------------------------------------------------------------+
| **access-protocol-stats**         | | Display access interface protocol packet and timeout statistics    |
|                                   | | as included in the final report (protocol-stats).                  |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``interface``                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **network-interfaces**            | | List all network interface functions.                              |
+-----------------------------------+----------------------------------------------------------------------+
| **a10nsp-interfaces**             | | List all a10nsp interface functions.                               |
+-----------------------------------+----------------------------------------------------------------------+
| **lag-info**                      | | List all link aggregation (LAG) interfaces.                        |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``interface``                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **interface-enable**              | | Enable interface.                                                  |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``interface`` Mandatory                                            |
+-----------------------------------+----------------------------------------------------------------------+
| **interface-disable**             | | Disable interface.                                                 |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``interface`` Mandatory                                            |
+-----------------------------------+----------------------------------------------------------------------+
| **interface-topology**            | | Display NUMA node, local CPU set and I/O thread pinning            |
|                                   | | (CPU, queue and state) per interface.                              |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``interface``                                                      |
+-----------------------------------+----------------------------------------------------------------------+

The access protocol statistics include packet counters per protocol
and timeout counters. The counter
``lcp-echo-timeout`` is incremented for each LCP echo request without
response and ``lcp-echo-expired`` for each session terminated because
all LCP echo requests (``lcp`` ``keepalive-retry``) remained without
response.

``$ sudo bngblaster-cli run.sock access-protocol-stats interface eth1``

The interface topology command helps to verify NUMA locality and CPU
pinning of the RX and TX threads configured with ``rx-cpuset``,
``tx-cpuset``, ``rx-auto-cpuset`` or ``tx-auto-cpuset``. The queue
is shown for DPDK and AF_XDP interfaces only.

``$ sudo bngblaster-cli run.sock interface-topology interface eth1``

.. code-block:: none

    interface: eth1
      io-mode: af_xdp
      numa-node: 0
      local-cpuset: [0, 1, 2, 3, 4, 5, 6, 7]
      rx-auto-cpuset: True
      rx-thread id=0 cpu=2 source=auto queue=0 active=True stopped=False
      rx-thread id=1 cpu=3 source=auto queue=1 active=True stopped=False
      tx-auto-cpuset: False
      tx-thread id=0 cpu=4 source=manual queue=0 active=True stopped=False
