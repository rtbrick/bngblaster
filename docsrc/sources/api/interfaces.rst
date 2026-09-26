+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **interfaces**                    | | List all interfaces with index.                                    |
+-----------------------------------+----------------------------------------------------------------------+
| **access-interfaces**             | | List all access interface functions.                               |
+-----------------------------------+----------------------------------------------------------------------+
| **network-interfaces**            | | List all network interface functions.                              |
+-----------------------------------+----------------------------------------------------------------------+
| **a10nsp-interfaces**             | | List all a10nsp interface functions.                               |
+-----------------------------------+----------------------------------------------------------------------+
| **lag-info**                      | | List all link aggregation (LAG) interfaces.                        |
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

The interface topology command helps to verify NUMA locality and CPU
pinning of the RX and TX threads configured with ``rx-cpuset``,
``tx-cpuset``, ``rx-auto-cpuset`` or ``tx-auto-cpuset``. The queue
is shown for DPDK and AF_XDP interfaces only.

``$ sudo bngblaster-cli run.sock interface-topology interface eth1``
