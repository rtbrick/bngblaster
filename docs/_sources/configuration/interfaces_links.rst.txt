The link configuration is optional and allows defining per interface link configurations. An explicit
link configuration with the global default settings is automatically generated if no link is defined
for interface links referenced by interface functions. 

.. code-block:: json

    { "interfaces": { "links": [] } }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **interface**                     | | Interface name (e.g. eth0, ...).                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **description**                   | | Interface description.                                             |
+-----------------------------------+----------------------------------------------------------------------+
| **mac**                           | | Overwrite the MAC address.                                         |
|                                   | | Default: `physical interface MAC address`                          |
+-----------------------------------+----------------------------------------------------------------------+
| **lag-interface**                 | | Add interface/link to LAG group.                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **lacp-priority**                 | | LACP interface priority.                                           |
|                                   | | Only applies together with **lag-interface**.                      |
|                                   | | Default: 32768 Range: 0 - 65535                                    |
+-----------------------------------+----------------------------------------------------------------------+
| **loopback-peer**                 | | Peer link for I/O mode ``loopback``. It is sufficient to define    |
|                                   | | the peer on one of both links.                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **tx-cpuset**                     | | Optionally pin TX threads to CPU cores (cpuset). Manual pinning    |
|                                   | | overrides automatic CPU placement. A single number or a list       |
|                                   | | of numbers (e.g. ``[1, 2]``) is accepted.                          |
+-----------------------------------+----------------------------------------------------------------------+
| **rx-cpuset**                     | | Optionally pin RX threads to CPU cores (cpuset). Manual pinning    |
|                                   | | overrides automatic CPU placement. A single number or a list       |
|                                   | | of numbers (e.g. ``[1, 2]``) is accepted.                          |
+-----------------------------------+----------------------------------------------------------------------+
| **tx-auto-cpuset**                | | Automatically pin TX threads to CPUs local to the interface.       |
|                                   | | BNG Blaster prefers local physical cores before SMT siblings.      |
|                                   | | Default: **interfaces->tx-auto-cpuset** (false)                    |
|                                   | | Uses only CPUs allowed for the process (e.g. taskset) and avoids   |
|                                   | | CPUs used by other instances, see                                  |
|                                   | | :ref:`CPU pinning <cpu-pinning>`.                                  |
+-----------------------------------+----------------------------------------------------------------------+
| **rx-auto-cpuset**                | | Automatically pin RX threads to CPUs local to the interface.       |
|                                   | | BNG Blaster prefers local physical cores before SMT siblings.      |
|                                   | | Default: **interfaces->rx-auto-cpuset** (false)                    |
|                                   | | Uses only CPUs allowed for the process (e.g. taskset) and avoids   |
|                                   | | CPUs used by other instances, see                                  |
|                                   | | :ref:`CPU pinning <cpu-pinning>`.                                  |
+-----------------------------------+----------------------------------------------------------------------+
| **io-mode**                       | | Overwrite the IO mode.                                             |
+-----------------------------------+----------------------------------------------------------------------+
| **io-burst**                      | | Overwrite the IO burst.                                            |
+-----------------------------------+----------------------------------------------------------------------+
| **io-slots**                      | | Overwrite the IO slots (ring size).                                |
+-----------------------------------+----------------------------------------------------------------------+
| **io-slots-tx**                   | | Overwrite the TX IO slots (ring size).                             |
+-----------------------------------+----------------------------------------------------------------------+
| **io-slots-rx**                   | | Overwrite the RX IO slots (ring size).                             |
|                                   | | With AF_XDP, the RX frames are sized automatically to at least     |
|                                   | | twice the NIC RX ring if not set explicitly.                       |
+-----------------------------------+----------------------------------------------------------------------+
| **af-xdp-mode**                   | | AF_XDP socket mode: ``auto``, ``zero-copy``, ``copy``              |
|                                   | | or ``generic``. ``auto`` prefers native zero-copy mode             |
|                                   | | and falls back to copy or generic mode. ``copy``                   |
|                                   | | avoids the zero-copy mode of the driver.                           |
|                                   | | Default: auto                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **qdisc-bypass**                  | | Overwrite the kernel's qdisc layer configuration.                  |
+-----------------------------------+----------------------------------------------------------------------+
| **tx-interval**                   | | Overwrite the TX polling interval in milliseconds.                 |
+-----------------------------------+----------------------------------------------------------------------+
| **rx-interval**                   | | Overwrite the RX polling interval in milliseconds.                 |
+-----------------------------------+----------------------------------------------------------------------+
| **tx-threads**                    | | Overwrite the number of TX threads per interface link.             |
+-----------------------------------+----------------------------------------------------------------------+
| **rx-threads**                    | | Overwrite the number of RX threads per interface link.             |
+-----------------------------------+----------------------------------------------------------------------+
