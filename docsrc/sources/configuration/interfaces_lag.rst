.. code-block:: json

    { "interfaces": { "lag": [] } }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **interface**                     | | LAG interface name (e.g. lag0, ...).                               |
+-----------------------------------+----------------------------------------------------------------------+
| **lacp**                          | | Enable LACP.                                                       |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **lacp-timeout-short**            | | Enable LACP short timeout (3x1s)                                   |
|                                   | | Default: false (3x30s)                                             |
+-----------------------------------+----------------------------------------------------------------------+
| **lacp-system-priority**          | | LACP system priority.                                              |
|                                   | | Default: 32768                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **lacp-system-id**                | | LACP system identifier                                             |
|                                   | | Default: 02:ff:ff:ff:ff:00                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **lacp-min-active-links**         | | Define the minimum number of active links.                         |
|                                   | | Default: 0                                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **lacp-max-active-links**         | | Limit the maximum number of active links.                          |
|                                   | | Default: 255                                                       |
+-----------------------------------+----------------------------------------------------------------------+
| **mac**                           | | LAG interface MAC address.                                         |
|                                   | | Default: 02:ff:ff:ff:ff:<interface-id>                             |
+-----------------------------------+----------------------------------------------------------------------+
| **monkey**                        | | Flap (disable/enable) one random member interface every 30 seconds.|
|                                   | | Members flap independently, so all members can be down at the same |
|                                   | | time. The commands monkey-start and monkey-stop control it as well |
|                                   | | as the session monkey (sessions->monkey-autostart).                |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+

.. note::

    Multithreaded TX is not supported for LAG member interfaces!
