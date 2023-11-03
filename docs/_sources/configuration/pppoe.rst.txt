.. code-block:: json

    { "pppoe": {} }

+-----------------------+------------------------------------------------------------------+
| Attribute             | Description                                                      |
+=======================+==================================================================+
| **session-time**      | | Max PPPoE session time in seconds.                             |
|                       | | Default: 0 (infinity)                                          |
+-----------------------+------------------------------------------------------------------+
| **reconnect**         | | Automatically reconnect sessions if terminated.                |
|                       | | Default: false                                                 |
+-----------------------+------------------------------------------------------------------+
| **discovery-timeout** | | PPPoE discovery (PADI and PADR) timeout in seconds.            |
|                       | | Default: 5                                                     |
+-----------------------+------------------------------------------------------------------+
| **discovery-retry**   | | PPPoE discovery (PADI and PADR) max retry.                     |
|                       | | Default: 10                                                    |
+-----------------------+------------------------------------------------------------------+
| **service-name**      | | PPPoE discovery service name.                                  |
|                       | | Default:                                                       |
+-----------------------+------------------------------------------------------------------+
| **host-uniq**         | | PPPoE discovery host-uniq.                                     |
|                       | | Default: false                                                 |
+-----------------------+------------------------------------------------------------------+
| **vlan-priority**     | | VLAN PBIT for all PPPoE/PPP control traffic.                   |
|                       | | Default: 0                                                     |
+-----------------------+------------------------------------------------------------------+
