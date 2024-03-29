.. code-block:: json

    { "ospf": {} }

+----------------------------------+-------------------------------------------------------------------+
| Attribute                        | Description                                                       |
+==================================+===================================================================+
| **instance-id**                  | | OSPF instance identifier.                                       |
+----------------------------------+-------------------------------------------------------------------+
| **version**                      | | OSPF version.                                                   |
|                                  | | Default: 2                                                      |
+----------------------------------+-------------------------------------------------------------------+
| **auth-key**                     | | OSPF authentication key.                                        |
+----------------------------------+-------------------------------------------------------------------+
| **auth-type**                    | | OSPF authentication type (simple or md5).                       |
+----------------------------------+-------------------------------------------------------------------+
| **hello-interval**               | | OSPF hello interval in seconds.                                 |
|                                  | | Default: 10 Range: 1 - 65535                                    |
+----------------------------------+-------------------------------------------------------------------+
| **dead-interval**                | | OSPF dead interval in seconds.                                  |
|                                  | | Default: 40 Range: 1 - 65535                                    |
+----------------------------------+-------------------------------------------------------------------+
| **lsa-retry-interval**           | | OSPF LSA retry interval in seconds.                             |
|                                  | | Default: 5 Range: 1 - 65535                                     |
+----------------------------------+-------------------------------------------------------------------+
| **hostname**                     | | OSPF hostname.                                                  |
|                                  | | Default: bngblaster                                             |
+----------------------------------+-------------------------------------------------------------------+
| **router-id**                    | | OSPF router identifier.                                         |
|                                  | | Default: 10.10.10.10                                            |
+----------------------------------+-------------------------------------------------------------------+
| **router-priority**              | | OSPF router priority.                                           |
|                                  | | Default: 64 Range: 0 - 255                                      |
+----------------------------------+-------------------------------------------------------------------+
| **area**                         | | OSPF area.                                                      |
|                                  | | Default: 0.0.0.0                                                |
+----------------------------------+-------------------------------------------------------------------+
| **sr-base**                      | | OSPF SR base.                                                   |
|                                  | | Default: 0 Range: 0 - 1048575                                   |
+----------------------------------+-------------------------------------------------------------------+
| **sr-range**                     | | OSPF SR range.                                                  |
|                                  | | Default: 0 Range: 0 - 1048575                                   |
+----------------------------------+-------------------------------------------------------------------+
| **sr-node-sid**                  | | OSPF SR node SID.                                               |
|                                  | | Default: 0 Range: 0 - 1048575                                   |
+----------------------------------+-------------------------------------------------------------------+
| **teardown-time**                | | OSPF teardown time in seconds.                                  |
|                                  | | Default: 5 Range: 0 - 65535                                     |
+----------------------------------+-------------------------------------------------------------------+
