+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **igmp-join**                     | | Join group.                                                        |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id`` Mandatory                                           |
|                                   | | ``group`` Mandatory                                                |
|                                   | | ``source1`` first IGMPv3/SSM source address for the group.         |
|                                   | | ``source2`` second IGMPv3/SSM source address for the group.        |
|                                   | | ``source3`` third IGMPv3/SSM source address for the group.         |
+-----------------------------------+----------------------------------------------------------------------+
| **igmp-join-iter**                | | Join multiple groups over all sessions.                            |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``group`` Mandatory                                                |
|                                   | | ``group-iter`` IPv4 address step used to iterate over multiple     |
|                                   | | groups (e.g. ``0.0.0.1``). Default: ``0.0.0.1``                    |
|                                   | | ``group-count`` number of groups to iterate over. The groups       |
|                                   | | are assigned round-robin to all sessions.                          |
|                                   | | ``source1`` first IGMPv3/SSM source address for the group.         |
|                                   | | ``source2`` second IGMPv3/SSM source address for the group.        |
|                                   | | ``source3`` third IGMPv3/SSM source address for the group.         |
+-----------------------------------+----------------------------------------------------------------------+
| **igmp-leave**                    | | Leave group.                                                       |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id`` Mandatory                                           |
|                                   | | ``group`` Mandatory                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **igmp-leave-all**                | | Leave all groups from all sessions.                                |
+-----------------------------------+----------------------------------------------------------------------+
| **igmp-info**                     | | Display group information.                                         |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id`` Mandatory                                           |
+-----------------------------------+----------------------------------------------------------------------+
| **zapping-start**                 | | Start IGMP zapping test.                                           |
+-----------------------------------+----------------------------------------------------------------------+
| **zapping-stop**                  | | Stop IGMP zapping test.                                            |
+-----------------------------------+----------------------------------------------------------------------+
| **zapping-stats**                 | | Display IGMP zapping stats.                                        |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``reset``                                                          |
+-----------------------------------+----------------------------------------------------------------------+