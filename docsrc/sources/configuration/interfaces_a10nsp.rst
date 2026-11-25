.. code-block:: json

    { "interfaces": { "a10nsp": [] } }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **interface**                     | | Parent interface/link name (e.g. eth0, ...).                       |
+-----------------------------------+----------------------------------------------------------------------+
| **qinq**                          | | Set outer VLAN ethertype to QinQ (0x88a8).                         |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **mac**                           | | Overwrite the A10NSP MAC address.                                  |
|                                   | | Default: `parent interface/link MAC address`                       |
+-----------------------------------+----------------------------------------------------------------------+
| **session-lookup**                | | Session lookup for received packets (mac or agent-remote-id).      |
|                                   | | With mac, the session is derived from the client MAC address.      |
|                                   | | With agent-remote-id, PPPoE discovery is mapped by the             |
|                                   | | Agent-Remote-Id and session packets by the assigned PPPoE          |
|                                   | | session-id (PPPoE only).                                           |
|                                   | | Default: mac                                                       |
+-----------------------------------+----------------------------------------------------------------------+
