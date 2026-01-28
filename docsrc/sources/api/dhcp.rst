+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **dhcp-start**                    | | Start DHCP client.                                                 |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+
| **dhcp-stop**                     | | Stop DHCP client without sending a release message.                |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
|                                   | | ``keep-address`` remember last address (init-reboot)               |
+-----------------------------------+----------------------------------------------------------------------+
| **dhcp-release**                  | | Stop DHCP client with sending release messages.                    |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+
