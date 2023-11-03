+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **session-info**                  | | Display session information.                                       |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **session-counters**              | | Display session counters.                                          |
+-----------------------------------+----------------------------------------------------------------------+
| **sessions-pending**              | | List all sessions not established.                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **session-traffic**               | | Display session traffic statistics.                                |
+-----------------------------------+----------------------------------------------------------------------+
| **session-traffic-start**         | | Enable/start session traffic.                                      |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **session-traffic-stop**          | | Disable/stop session traffic.                                      |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **session-traffic-reset**         | | Reset all session traffic streams.                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **session-streams**               | | Display session streams.                                           |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id`` Mandatory                                           |
+-----------------------------------+----------------------------------------------------------------------+
| **session-start**                 | | Start session manually.                                            |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id``                                               |
+-----------------------------------+----------------------------------------------------------------------+
| **session-stop**                  | | Stop sessions manually.                                            |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id``                                               |
+-----------------------------------+----------------------------------------------------------------------+
| **session-restart**               | | Restart sessions manually.                                         |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id``                                               |
|                                   | | ``reconnect-delay``                                                |
+-----------------------------------+----------------------------------------------------------------------+

The argument ``reconnect-delay`` is only applicable in combination with
session reconnect enabled in the configuration. This argument delays the 
session reconnect by the defined amount of seconds. 