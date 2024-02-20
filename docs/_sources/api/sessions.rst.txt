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
| **session-start**                 | | Start/stop sessions.                                               |
| **session-stop**                  | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+
| **session-restart**               | | Restart sessions.                                                  |
|                                   | | The argument ``reconnect-delay`` is only applicable in combination |
|                                   | | with session reconnect enabled in the configuration. This argument |
|                                   | | delays the session reconnect by the defined amount of seconds.     |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
|                                   | | ``reconnect-delay``                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **session-streams**               | | Display session streams.                                           |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id`` Mandatory                                           |
+-----------------------------------+----------------------------------------------------------------------+
| **session-traffic**               | | Display session traffic statistics.                                |
+-----------------------------------+----------------------------------------------------------------------+
| **session-traffic-start**         | | This command can be used to start or stop session-traffic flows.   |
| **session-traffic-stop**          | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
|                                   | | ``direction`` (upstream/downstream/both)                           |
+-----------------------------------+----------------------------------------------------------------------+
| **session-traffic-reset**         | | Reset all session traffic streams.                                 |
+-----------------------------------+----------------------------------------------------------------------+
