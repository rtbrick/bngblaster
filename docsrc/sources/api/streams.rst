+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **stream-stats**                  | | Display stream traffic statistics.                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **stream-info**                   | | Display stream/flow information.                                   |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``flow-id``                                                        |
+-----------------------------------+----------------------------------------------------------------------+
| **stream-summary**                | | Display stream/flow summary information.                           |
+-----------------------------------+----------------------------------------------------------------------+
| **stream-reset**                  | | Reset all traffic streams.                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **stream-start**                  | | This command can be used to start or stop traffic stream flows.    |
| **stream-stop**                   | | This command applies to all flows except session-traffic and       |
|                                   | | multicast. If you provide a specific ``flow-id`` as an argument,   |
|                                   | | other arguments are ignored. In this particular case, you can also |
|                                   | | start and stop session-traffic and multicast.                      |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``flow-id``                                                        |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
|                                   | | ``name``                                                           |
|                                   | | ``direction`` [both(default), upstream, downstream]                |
+-----------------------------------+----------------------------------------------------------------------+
| **streams-pending**               | | List flow-id of all pending (not verified) traffic streams.        |
+-----------------------------------+----------------------------------------------------------------------+