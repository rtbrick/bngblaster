+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **ancp-sessions**                 | | Display all ANCP adjacencies with state, Port-Up trigger and       |
|                                   | | number of bound, established and Port-Up sessions.                 |
+-----------------------------------+----------------------------------------------------------------------+
| **ancp-port-up**                  | | Send Port-Up and keep the port up regardless of the                |
|                                   | | **port-up-trigger** (requires an established adjacency).           |
|                                   | | Without ``session-id``, all sessions (of ``ancp-session-id``).     |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``ancp-session-id``                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **ancp-port-down**                | | Send Port-Down and keep the port down.                             |
|                                   | | Without ``session-id``, all sessions (of ``ancp-session-id``).     |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``ancp-session-id``                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **ancp-port-auto**                | | Return the port to **port-up-trigger** control.                    |
|                                   | | Without ``session-id``, all sessions (of ``ancp-session-id``).     |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``ancp-session-id``                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **ancp-adjacency-down**           | | Close the ANCP TCP connection and do not reconnect.                |
|                                   | | Without ``ancp-session-id``, all adjacencies.                      |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``ancp-session-id``                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **ancp-adjacency-up**             | | Reconnect an adjacency disabled by **ancp-adjacency-down**.        |
|                                   | | Without ``ancp-session-id``, all adjacencies.                      |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``ancp-session-id``                                                |
+-----------------------------------+----------------------------------------------------------------------+
