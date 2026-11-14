+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **bfd-sessions**                  | | Display all matching BFD sessions.                                 |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``bfd-session-id``                                                 |
|                                   | | ``network-interface``                                              |
|                                   | | ``peer-address`` IPv4 or IPv6 address                              |
|                                   | | ``state`` e.g. Up, Down, Init or AdminDown                         |
+-----------------------------------+----------------------------------------------------------------------+
| **bfd-session-disable**           | | Set all matching BFD sessions administratively                     |
|                                   | | down (AdminDown with diagnostic 7).                                |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``bfd-session-id``                                                 |
|                                   | | ``network-interface``                                              |
|                                   | | ``peer-address``                                                   |
|                                   | | ``state``                                                          |
+-----------------------------------+----------------------------------------------------------------------+
| **bfd-session-enable**            | | Enable all matching BFD sessions again.                            |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``bfd-session-id``                                                 |
|                                   | | ``network-interface``                                              |
|                                   | | ``peer-address``                                                   |
|                                   | | ``state``                                                          |
+-----------------------------------+----------------------------------------------------------------------+
| **bfd-session-update**            | | Change the timers of all matching BFD sessions,                    |
|                                   | | which starts a poll sequence for sessions in state Up.             |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``tx-interval`` in milliseconds                                    |
|                                   | | ``rx-interval`` in milliseconds                                    |
|                                   | | ``multiplier``                                                     |
|                                   | | ``bfd-session-id``                                                 |
|                                   | | ``network-interface``                                              |
|                                   | | ``peer-address``                                                   |
|                                   | | ``state``                                                          |
+-----------------------------------+----------------------------------------------------------------------+
