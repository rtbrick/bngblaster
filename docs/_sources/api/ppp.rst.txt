+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **ipcp-open**                     | | Open IPCP.                                                         |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+
| **ipcp-close**                    | | Close IPCP.                                                        |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+
| **ip6cp-open**                    | | Open IP6CP.                                                        |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+
| **ip6cp-close**                   | | Close IP6CP.                                                       |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+
| **lcp-echo-request-ignore**       | | Ignore LCP echo-request from BNG.                                  |
|                                   | | This feature can be used to enforce LCP timeouts on the BNG.       |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+
| **lcp-echo-request-accept**       | | Accept LCP echo-request from BNG (restore default behavior).       |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``session-group-id`` (ignored if session-id is present)            |
+-----------------------------------+----------------------------------------------------------------------+