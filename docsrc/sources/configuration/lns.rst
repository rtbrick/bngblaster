.. code-block:: json

    { "l2tp-server": [] }

+-------------------------------------------+---------------------------------------------------------------------+
| Attribute                                 | Description                                                         |
+===========================================+=====================================================================+
| **name**                                  | | Mandatory L2TP LNS server hostname (AVP 7)                        |
+-------------------------------------------+---------------------------------------------------------------------+
| **address**                               | | Mandatory L2TP server address.                                    |
+-------------------------------------------+---------------------------------------------------------------------+
| **secret**                                | | Tunnel secret.                                                    |
+-------------------------------------------+---------------------------------------------------------------------+
| **receive-window-size**                   | | Control messages receive window size.                             |
|                                           | | Default: 16 Range: 1 - 65535                                      |
+-------------------------------------------+---------------------------------------------------------------------+
| **max-retry**                             | | Control messages max retry.                                       |
|                                           | | Default: 5 Range: 1 - 65535                                       |
+-------------------------------------------+---------------------------------------------------------------------+
| **congestion-mode**                       | | Control messages congestion mode (default, slow or aggressive).   |
|                                           | | The BNG Blaster supports different congestion modes for the       |
|                                           | | reliable delivery of control messages. The default mode is        |
|                                           | | described in RFC2661 appendix A (Control Channel Slow Start and   |
|                                           | | Congestion Avoidance). The mode slow uses a fixed control window  |
|                                           | | size of 1 where aggressive sticks to max permitted based on peer  |
|                                           | | received window size.                                             |
|                                           | | Default: default                                                  |
+-------------------------------------------+---------------------------------------------------------------------+
| **hello-interval**                        | | Set hello interval.                                               |
|                                           | | Default: 30 Range: 1 - 65535                                      |
+-------------------------------------------+---------------------------------------------------------------------+
| **data-control-priority**                 | | Set the priority bit in the L2TP header for all non-IP data       |
|                                           | | packets (LCP, IPCP, ...).                                         |
|                                           | | Default: false                                                    |
+-------------------------------------------+---------------------------------------------------------------------+
| **data-length**                           | | Set length bit for all data packets.                              |
|                                           | | Default: false                                                    |
+-------------------------------------------+---------------------------------------------------------------------+
| **data-offset**                           | | Set offset bit with offset zero for all data packets.             |
|                                           | | Default: false                                                    |
+-------------------------------------------+---------------------------------------------------------------------+
| **control-tos**                           | | Set L2TP control traffic (SCCRQ, ICRQ, ...) TOS priority.         |
|                                           | | Default: 0 Range: 0 - 255                                         |
+-------------------------------------------+---------------------------------------------------------------------+
| **data-control-tos**                      | | Set the L2TP tunnel TOS priority (outer IPv4 header) for all      |
|                                           | | non-IP data packets (LCP, IPCP, ...).                             |
|                                           | | Default: 0 Range: 0 - 255                                         |
+-------------------------------------------+---------------------------------------------------------------------+
| **lcp-padding**                           | | Add fixed padding to LCP packets send from LNS.                   |
|                                           | | Default: 0 Range: 0 - 65535                                       |
+-------------------------------------------+---------------------------------------------------------------------+


