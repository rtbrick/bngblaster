.. code-block:: json

    { "l2tp-client": [] }

+-------------------------------------------+---------------------------------------------------------------------+
| Attribute                                 | Description                                                         |
+===========================================+=====================================================================+
| **group-id**                              | | Mandatory group identifier.  All ``l2tp-client`` entries with     |
|                                           | | the same ``group-id`` form a group.  Access interface sections    |
|                                           | | reference the group via ``l2tp-client-group-id``.  Sessions are   |
|                                           | | spread evenly across all tunnels in the group.                    |
|                                           | | Range: 1 - 65535                                                  |
+-------------------------------------------+---------------------------------------------------------------------+
| **name**                                  | | Mandatory L2TP LAC client name sent as hostname (AVP 7).          |
+-------------------------------------------+---------------------------------------------------------------------+
| **network-interface**                     | | Mandatory name of the network interface used to reach the LNS.    |
+-------------------------------------------+---------------------------------------------------------------------+
| **server-address**                        | | Mandatory IPv4 address of the LNS to connect to.                  |
+-------------------------------------------+---------------------------------------------------------------------+
| **client-address**                        | | Optional source IPv4 address used for outgoing L2TP/UDP packets.  |
|                                           | | Defaults to the network interface address when not set.  When     |
|                                           | | set, BNG Blaster automatically answers ARP requests for this      |
|                                           | | address on the network interface. For now, all l2tp-clients must  |
|                                           | | have a different address.                                         |
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
| **hello-interval**                        | | Set hello interval in seconds.                                    |
|                                           | | Default: 30 Range: 0 - 65535                                      |
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
| **lcp-padding**                           | | Add fixed padding to LCP packets sent from the LAC.               |
|                                           | | Default: 0 Range: 0 - 65535                                       |
+-------------------------------------------+---------------------------------------------------------------------+
| **calling-number**                        | | Optional Calling Number string sent in ICRQ (AVP 22).             |
+-------------------------------------------+---------------------------------------------------------------------+
| **called-number**                         | | Optional Called Number string sent in ICRQ (AVP 21).              |
+-------------------------------------------+---------------------------------------------------------------------+
