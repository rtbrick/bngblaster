.. code-block:: json

    { "igmp": {} }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **autostart**                     | | Automatically join after the session is established.               |
|                                   | | Default: true                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **start-delay**                   | | Delay between session established and initial IGMP join in seconds.|
|                                   | | Default: 1                                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **version**                       | | IGMP protocol version (1, 2, or 3).                                |
|                                   | | Default: 3                                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **combined-leave-join**           | | Per default, join and leave requests are sent using dedicated      |
|                                   | | reports. This option allows the combination of leave and join      |
|                                   | | records within a single IGMPv3 report using multiple group records.|
|                                   | | This option applies to the IGMP version 3 only!                    |
|                                   | | Default: true                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **group**                         | | Multicast group base address (e.g. 239.0.0.1).                     |
|                                   | | If group is set to 293.0.0.1 with group-iter of 0.0.0.2,           |
|                                   | | source 1.1.1.1 and group-count 3, the result are the following     |
|                                   | | three groups (S.G):                                                |
|                                   | | `1.1.1.1,239.0.0.1, 1.1.1.1,239.0.0.3, 1.1.1.1,239.0.0.5`          |
|                                   | | Default: 0.0.0.0 (disabled)                                        |
+-----------------------------------+----------------------------------------------------------------------+
| **group-iter**                    | | Multicast group iterator.                                          |
|                                   | | Default: 0.0.0.1                                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **group-count**                   | | Multicast group count.                                             |
|                                   | | Default: 1                                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **source**                        | | Multicast source address (e.g. 1.1.1.1).                           |
|                                   | | Default: 0.0.0.0 (ASM)                                             |
+-----------------------------------+----------------------------------------------------------------------+
| **zapping-interval**              | | IGMP channel zapping interval in seconds.                          |
|                                   | | Default: 0 (disabled)                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **zapping-count**                 | | Define the number of channel changes before starting               |
|                                   | | the view duration.                                                 |
|                                   | | Default: 0 (disabled)                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **zapping-wait**                  | | Wait for multicast traffic before zapping to the next channel.     |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **view-duration**                 | | Define the view duration in seconds.                               |
|                                   | | Default: 0 (disabled)                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **max-join-delay**                | | Maximum join delay in milliseconds.                                |
|                                   | | If configured, the final report includes how often                 |
|                                   | | the measured join delay is above this threshold.                   |
|                                   | | Default: 0 (disabled)                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **send-multicast-traffic**        | | If enabled, the BNG Blaster generates multicast traffic on the     |
|                                   | | network interface based on the specified  group and source         |
|                                   | | attributes mentioned before. This traffic includes some special    |
|                                   | | signatures for faster processing and more detailed analysis.       |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **multicast-traffic-length**      | | Multicast traffic IP length.                                       |
|                                   | | Only applicable with **send-multicast-traffic** enabled!           |
|                                   | | Default: 76                                                        |
+-----------------------------------+----------------------------------------------------------------------+
| **multicast-traffic-tos**         | | Multicast traffic TOS priority.                                    |
|                                   | | Only applicable with **send-multicast-traffic** enabled!           |
|                                   | | Default: 0                                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **multicast-traffic-pps**         | | Multicast traffic PPS (packets-per-second) per group.              |
|                                   | | Only applicable with **send-multicast-traffic** enabled!           |
|                                   | | Default: 1000                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **network-interface**             | | Multicast traffic source interface.                                |
|                                   | | Only applicable with **send-multicast-traffic** enabled!           |
|                                   | | Default: `first network interface from configuration`              |
+-----------------------------------+----------------------------------------------------------------------+
