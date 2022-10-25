.. code-block:: json

    { "igmp": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `autostart`
     - Automatically join after session is established
     - true
   * - `version`
     - IGMP protocol version (1, 2 or 3)
     - 3
   * - `combined-leave-join`
     - Combine leave and join records within a single IGMPv3 report
     - true
   * - `start-delay`
     - Delay between session established and initial IGMP join in seconds
     - 1
   * - `group`
     - Multicast group base address (e.g. 239.0.0.1)
     - 0.0.0.0 (disabled)
   * - `group-iter`
     - Multicast group iterator
     - 0.0.0.1
   * - `group-count`
     - Multicast group count
     - 1
   * - `source`
     - Multicast source address (e.g. 1.1.1.1)
     - 0.0.0.0 (ASM)
   * - `zapping-interval`
     - IGMP channel zapping interval in seconds
     - 0 (disabled)
   * - `zapping-count`
     - Define the amount of channel changes before starting view duration
     - 0 (disabled)
   * - `view-duration`
     - Define the view duration in seconds
     - 0 (disabled)
   * - `send-multicast-traffic`
     - Generate multicast traffic
     - false
   * - `multicast-traffic-autostart`
     - Automatically start multicast traffic
     - true
   * - `multicast-traffic-length`
     - Multicast traffic IP length
     - 76
   * - `multicast-traffic-tos`
     - Multicast traffic TOS priority
     - 0
   * - `multicast-traffic-pps`
     - Multicast traffic PPS per group
     - 1000
   * - `network-interface`
     - Multicast traffic source interface
     - 
   * - `max-join-delay`
     - Maximum join delay in milliseconds
     - 0 (disabled)

Per default join and leave requests are send using dedicated reports. 
The option ``combined-leave-join`` allows the combination of leave and 
join records within a single IGMPv3 report using multiple group records.
This option is applicable to IGMP version 3 only!

If ``send-multicast-traffic`` is true, the BNG Blaster generates multicast 
traffic on the network interface based on the specified group and source 
attributes mentioned before. This traffic includes some special signatures 
for faster processing and more detailed analysis. This traffic starts 
automatically, which can be suppressed by setting ``multicast-traffic-autostart``
to false. The length, TOS and packets per seconds (PPS) can be controlled
with the corresponding options. 

If group is set to 293.0.0.1 with group-iter of 0.0.0.2, source 1.1.1.1 
and group-count 3 the result are the following three groups (S.G) 
1.1.1.1,239.0.0.1, 1.1.1.1,239.0.0.3 and 1.1.1.1,239.0.0.5.

If ``max-join-delay`` is configured, the final report includes how often 
the measured join delay is above the configured threshold here. 
