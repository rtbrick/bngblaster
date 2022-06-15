.. list-table::
   :header-rows: 1

   * - Attribute
     - Description
     - Mandatory Arguments
     - Optional Arguments
   * - `igmp-join`
     - Join group
     - `session-id`, `group`
     - `source1`, `source2`, `source3`
   * - `igmp-join-iter`
     - Join multiple groups over all sessions
     - `group`
     - `group-iter`, `group-count`, `source1`, `source2`, `source3`
   * - `igmp-leave`
     - Leave group
     - `session-id`, `group`
     - 
   * - `igmp-leave-all`
     - Leave all groups from all sessions
     -
     - 
   * - `igmp-info`
     - Display group information
     - `session-id`
     - 
   * - `zapping-start`
     - Start IGMP zapping test
     - 
     - 
   * - `zapping-stop`
     - Stop IGMP zapping test
     - 
     - 
   * - `zapping-stats`
     - Return IGMP zapping stats
     - 
     - `reset`