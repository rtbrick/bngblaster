.. list-table::
   :header-rows: 1

   * - Attribute
     - Description
     - Mandatory Arguments
     - Optional Arguments
   * - `session-info`
     - Display session information
     - 
     - `session-id`
   * - `session-counters`
     - Display session counters
     - 
     - 
   * - `sessions-pending`
     - List all sessions not established
     - 
     - 
   * - `session-traffic`
     - Display session traffic statistics
     - 
     - 
   * - `session-traffic-start`
     - Enable/start session traffic
     - 
     - `session-id`
   * - `session-traffic-stop`
     - Disable/stop session traffic
     - 
     - `session-id`
   * - `session-streams`
     - Display session streams
     - `session-id`
     - 
   * - `session-start`
     - Start session manually
     - 
     - `session-id`, `session-group-id`
   * - `session-stop`
     - Stop sessions manually
     - 
     - `session-id`, `session-group-id`, `reconnect-delay`
   * - `session-restart`
     - Restart sessions manually
     - 
     - `session-id`, `session-group-id`, `reconnect-delay`

The argument ``reconnect-delay`` is only applicable in combination with
session reconnect enabled in the configuration. This argument delays the 
session reconnect by the defined amount of seconds. 