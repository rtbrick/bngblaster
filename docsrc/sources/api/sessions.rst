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
   * - `terminate`
     - Terminate session
     - 
     - `session-id`, `reconnect-delay`

The argument ``reconnect-delay`` is only applicable in combination with ``session-id`` 
and reconnect enabled in configuration. This argument allows to delay the session 
reconnect by the defined amount of seconds. 
