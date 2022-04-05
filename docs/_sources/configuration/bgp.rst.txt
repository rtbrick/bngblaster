.. code-block:: json

    { "bgp": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `network-interface`
     - BGP local interface (source-interface)
     - first network interface
   * - `local-ipv4-address`
     - BGP local IPv4 address (source-address)
     - network interface address
   * - `local-as`
     - BGP local AS
     - 65000
   * - `peer-ipv4-address`
     - BGP peer address
     - 
   * - `peer-as`
     - BGP peer AS
     - local AS
   * - `holdtime`
     - BGP holdtime in seconds
     - 90
   * - `id`
     - BGP identifier
     - 1.2.3.4
   * - `reconnect`
     - BGP reconnect
     - true
   * - `start-traffic`
     - BGP start global traffic after RAW update
     - false
   * - `teardown-time`
     - BGP teardown time in seconds
     - 5
   * - `raw-update-file`
     - BGP RAW update file
     - 