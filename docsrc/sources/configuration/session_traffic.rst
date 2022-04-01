.. code-block:: json

    { "session-traffic": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `autostart`
     - Automatically start session traffic after session is established
     - true
   * - `ipv4-pps`
     - Generate bidirectional IPv4 traffic between network interface and all session framed IPv4 addresses
     - 0 (disabled)
   * - `ipv4-label`
     - Send traffic from network interface with the specified MPLS label
     - 0 (unlabelled)
   * - `ipv4-address`
     - Send traffic from network interface with the specified address
     - network interface address
   * - `ipv6-pps`
     - Generate bidirectional IPv6 traffic between network interface and all session framed IPv6 addresses
     - 0 (disabled)
   * - `ipv6-label`
     - Send traffic from network interface with the specified MPLS label
     - 0 (unlabelled)
   * - `ipv6-address`
     - Send traffic from network interface with the specified address
     - network interface address
   * - `ipv6pd-pps`
     - Generate bidirectional IPv6 traffic between network interface and all session delegated IPv6 addresses
     - 0 (disabled)
