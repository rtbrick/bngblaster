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
   * - `ipv6-pps`
     - Generate bidirectional IPv6 traffic between network interface and all session framed IPv6 addresses
     - 0 (disabled)
   * - `ipv6pd-pps`
     - Generate bidirectional Ipv6 traffic between network interface and all session delegated IPv6 addresses
     - 0 (disabled)