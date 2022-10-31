.. code-block:: json

    { "session-traffic": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `autostart`
     - Automatically start session traffic after the session is established
     - true
   * - `ipv4-pps`
     - Autogenerate bidirectional IPv4 traffic between a network interface and all sessions
     - 0 (disabled)
   * - `ipv4-label`
     - Send downstream IPv4 traffic with the specified MPLS label
     - 0 (unlabeled)
   * - `ipv4-address`
     - Overwrite network interface IPv4 address
     - network interface address
   * - `ipv6-pps`
     - Generate bidirectional IPv6 traffic between a network interface and all sessions
     - 0 (disabled)
   * - `ipv6-label`
     - Send downstream IPv6 traffic with the specified MPLS label
     - 0 (unlabeled)
   * - `ipv6-address`
     - Overwrite network interface IPv6 address
     - network interface address
   * - `ipv6pd-pps`
     - Generate bidirectional IPv6PD (delegated prefix) traffic between a network interface and all sessions
     - 0 (disabled)
