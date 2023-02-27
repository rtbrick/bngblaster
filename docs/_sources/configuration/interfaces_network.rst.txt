.. code-block:: json

    { "interfaces": { "network": [] } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `interface`
     - Parent interface link name (e.g. eth0, ...)
     - 
   * - `address`
     - Local network interface IPv4 address
     - 
   * - `gateway`
     - Gateway network interface IPv4 address
     - 
   * - `address-ipv6`
     - Local network interface IPv6 address (implicitly /64)
     - 
   * - `gateway-ipv6`
     - Gateway network interface IPv6 address (implicitly /64)
     - 
   * - `ipv6-router-advertisement`
     - Disable IPv6 router advertisements
     - true
   * - `vlan`
     - Network interface VLAN
     - 0 (untagged)
   * - `gateway-mac`
     - Optional set gateway MAC address manually
     - 
   * - `gateway-resolve-wait`
     - Sessions will not start until gateways are resolved
     - true
   * - `isis-instance-id`
     - Assign the interface to ISIS instance
     - 
   * - `isis-level`
     - ISIS interface level
     - 3
   * - `isis-p2p`
     - ISIS P2P interface
     - true
   * - `isis-l1-metric`
     - ISIS level 1 interface metric
     - 10
   * - `isis-l2-metric`
     - ISIS level 2 interface metric
     - 10