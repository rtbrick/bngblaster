.. code-block:: json

    { "ipoe": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `ipv4`
     - Enable/disable IPv4
     - true (enabled)
   * - `arp-timeout`
     - Initial ARP resolve timeout/retry interval in seconds
     - 1
   * - `arp-interval`
     - Periodic ARP interval in seconds (0 means disabled)
     - 300
   * - `ipv6`
     - Enable/disable IPv6
     - true (enabled)