.. code-block:: json

    { "dhcp": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `enable`
     - This option allows to enable or disable DHCP
     - false
   * - `broadcast`
     - DHCP broadcast flag
     - false
   * - `timeout`
     - DHCP timeout in seconds
     - 5
   * - `retry`
     - DHCP retry
     - 10
   * - `release-interval`
     - DHCP release interval
     - 1
   * - `release-retry`
     - DHCP release retry
     - 3
   * - `tos`
     - IPv4 TOS for all DHCP control traffic
     - 0
   * - `vlan-priority`
     - VLAN PBIT for all DHCP control traffic
     - 0
   * - `access-line`
     - Add access-line attributes like Agent-Remote/Circuit-Id
     - true