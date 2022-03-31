.. code-block:: json

    { "pppoe": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `session-time`
     - Max PPPoE session time in seconds
     - 0 (infinity)
   * - `reconnect`
     - Automatically reconnect sessions if terminated
     - false
   * - `discovery-timeout`
     - PPPoE discovery (PADI and PADR) timeout in seconds
     - 5
   * - `discovery-retry`
     - PPPoE discovery (PADI and PADR) max retry
     - 10
   * - `service-name`
     - PPPoE discovery service name
     - 
   * - `host-uniq`
     - PPPoE discovery host-uniq
     - false
   * - `vlan-priority`
     - VLAN PBIT for all PPPoE/PPP control traffic
     - 0
