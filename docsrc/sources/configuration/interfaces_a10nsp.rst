.. code-block:: json

    { "interfaces": { "a10nsp": [] } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `interface`
     - Parent interface link name (e.g. eth0, ...)
     - 
   * - `qinq`
     - Set outer VLAN ethertype to QinQ (0x88a8)
     - false
   * - `mac`
     - Optional set gateway interface address manually
     - 