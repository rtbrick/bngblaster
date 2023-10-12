.. code-block:: json

    { "ospf": { "external": { "connections": [] } } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `router-id`
     - Mandatory remote router identifier
     - 
   * - `metric`
     - Optional interface metric
     - 10
   * - `local-ipv4-address`
     - Mandatory local IPv4 address (OSPFv2 only)
     - 
   * - `local-interface-id`
     - Local interface identifier (OSPFv3 only)
     - 1 (2,3,...)
   * - `remote-interface-id`
     - Remote interface identifier (OSPFv3 only)
     - `local-interface-id`
