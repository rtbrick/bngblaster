.. code-block:: json

    { "interfaces": { "lag": [] } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `interface`
     - Interface name (e.g. lag0, ...)
     - 
   * - `lacp`
     - De-/activate LACP
     - false
   * - `lacp-timeout-short`
     - De-/activate LACP short timeout (3x1s)
     - false (3x30s)
   * - `lacp-system-priority`
     - LACP system priority
     - 32768
   * - `lacp-system-id`
     - LACP system identifier
     - 02:ff:ff:ff:ff:00
   * - `lacp-max-active-links`
     - Limit the maximum number of active links
     - 255
   * - `mac`
     - LAG interface MAC address
     - 02:ff:ff:ff:ff:<id>
