.. code-block:: json

    { "interfaces": { "links": [] } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `interface`
     - Interface name (e.g. eth0, ...)
     - 
   * - `description`
     - Interface description
     - 
   * - `mac`
     - Overwrite the MAC address
     - Interface MAC address
   * - `io-mode`
     - Overwrite the IO mode
     - 
   * - `io-slots`
     - Overwrite the IO slots (ring size)
     - 
   * - `io-slots-tx`
     - Overwrite the TX IO slots (ring size)
     - 
   * - `io-slots-rx`
     - Overwrite the RX IO slots (ring size)
     - 
   * - `qdisc-bypass`
     - Overwrite the kernel's qdisc layer configuration
     - 
   * - `tx-interval`
     - Overwrite the TX polling interval in milliseconds
     - 
   * - `rx-interval`
     - Overwrite the RX polling interval in milliseconds
     - 
   * - `tx-threads`
     - Overwrite the number of TX threads per interface link
     - 
   * - `rx-threads`
     - Overwrite the number of RX threads per interface link
     - 
   * - `lag-interface`
     - Add interface link to LAG group
     - 
   * - `lacp-priority`
     - LACP interface priority
     - 32768