.. code-block:: json

    { "ldp": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `instance-id`
     - LDP instance identifier
     - 
   * - `keepalive-time`
     - LDP keepalive time in seconds
     - 15
   * - `hold-time`
     - LDP hold time in seconds
     - 30
   * - `hostname`
     - LDP hostname
     - bngblaster
   * - `lsr-id`
     - LDP LSR identifier
     - 10.10.10.10
   * - `teardown-time`
     - LDP teardown time in seconds
     - 5
   * - `ipv4-transport-address`
     - LDP transport address
     - `lsr-id`
   * - `raw-update-file`
     - LDP RAW update file
     - 