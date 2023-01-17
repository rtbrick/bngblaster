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
     - LDP session keepalive time in seconds
     - 15
   * - `hold-time`
     - LDP hello hold time in seconds
     - 15
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

The `keepalive-time` defines the local LDP session keepalive 
timeout. Each LDP peer must calculate the effective keepalive
timeout by using the smaller of its locally defined and received
timeout in the PDU. The value chosen indicates the maximum number
of seconds that may elapse between the receipt of successive PDUs
from the LDP peer on the session TCP connection. The keepalive
timeout is reset each time a PDU arrives. The BNG Blaster will 
send keepalive messages at an interval calculated by using the
effective keepalive time divided by 3. Assuming an effective
keepalive time of 15 seconds results in a keepalive interval
of 5 seconds. 