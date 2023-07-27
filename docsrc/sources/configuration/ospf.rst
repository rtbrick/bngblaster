.. code-block:: json

    { "ospf": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `instance-id`
     - OSPF instance identifier
     - 
   * - `version`
     - version
     - 2
   * - `overload`
     - OSPF overload
     - false
   * - `auth-key`
     - ISIS level 1 authentication key
     - 
   * - `auth-type`
     - ISIS level 1 authentication type (simple or md5)
     - disabled
   * - `hello-interval`
     - OSPF hello interval in seconds
     - 10
   * - `dead-interval`
     - OSPF dead interval in seconds
     - 40
   * - `lsa-retry-interval`
     - OSPF LSA retry interval in seconds
     - 5
   * - `hostname`
     - OSPF hostname
     - bngblaster
   * - `router-id`
     - OSPF router identifier
     - 10.10.10.10
   * - `router-priority`
     - OSPF router priority
     - 64
   * - `area`
     - OSPF area
     - 0.0.0.0
   * - `teardown-time`
     - OSPF teardown time in seconds
     - 5