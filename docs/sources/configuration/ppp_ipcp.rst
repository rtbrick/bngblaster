.. code-block:: json

    { "ppp": { "ipcp": {} } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `enable`
     - This option allows to enable or disable the IPCP protocol
     - true
   * - `request-ip`
     - Include IP-Address with 0.0.0.0 in initial LCP configuration request
     - true
   * - `request-dns1`
     - Request Primary DNS Server Address (option 129)
     - true
   * - `request-dns2`
     - Request Secondary DNS Server Address (option 131)
     - true
   * - `conf-request-timeout`
     - IPCP configuration request timeout in seconds
     - 5
   * - `conf-request-retry`
     - IPCP configuration request max retry
     - 10