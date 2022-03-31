.. code-block:: json

    { "ppp": { "lcp": {} } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `conf-request-timeout`
     - LCP configuration request timeout in seconds
     - 5
   * - `conf-request-retry`
     - LCP configuration request max retry
     - 10
   * - `keepalive-interval`
     - LCP echo request interval in seconds (0 means disabled)
     - 30
   * - `keepalive-retry`
     - PPP LCP echo request max retry
     - 3
   * - `start-delay`
     - PPP LCP initial request delay in milliseconds
     - 0
   * - `ignore-vendor-specific`
     - Ignore LCP vendor specific requests
     - false
   * - `connection-status-message`
     - Accept LCP connection status messages
     - false