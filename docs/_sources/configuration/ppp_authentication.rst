.. code-block:: json

    { "ppp": { "authentication": {} } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `username`
     - Username
     - user{session-global}@rtbrick.com
   * - `password`
     - Password
     - test
   * - `timeout`
     - Authentication request timeout in seconds
     - 5
   * - `retry`
     - Authentication request max retry
     - 30
   * - `protocol`
     - This value can be set to `PAP` or `CHAP` to reject the other protocol
     - allow PAP and CHAP