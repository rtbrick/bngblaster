.. code-block:: json

    { "ppp": {} }

+-------------+------------------------------------------------------------------+
| Attribute   | Description                                                      |
+=============+==================================================================+
| **mru**     | | Define the maximum receive unit proposed via PPP.              |
|             | | For PPPoE, a peer MRU above 1492, or above the PPP-Max-Payload |
|             | | echoed by the server (RFC4638), is rejected with LCP           |
|             | | configure-nak suggesting the maximum.                          |
|             | | Default: 1492 Range: 0 - 65535                                 |
+-------------+------------------------------------------------------------------+
