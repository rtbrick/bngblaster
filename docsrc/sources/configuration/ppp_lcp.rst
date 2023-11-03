.. code-block:: json

    { "ppp": { "lcp": {} } }

+-------------------------------+------------------------------------------------------------------+
| Attribute                     | Description                                                      |
+===============================+==================================================================+
| **conf-request-timeout**      | | LCP configuration request timeout in seconds.                  |
|                               | | Default: 5                                                     |
+-------------------------------+------------------------------------------------------------------+
| **conf-request-retry**        | | LCP configuration request max retry.                           |
|                               | | Default: 10                                                    |
+-------------------------------+------------------------------------------------------------------+
| **keepalive-interval**        | | LCP echo request interval in seconds (0 means disabled).       |
|                               | | Default: 30                                                    |
+-------------------------------+------------------------------------------------------------------+
| **keepalive-retry**           | | PPP LCP echo request max retry.                                |
|                               | | Default: 3                                                     |
+-------------------------------+------------------------------------------------------------------+
| **start-delay**               | | PPP LCP initial request delay in milliseconds.                 |
|                               | | Default: 0                                                     |
+-------------------------------+------------------------------------------------------------------+
| **ignore-vendor-specific**    | | Ignore LCP vendor-specific requests.                           |
|                               | | Default: false                                                 |
+-------------------------------+------------------------------------------------------------------+
| **connection-status-message** | | Accept LCP connection status messages.                         |
|                               | | Default: false                                                 |
+-------------------------------+------------------------------------------------------------------+
