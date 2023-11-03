.. code-block:: json

    { "ppp": { "ipcp": {} } }

+--------------------------+------------------------------------------------------------------+
| Attribute                | Description                                                      |
+==========================+==================================================================+
| **enable**               | | This option allows to enable or disable the IPCP protocol      |
|                          | | Default: true                                                  |
+--------------------------+------------------------------------------------------------------+
| **request-ip**           | | Include IP-Address with 0.0.0.0 in the initial IPCP            |
|                          | | configuration request.                                         |
|                          | | Default: true                                                  |
+--------------------------+------------------------------------------------------------------+
| **request-dns1**         | | Request Primary DNS Server Address (option 129).               |
|                          | | Default: true                                                  |
+--------------------------+------------------------------------------------------------------+
| **request-dns2**         | | Request Secondary DNS Server Address (option 131).             |
|                          | | Default: true                                                  |
+--------------------------+------------------------------------------------------------------+
| **conf-request-timeout** | | IPCP configuration request timeout in seconds                  |
|                          | | Default: 5                                                     |
+--------------------------+------------------------------------------------------------------+
| **conf-request-retry**   | | IPCP configuration request max retry.                          |
|                          | | Default: 10                                                    |
+--------------------------+------------------------------------------------------------------+