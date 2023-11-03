.. code-block:: json

    { "ppp": { "authentication": {} } }

+----------------+------------------------------------------------------------------+
| Attribute      | Description                                                      |
+================+==================================================================+
| **username**   | | Username.                                                      |
|                | | Default: user{session-global}@rtbrick.com                      |
+----------------+------------------------------------------------------------------+
| **password**   | | Password.                                                      |
|                | | Default: test                                                  |
+----------------+------------------------------------------------------------------+
| **timeout**    | | Authentication request timeout in seconds.                     |
|                | | Default: 5                                                     |
+----------------+------------------------------------------------------------------+
| **retry**      | | Authentication request max retry.                              |
|                | | Default: 30                                                    |
+----------------+------------------------------------------------------------------+
| **protocol**   | | This value can be set to PAP or CHAP to reject                 |
|                | | the other protocol.                                            |
|                | | Default: `allow both PAP and CHAP`                             |
+----------------+------------------------------------------------------------------+
