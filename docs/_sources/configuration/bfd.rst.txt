.. code-block:: json

    { "bfd": [] }

BFD profiles define the timers and authentication of BFD sessions.
Static BFD sessions and routing protocols refer to a profile by its
``bfd-profile-id``. Sessions without profile use the defaults.

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **bfd-profile-id**                | | Mandatory BFD profile identifier.                                  |
|                                   | | Range: 1 - 65535                                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **tx-interval**                   | | Desired min TX interval in milliseconds.                           |
|                                   | | The TX interval is at least one second while the session           |
|                                   | | is not up (slow start).                                            |
|                                   | | Default: 1000 Range: 1 - 60000                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **rx-interval**                   | | Required min RX interval in milliseconds.                          |
|                                   | | Default: 1000 Range: 1 - 60000                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **multiplier**                    | | Detect multiplier.                                                 |
|                                   | | Default: 3 Range: 1 - 255                                          |
+-----------------------------------+----------------------------------------------------------------------+
| **passive**                       | | Passive role, packets are sent only after a packet                 |
|                                   | | from the peer is received.                                         |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **min-ttl**                       | | Minimum TTL or hop limit of received packets of                    |
|                                   | | multi-hop sessions. Single-hop sessions always                     |
|                                   | | require 255 (RFC 5881).                                            |
|                                   | | Default: 254 Range: 1 - 255                                        |
+-----------------------------------+----------------------------------------------------------------------+
| **authentication-type**           | | Authentication type (none, simple, keyed-md5,                      |
|                                   | | meticulous-keyed-md5, keyed-sha1 or meticulous-keyed-sha1).        |
|                                   | | Default: none                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **authentication-key-id**         | | Authentication key ID.                                             |
|                                   | | Default: 1 Range: 0 - 255                                          |
+-----------------------------------+----------------------------------------------------------------------+
| **authentication-key**            | | Authentication key (password), mandatory if                        |
|                                   | | authentication is enabled.                                         |
|                                   | | Length: simple and MD5 1 - 16, SHA1 1 - 20 characters              |
+-----------------------------------+----------------------------------------------------------------------+
