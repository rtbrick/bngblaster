.. code-block:: json

    { "icmp-client": {} }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **icmp-client-group-id**          | | ICMP client identifier.                                            |
|                                   | | This identifier is used to create ICMP clients for sessions.       |
|                                   | | Range: 1 - 65535                                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **network-interface**             | | ICMP client network-interface.                                     |
|                                   | | Use **network-interface** instead of **icmp-client-group-id** when |
|                                   | | creating ICMP clients on a network interface. These two options    |
|                                   | | are mutually exclusive, but at least one of them is required.      |
+-----------------------------------+----------------------------------------------------------------------+
| **destination-address**           | | Mandatory destination IPv4 address.                                |
+-----------------------------------+----------------------------------------------------------------------+
| **source-address**                | | Optional source IPv4 address.                                      |
|                                   | | Default: session/interface address                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **size**                          | | ICMP data size.                                                    |
|                                   | | Default: 8 Range: 0 - 65507                                        |
+-----------------------------------+----------------------------------------------------------------------+
| **interval**                      | | ICMP send interval in seconds.                                     |
|                                   | | Default: 1.0                                                       |
+-----------------------------------+----------------------------------------------------------------------+
| **count**                         | | ICMP requests to send before stopping.                             |
|                                   | | Default: 0 (infinity)                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **results**                       | | ICMP request to track results for.                                 |
|                                   | | Default: 3 or **count** if set                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **ttl**                           | | IPv4 header TTL value.                                             |
|                                   | | Default: 64                                                        |
+-----------------------------------+----------------------------------------------------------------------+
| **tos**                           | | IPv4 header TOS value.                                             |
|                                   | | Default: 0                                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **df**                            | | IPv4 header dont-fragement (DF) bit.                               |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **autostart**                     | | Autostart ICMP client after session reconnects. This applies only  |
|                                   | | to ICMP clients that are bound to access sessions.                 |
|                                   | | Default: true                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **start-delay**                   | | ICMP client start delay in seconds.                                |
|                                   | | Default: 0                                                         |
+-----------------------------------+----------------------------------------------------------------------+
