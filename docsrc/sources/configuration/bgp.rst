.. code-block:: json

    { "bgp": {} }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **network-interface**             | | BGP local interface (source interface).                            |
|                                   | | Default: `first network interface from configuration`              |
+-----------------------------------+----------------------------------------------------------------------+
| **local-address**                 | | BGP local IPv4/6 address (source address).                         |
|                                   | | Default: `network interface address`                               |
+-----------------------------------+----------------------------------------------------------------------+
| **local-as**                      | | BGP local AS.                                                      |
|                                   | | Default: 65000 Range: 0 - 4294967295                               |
+-----------------------------------+----------------------------------------------------------------------+
| **peer-address**                  | | Mandatory BGP peer IPv4/6 address.                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **peer-as**                       | | BGP peer AS.                                                       |
|                                   | | Default: `local AS` Range: 0 - 4294967295                          |
+-----------------------------------+----------------------------------------------------------------------+
| **hold-time**                     | | BGP hold-time in seconds.                                          |
|                                   | | Default: 90 Range: 0 - 65535                                       |
+-----------------------------------+----------------------------------------------------------------------+
| **id**                            | | BGP identifier.                                                    |
|                                   | | Default: 1.2.3.4                                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **tos**                           | | BGP IP TOS.                                                        |
|                                   | | Default: 0 Range: 0 - 255                                          |
+-----------------------------------+----------------------------------------------------------------------+
| **ttl**                           | | BGP IP TTL.                                                        |
|                                   | | Default: 255 Range: 0 - 255                                        |
+-----------------------------------+----------------------------------------------------------------------+
| **reconnect**                     | | Reconnect BGP session automatically.                               |
|                                   | | Default: true                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **start-traffic**                 | | Start global traffic after RAW update finished.                    |
|                                   | | If enabled, the control command **traffic-start** is automatically |
|                                   | | executed as soon as the BGP RAW update has finished.               |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **teardown-time**                 | | BGP teardown time in seconds.                                      |
|                                   | | Default: 5 Range: 0 - 65535                                        |
+-----------------------------------+----------------------------------------------------------------------+
| **raw-update-file**               | | BGP RAW update file.                                               |
+-----------------------------------+----------------------------------------------------------------------+
| **family**                        | | BGP families to be send in open message.                           |
|                                   | | Default: ipv4/6-unicast, ipv4/6-labeled-unicast                    |
|                                   | | Values:                                                            |
|                                   | | ipv4-unicast, ipv6-unicast,                                        |
|                                   | | ipv4-multicast, ipv6-multicast,                                    |
|                                   | | ipv4-labeled-unicast, ipv6-labeled-unicast,                        |
|                                   | | ipv4-vpn-unicast, ipv6-vpn-unicast,                                |
|                                   | | ipv4-vpn-multicast, ipv6-vpn-multicast,                            |
|                                   | | ipv4-flow, ipv6-flow, evpn                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **extended-nexthop**              | | BGP extended-nexthop families to be send in open message.          |
|                                   | | Default: None                                                      |
|                                   | | Values: ipv4-unicast, ipv4-vpn-unicast                             |
+-----------------------------------+----------------------------------------------------------------------+