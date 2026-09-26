.. code-block:: json

    { "bgp": {} }

Every configured BGP peer both actively connects and passively listens on
TCP port 179, matching real router behavior. If the peer also connects
towards BNG Blaster at the same time, the resulting connection collision is
resolved automatically per :rfc:`4271#section-6.8` by comparing BGP
Identifiers, with the losing TCP connection closed via a NOTIFICATION
(Cease, Connection Collision Resolution).

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
| **tcp-ao-key**                    | | TCP authentication key. TCP-AO (RFC 5925) master key, or the       |
|                                   | | legacy TCP MD5 (RFC 2385) secret if **tcp-ao-algorithm** is md5.   |
|                                   | | A recommended minimum length applies per **tcp-ao-algorithm**      |
|                                   | | (32 characters for hmac-sha-256-128, 20 for hmac-sha-1-96, 16 for  |
|                                   | | aes-128-cmac-96, none for md5) but is not enforced, so shorter     |
|                                   | | keys can be used to test interop with peers that accept them.      |
+-----------------------------------+----------------------------------------------------------------------+
| **tcp-ao-algorithm**              | | TCP authentication algorithm. **tcp-ao-key** is ignored unless     |
|                                   | | this is also set to a value other than none, so TCP                |
|                                   | | authentication can be toggled on/off by changing only this         |
|                                   | | attribute, without removing **tcp-ao-key** from the config.        |
|                                   | | Default: none (disabled)                                           |
|                                   | | Values: none, hmac-sha-1-96, hmac-sha-256-128, aes-128-cmac-96,    |
|                                   | | md5                                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **tcp-ao-key-id**                 | | TCP-AO KeyID (SendID) sent with all segments. Mandatory for TCP-AO |
|                                   | | (tcp-ao-key and tcp-ao-algorithm other than none or md5).          |
|                                   | | Not supported for md5 (RFC 2385 has no KeyID).                     |
|                                   | | Range: 0 - 255                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **tcp-ao-rnext-key-id**           | | TCP-AO RNextKeyID, which is also the KeyID (RecvID) expected in    |
|                                   | | received segments. Not supported for md5.                          |
|                                   | | Default: tcp-ao-key-id Range: 0 - 255                              |
+-----------------------------------+----------------------------------------------------------------------+
| **reconnect**                     | | Reconnect BGP session automatically.                               |
|                                   | | Default: true                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **start-traffic**                 | | Start global traffic after RAW update finished.                    |
|                                   | | If enabled, the control command **traffic-start** is automatically |
|                                   | | executed as soon as the BGP RAW update has finished.               |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **learn-routes**                  | | Store received IPv4/IPv6 unicast, labeled unicast and EVPN routes. |
|                                   | | If disabled, received updates are not parsed.                      |
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