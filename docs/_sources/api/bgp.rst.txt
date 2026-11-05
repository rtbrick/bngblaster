+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **bgp-sessions**                  | | Display all matching BGP sessions.                                 |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``local-ipv4-address``                                             |
|                                   | | ``peer-ipv4-address``                                              |
|                                   | | ``local-ipv6-address``                                             |
|                                   | | ``peer-ipv6-address``                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **bgp-disconnect**                | | Disconnect all matching BGP sessions.                              |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``local-ipv4-address``                                             |
|                                   | | ``peer-ipv4-address``                                              |
|                                   | | ``local-ipv6-address``                                             |
|                                   | | ``peer-ipv6-address``                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **bgp-teardown**                  | | Teardown BGP.                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **bgp-raw-update-list**           | | List all loaded BGP RAW update files.                              |
+-----------------------------------+----------------------------------------------------------------------+
| **bgp-raw-update**                | | Update all matching BGP sessions.                                  |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``file`` Mandatory path to BGP RAW update file.                    |
|                                   | | ``local-ipv4-address``                                             |
|                                   | | ``peer-ipv4-address``                                              |
|                                   | | ``local-ipv6-address``                                             |
|                                   | | ``peer-ipv6-address``                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **bgp-routes**                    | | Display learned IPv4/IPv6 routes of all matching BGP sessions      |
|                                   | | with learn-routes enabled.                                         |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``local-ipv4-address``                                             |
|                                   | | ``peer-ipv4-address``                                              |
|                                   | | ``local-ipv6-address``                                             |
|                                   | | ``peer-ipv6-address``                                              |
|                                   | | ``family`` Filter by family (ipv4-unicast, ipv6-unicast,           |
|                                   | | ipv4-labeled-unicast, ipv6-labeled-unicast).                       |
|                                   | | ``prefix`` Filter by IPv4 or IPv6 prefix.                          |
|                                   | | ``match`` Prefix match (exact or longer).                          |
|                                   | | Default: exact                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **bgp-routes-stats**              | | Display learned route counters of all matching BGP sessions.       |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``local-ipv4-address``                                             |
|                                   | | ``peer-ipv4-address``                                              |
|                                   | | ``local-ipv6-address``                                             |
|                                   | | ``peer-ipv6-address``                                              |
+-----------------------------------+----------------------------------------------------------------------+
| **bgp-evpn-routes**               | | Display learned BGP EVPN routes of all matching BGP sessions       |
|                                   | | with learn-routes enabled.                                         |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``local-ipv4-address``                                             |
|                                   | | ``peer-ipv4-address``                                              |
|                                   | | ``local-ipv6-address``                                             |
|                                   | | ``peer-ipv6-address``                                              |
|                                   | | ``route-type`` Filter by route type (1-5).                         |
|                                   | | ``rd`` Filter by route distinguisher.                              |
+-----------------------------------+----------------------------------------------------------------------+
| **bgp-l2vpn-routes**              | | Display learned BGP L2VPN label blocks (RFC 6624) of all matching  |
|                                   | | BGP sessions with learn-routes enabled.                            |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``local-ipv4-address``                                             |
|                                   | | ``peer-ipv4-address``                                              |
|                                   | | ``local-ipv6-address``                                             |
|                                   | | ``peer-ipv6-address``                                              |
|                                   | | ``ce-id`` Filter by CE ID.                                         |
|                                   | | ``rd`` Filter by route distinguisher.                              |
+-----------------------------------+----------------------------------------------------------------------+

