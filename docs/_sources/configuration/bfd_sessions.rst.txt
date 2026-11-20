.. code-block:: json

    { "bfd-sessions": [] }

Static BFD sessions are started with BNG Blaster and kept until the end
of the test, independent of routing protocols.

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **network-interface**             | | Network interface of the session.                                  |
|                                   | | Mandatory for single-hop sessions.                                 |
|                                   | | Default: first network interface (multi-hop)                       |
+-----------------------------------+----------------------------------------------------------------------+
| **peer-ipv4-address**             | | Peer IPv4 address.                                                 |
|                                   | | Either peer-ipv4-address or peer-ipv6-address is mandatory.        |
+-----------------------------------+----------------------------------------------------------------------+
| **local-ipv4-address**            | | Local IPv4 address.                                                |
|                                   | | Default: network interface address                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **peer-ipv6-address**             | | Peer IPv6 address (global or link-local).                          |
+-----------------------------------+----------------------------------------------------------------------+
| **local-ipv6-address**            | | Local IPv6 address.                                                |
|                                   | | Default: network interface link-local address for                  |
|                                   | | link-local peers, otherwise the global address                     |
+-----------------------------------+----------------------------------------------------------------------+
| **bfd-profile-id**                | | BFD profile.                                                       |
|                                   | | Default: built-in defaults (1000 ms, multiplier 3)                 |
+-----------------------------------+----------------------------------------------------------------------+
| **multihop**                      | | Multi-hop session (RFC 5883, UDP port 4784).                       |
|                                   | | Default: false (single-hop, RFC 5881, UDP port 3784)               |
+-----------------------------------+----------------------------------------------------------------------+
| **name**                          | | Optional session name shown in the session output.                 |
+-----------------------------------+----------------------------------------------------------------------+
