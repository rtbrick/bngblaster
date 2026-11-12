.. code-block:: json

    { "ldp": { "targeted-neighbors": [] } }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **address**                       | | Mandatory targeted neighbor IPv4 or IPv6 address.                  |
|                                   | | IPv6 requires the LDP ``ipv6-transport-address``.                  |
+-----------------------------------+----------------------------------------------------------------------+
| **source-address**                | | Source address of the targeted hellos, of the same address         |
|                                   | | family as ``address``.                                             |
|                                   | | Default: IPv4 or IPv6 transport address                            |
+-----------------------------------+----------------------------------------------------------------------+
| **network-interface**             | | Network interface used for the targeted hellos and the session.    |
|                                   | | Default: first network interface                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **bfd-profile-id**                | | Enable multi-hop BFD for the session of this targeted              |
|                                   | | neighbor with this BFD profile.                                    |
+-----------------------------------+----------------------------------------------------------------------+
