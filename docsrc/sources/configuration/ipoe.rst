.. code-block:: json

    { "ipoe": {} }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **ipv6**                          | | Enable/disable IPv6.                                               |
|                                   | | Default: true (enabled)                                            |
+-----------------------------------+----------------------------------------------------------------------+
| **ipv4**                          | | Enable/disable IPv4.                                               |
|                                   | | Default: true (enabled)                                            |
+-----------------------------------+----------------------------------------------------------------------+
| **arp-timeout**                   | | Initial ARP timeout/retry interval in seconds.                     |
|                                   | | Default: 1                                                         |
+-----------------------------------+----------------------------------------------------------------------+
| **arp-interval**                  | | Periodic ARP interval in seconds (0 means disabled).               |
|                                   | | Default: 300                                                       |
+-----------------------------------+----------------------------------------------------------------------+
| **vlan-priority**                 | | VLAN PBIT for generic IPoE control traffic.                        |
|                                   | | Used for ARP and ICMPv6 ND/RS/NS control traffic.                  |
|                                   | | Default master value for IPoE traffic (including DHCP and DHCPv6)  |
|                                   | | unless overridden by protocol-specific settings.                    |
|                                   | | Default: 0                                                         |
+-----------------------------------+----------------------------------------------------------------------+
