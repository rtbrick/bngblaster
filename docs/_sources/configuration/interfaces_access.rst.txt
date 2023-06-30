.. code-block:: json

    { "interfaces": { "access": [] } }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `interface`
     - Parent interface link name (e.g. eth0, ...)
     - 
   * - `network-interface`
     - Select the corresponding network interface for this session
     - 
   * - `a10nsp-interface`
     - Select the corresponding A10NSP interface for this session
     - 
   * - `type`
     - Set access type (`pppoe` or `ipoe`)
     - pppoe
   * - `vlan-mode`
     - Set VLAN mode `1:1` or `N:1`
     - 1:1
   * - `qinq`
     - Set outer VLAN ethertype to QinQ (0x88a8)
     - false
   * - `outer-vlan-min`
     - Outer VLAN minimum value
     - 0 (untagged)
   * - `outer-vlan-max`
     - Outer VLAN maximum value
     - 0 (untagged)
   * - `outer-vlan-step`
     - Outer VLAN step (iterator)
     - 1
   * - `outer-vlan`
     - Set outer-vlan-min/max equally
     - 
   * - `inner-vlan-min`
     - Inner VLAN minimum value
     - 0 (untagged)
   * - `inner-vlan-max`
     - Inner VLAN maximum value
     - 0 (untagged)
   * - `inner-vlan-step`
     - Inner VLAN step (iterator)
     - 1
   * - `inner-vlan`
     - Set inner-vlan-min/max equally
     - 
   * - `third-vlan`
     - Add a fixed third VLAN (most inner VLAN)
     - 0 (untagged)
   * - `address`
     - Static IPv4 base address (IPoE only)
     - 
   * - `ppp-mru`
     - Overwrite PPP MRU (PPPoE only)
     - 
   * - `address-iter`
     - Static IPv4 base address iterator (IPoE only)
     - 
   * - `gateway`
     - Static IPv4 gateway address (IPoE only)
     - 
   * - `gateway-iter`
     - Static IPv4 gateway address iterator (IPoE only)
     - 
   * - `username`
     - Overwrite the username from the authentication section
     - 
   * - `password`
     - Overwrite the password from the authentication section
     - 
   * - `authentication-protocol`
     - Overwrite the username from the authentication section
     - 
   * - `agent-circuit-id`
     - Overwrite the agent-circuit-id from the access-line section
     - 
   * - `agent-remote-id`
     - Overwrite the agent-remote-id from the access-line section
     - 
   * - `access-aggregation-circuit-id`
     - Overwrite the access-aggregation-circuit-id from the access-line section
     - 
   * - `rate-up`
     - Overwrite the rate-up from the access-line section
     - 
   * - `rate-down`
     - Overwrite the rate-down from the access-line section
     - 
   * - `dsl-type`
     - Overwrite the dsl-type from the access-line section
     - 
   * - `ipcp`
     - De-/activate PPP IPCP
     - 
   * - `ip6cp`
     - De-/activate PPP IP6CP
     - 
   * - `ipv4`
     - De-/activate IPv4
     - 
   * - `ipv6`
     - De-/activate IPv6
     - 
   * - `dhcp`
     - De-/activate DHCP
     - 
   * - `dhcpv6`
     - De-/activate DHCPv6
     - 
   * - `dhcpv6-ldra`
     - De-/activate DHCPv6 LDRA
     - 
   * - `igmp-autostart`
     - Overwrite IGMP autostart
     - 
   * - `igmp-version`
     - Overwrite IGMP protocol version (1, 2 or 3)
     - 
   * - `session-group-id`
     - Session group identifier
     - 
   * - `stream-group-id`
     - Stream group identifier
     - 
   * - `access-line-profile-id`
     - Access-line-profile identifier
     - 
   * - `cfm-cc`
     - De-/activate EOAM CFM CC (IPoE only)
     - false
   * - `cfm-level`
     - Set EOAM CFM maintenance domain level
     - 0
   * - `cfm-ma-id`
     - Set EOAM CFM maintenance association identifier
     - 0
   * - `cfm-ma-name`
     - Set EOAM CFM maintenance association short name
     - 
   * - `i1-start`
     - Iterator for usage in strings `{i1}`
     - 1
   * - `i1-step`
     - Iterator step per session
     - 1
   * - `i2-start`
     - Iterator for usage in strings `{i2}`
     - 1
   * - `i2-step`
     - Iterator step per session
     - 1
   * - `monkey`
     - Enable monkey testing
     - false
