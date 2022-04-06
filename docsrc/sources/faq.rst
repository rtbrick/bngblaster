Frequently Asked Questions
==========================

**Outer VLAN header not captured in PCAP?**

Some interface drivers drop the outer VLAN header. The BNG Blaster tries to 
recover the VLAN from kernel headers but will not change the packets stored 
in the PCAP file.

**Some session established on BNG are not established on BNG Blaster?**

The BNG Blaster considers a session only as established if all configured 
protocols are established. This could occur if the device under test (your BNG)
is configured for IPv4 only but the BNG Blaster is configured for IPv4 and IPv6. 

The idea here is to prevent that potential failures will be overseen. 

**DHCPv6 does not start for PPPoE sessions?**

The BNG Blaster expects an ICMPv6 router-advertisement with other-config flag
before it starts sending DHCPv6 within a PPPoE session.

