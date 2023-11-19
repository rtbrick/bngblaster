Routing Protocols
=================

Multiple routing protocols are available, including ISIS and BGP. 
To perform comprehensive end-to-end testing for both BNG and 
non-BNG routers, you can use the BNG Blaster.

The routing protocols are designed to create a virtual node linked to 
one or multiple network interface functions. These virtual nodes enable 
the attachment of emulated network topologies. These topologies are 
generated offline using built-in tools such as lspgen (for ISIS and OSPF), 
bgpupdate, ldpupdate, or through the creation of custom tools using 
provided examples.

For ISIS and OSPF, the generated topologies are serialized into an 
MRT file as defined in `RFC6396 <https://datatracker.ietf.org/doc/html/rfc6396>`_.
This serialized topology can be dynamically updated to simulate 
link flapping in real-time.

Additionally, commands are available to for example inject LSA/LSP 
messages via CLI/REST API.

In the case of LDP and BGP, update messages are produced as raw updates 
and then transmitted to the established session. Similar to ISIS and OSPF, 
live updates can replace the file to mimic link flapping. 

.. toctree::
   :maxdepth: 1

   isis.rst
   ospf.rst
   mpls.rst
   bgp.rst
   ldp.rst
   lspgen.rst
