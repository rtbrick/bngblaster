Troubleshooting
===============

Logging
-------

The BNG Blaster is able to log events to the standard output
or logging window of the interactive courses interface. Those
events could be also logged to files using the argument 
``-L <file>``.

Per default only events classified as `info` or `error` are logged. 
The following list shows all supported logging options. 

* ``debug``: debug events
* ``error``: error events
* ``igmp``: igmp events with join and leave time
* ``io``: interface input/output events
* ``pppoe``: pppoe events
* ``info``: informational events (enabled per default)
* ``pcap``: PCAP related events
* ``timer``: timer events
* ``timer-detail``: detailed timer events
* ``ip``: log learned IP addresses
* ``loss``: log traffic loss with sequence number
* ``l2tp``: log L2TP (LNS) events
* ``dhcp``: log DHCP events
* ``isis``: log ISIS events
* ``bgp``: log BGP events 
* ``tcp``: log TCP events

.. code-block:: none
    
    $ sudo bngblaster -C test.json -L test.log -l ip -l isis -l bgp


PCAP
----

You can start the BNG Blaster with the argument ``-P <file>`` 
to capture all traffic send and received by the BNG Blaster 
into a single PCAP file. This file includes all traffic from all
interfaces in use with proper meta header to filter by interface 
names. 

This helps to verify if traffic is received or how it has received.
Some network interfaces drop the most outer VLAN which can be easily
verified using the capture file. 