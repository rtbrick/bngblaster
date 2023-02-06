Troubleshooting
===============

.. _logging:

Logging
-------

The BNG Blaster can log events to the standard output
or the logging window of the interactive courses interface. 
Those events could be also logged into files using the argument 
``-L <file>``.

Per default, only events classified as `info` or `error` are logged. 
The following list shows all supported logging options. 

* ``debug``: debug events
* ``info``: informational events
* ``error``: error events
* ``igmp``: igmp events with join and leave time
* ``io``: interface input/output events
* ``pppoe``: pppoe events
* ``pcap``: PCAP related events
* ``ip``: log learned IP addresses
* ``loss``: log traffic loss with sequence number
* ``l2tp``: log L2TP (LNS) events
* ``dhcp``: log DHCP events
* ``isis``: log ISIS events
* ``bgp``: log BGP events 
* ``tcp``: log TCP events
* ``lag``: log link aggregation (LAG) events
* ``dpdk``: log DPDK events

.. code-block:: none
    
    $ sudo bngblaster -C test.json -L test.log -l ip -l isis -l bgp

.. _capture:

PCAP
----

You can start the BNG Blaster with the argument ``-P <file>`` 
to capture all traffic sent and received by the BNG Blaster 
into a single PCAP file. This file includes all traffic from all
interfaces in use with proper meta header to filter by interface 
names. 

This helps to verify if traffic is received or how it has been received.
Some network interfaces drop the most outer VLAN which can be easily
verified using the capture file. 

The configuration option ``capture-include-streams`` allows to 
include or exclude (default behavior) traffic streams from capture. 

.. code-block:: json

    {
        "interfaces": {
            "capture-include-streams": true
        }
    }


Traffic streams send or received on threaded interfaces will be also not captured.
All other traffic is still captured on threaded interfaces. 

Wireshark Plugin
~~~~~~~~~~~~~~~~

Traffic streams generated with the BNG Blaster include the
:ref:`BNG Blaster Header <bbl_header>` which can be analyzed 
with the Wireshark BNG Blaster Header Dissector. 

Download the LUA dissector script 
`bbl_header.lua <https://github.com/rtbrick/bngblaster/tree/main/wireshark>`_
and start Wireshark as shown below from the directory where the script is placed.

.. code-block:: none

    $ wireshark -X lua_script:bbl_header.lua

