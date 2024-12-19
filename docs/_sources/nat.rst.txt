.. _nat:

NAT / CGNAT
===========

NAT, or Network Address Translation, is a technology used in 
computer networking to enable multiple devices on a local 
network to share a single public IP address for connecting to 
the internet. NAT works by mapping private IP addresses used 
within a local network to a single public IP address when 
communicating with external networks, such as the internet. 
This allows a single public IP address to serve as an entry 
point for multiple devices within the private network, 
effectively concealing the internal network structure.

Carrier-Grade NAT (CGNAT) is an extension of NAT specifically 
designed for large-scale service providers, such as internet 
service providers (ISPs) and telecommunications companies. 
It is used to address the increasing scarcity of IPv4 addresses, 
as more and more devices are connected to the internet.

The BNG Blaster incorporates a comprehensive set of functionalities 
tailored to NAT, with a particular focus on CGNAT testing. These 
features are purpose-built to address the specific requirements and 
complexities associated with Carrier-Grade Network Address Translation. 

The tool offers a range of capabilities that are instrumental in assessing 
and validating the performance and functionality of CGNAT systems. 
This includes the ability to simulate and analyze large-scale address 
translation scenarios, ensuring that the NAT infrastructure effectively 
handles the demands of a multitude of users sharing a limited pool of public 
IP addresses. Furthermore, the BNG Blaster's CGNAT testing features enable the 
emulation of various network conditions and scenarios, helping service providers 
and network operators assess the impact of CGNAT on user experiences and address 
any potential issues.

In addition to CGNAT testing, the BNG Blaster's NAT-related features encompass 
a broad spectrum of testing and evaluation options, ensuring that Network Address 
Translation mechanisms, whether they be traditional NAT or CGNAT, are rigorously 
examined for performance, scalability, and reliability. This robust suite of tools 
makes the BNG Blaster an invaluable resource for network professionals working 
with NAT technologies in their infrastructure.

NAT Features
------------

Reverse Flow
~~~~~~~~~~~~
For all bidirectional streams ("direction": "both"), the reverse (other direction) 
stream flow-id is now displayed which allows for more efficient analysis of 
bidirectional flows. 

.. code-block:: none

    $ sudo bngblaster-cli run.sock stream-info flow-id 1
    {
        "status": "ok",
        "code": 200,
        "stream-info": {
            "name": "UDP1",
    …
            "flow-id": 1,
    …
            "reverse-flow-id": 2
        }
    }
    $ sudo bngblaster-cli run.sock stream-info flow-id 2
    {
        "status": "ok",
        "code": 200,
        "stream-info": {
            "name": "UDP1",
    …
            "flow-id": 2,
    …
            "reverse-flow-id": 1
        }
    }

Flow Addresses
~~~~~~~~~~~~~~
The configured or dynamically resolved source and destination 
address and port is now shown with stream-info command.

.. code-block:: none

    $ sudo bngblaster-cli run.sock stream-info flow-id 1
    {
        "status": "ok",
        "code": 200,
        "stream-info": {
            "name": "UDP1",
            "type": "unicast",
            "sub-type": "ipv4",
            "direction": "downstream",
            "source-address": "10.0.0.1",
            "source-port": 65056,
            "destination-address": "192.0.2.8",
            "destination-port": 65056,
            "protocol": "udp", # udp or tcp
    …
        }
    }


NAT Enabled Streams
~~~~~~~~~~~~~~~~~~~
A new option called **nat** is added to the stream configuraton. 
This option is supported for bidirectional and upstream streams only, 
meaning it is not supported for downstream-only streams, as those can't 
pass a NAT gateway. 

For bidirectional streams, the downstream flow waits until first upstream
packet has been received to learn the translated source address and port
which have to be used as destionation for this flow. 

.. code-block:: json

    {
        "streams": [
            {
                "name": "UDP1",
                "stream-group-id": 1,
                "type": "ipv4",
                "direction": "both",
                "pps": 1,
                "nat": true,
                "network-ipv4-address": "10.0.0.1"
            },
            {
                "name": "UDP2",
                "stream-group-id": 1,
                "type": "ipv4",
                "direction": "upstream",
                "pps": 1,
                "nat": true,
                "network-ipv4-address": "10.0.0.2"
            }
        ]
    }

The stream in the upstream direction (from the client) will also record the 
received source IPv4 address and port, meaning the address and port assigned by the 
NAT gateway.

.. code-block:: none

    $ sudo bngblaster-cli run.sock stream-info flow-id 1
    {
        "status": "ok",
        "code": 200,
        "stream-info": {
            "name": "UDP1",
            "type": "unicast",
            "sub-type": "ipv4",
            "direction": "upstream",
            "source-address": "100.64.0.2",
            "source-port": 65056,
            "destination-address": "10.0.0.1",
            "destination-port": 65056,
            "protocol": "udp", # udp or tcp
    …
            "rx-source-ip": "192.0.2.8",
            "rx-source-port": 48523,
    …
            "session-id": 1,
            "reverse-flow-id": 2
        }
    }


TCP RAW Streams
~~~~~~~~~~~~~~~

A new option called **raw-tcp** is added to the stream configuraton. 
If enabled, UDP-like traffic with a constant rate is sent using a 
static (RAW) TCP header.

.. code-block:: json

    {
        "streams": [
            {
                "name": "TCP1",
                "stream-group-id": 1,
                "type": "ipv4",
                "direction": "both",
                "pps": 1,
                "raw-tcp": true,
                "network-ipv4-address": "10.0.0.1"
            }
        ]
    }

This option can be used stand-alone to verify firewall filters or together 
with the new NAT option to verify NAT TCP streams. 

For now, TCP flags (SYN, …) are statically set to SYN but this could be adopted if needed.

Stream Setup interval
~~~~~~~~~~~~~~~~~~~~~

It is possible to configure an optional stream setup interval in seconds.
If set, the BNG Blaster will sent max 1 packet per setup interval until the 
stream becomes verified. After setup is done, the actual rate will be applied. 

For bidirectional streams (direction both), this requires both 
directions to be verified.    

.. code-block:: json

    {
        "streams": [
            {
                "name": "TCP1",
                "stream-group-id": 1,
                "type": "ipv4",
                "direction": "both",
                "pps": 1,
                "setup-interval": 30,
                "raw-tcp": true,
                "network-ipv4-address": "10.0.0.1"
            }
        ]
    }

HTTP NAT Extension
~~~~~~~~~~~~~~~~~~
The existing :ref:`HTTP client/server <http>` was also enhanced for NAT usage.
The actual configuration is uncahnged but the HTTP server will now return the 
received client IP address and port in dedicated HTTP headers as shown below 
where X-Client-Ip and Port shows the IP address and port assigned from the NAT gateway. 

.. code-block:: json

    {
        "interfaces": {
            "capture-include-streams": true,
            "network": {
                "interface": "enp6s21",
                "address": "192.0.2.254/24",
                "gateway": "192.0.2.1"
            },
            "access": [
            {
                "interface": "enp6s20",
                "type": "ipoe",
                "address": "100.64.0.2",
                "address-iter": "0.0.0.1",
                "gateway": "100.64.0.1",
                "gateway-iter": "0.0.0.0",
                "dhcp": false,
                "ipv6": false,
                "http-client-group-id": 1
            }
        ]
        },
        "http-client": [
            {
                "http-client-group-id": 1,
                "name": "C1",
                "destination-ipv4-address": "192.0.2.254",
                "destination-port": 80,
                "url": "blaster.test.de"
            },
            {
                "http-client-group-id": 1,
                "name": "C2",
                "destination-ipv4-address": "192.0.2.254",
                "destination-port": 80,
                "url": "blaster.test.de"
            }
        ],
        "http-server": [
            {
                "name": "SERVER",
                "ipv4-address": "192.0.2.254",
                "port": 80,
                "network-interface": "enp6s21"
            }
        ]
    }

.. code-block:: none

    $ sudo bngblaster-cli run.sock http-clients
    {
        "status": "ok",
        "code": 200,
        "http-clients": [
            {
                "session-id": 1,
                "http-client-group-id": 1,
                "name": "C2",
                "url": "blaster.test.de",
                "destination-address": "192.0.2.254",
                "destination-port": 80,
                "state": "closed",
                "response": {
                    "minor-version": 1,
                    "status": 200,
                    "msg": "OK\r\nServer: BNG-Blaster\r\nX-Client-Ip: 192.0.2.5\r\nX-Client-Port: 63122\r\n\r\n",
                    "headers": [
                        {
                            "name": "Server",
                            "value": "BNG-Blaster"
                        },
                        {
                            "name": "X-Client-Ip",
                            "value": "192.0.2.5"
                        },
                        {
                            "name": "X-Client-Port",
                            "value": "63122"
                        }
                    ]
                }
            },
            {
                "session-id": 1,
                "http-client-group-id": 1,
                "name": "C1",
                "url": "blaster.test.de",
                "destination-address": "192.0.2.254",
                "destination-port": 80,
                "state": "closed",
                "response": {
                    "minor-version": 1,
                    "status": 200,
                    "msg": "OK\r\nServer: BNG-Blaster\r\nX-Client-Ip: 192.0.2.5\r\nX-Client-Port: 63121\r\n\r\n",
                    "headers": [
                        {
                            "name": "Server",
                            "value": "BNG-Blaster"
                        },
                        {
                            "name": "X-Client-Ip",
                            "value": "192.0.2.5"
                        },
                        {
                            "name": "X-Client-Port",
                            "value": "63121"
                        }
                    ]
                }
            }
        ]
    }

Unfortunately HTTP client/server scaling is limited, therefore raw-TCP
streams is the better option to test NAT on scale. 

ICMP Client
~~~~~~~~~~~

The :ref:`ICMP client <icmp>` makes it possible to initiate pings from NATed sessions to network 
interfaces or other endpoint, allowing you to verify that ICMP traffic is correctly translated 
by the NAT device under test.

Scaling
~~~~~~~
The number of UDP and raw-TCP traffic streams can be further expanded by 
leveraging the following configuration options.

One option to increase scaling is to disable per stream live rate calculation
which is typically not needed for millions of streams. 

.. code-block:: json

    { "traffic": { "stream-rate-calculation": false } }

All traffic stats are still working but the live rate is not calculated. 

It is also possible to disable the stream delay calcualtion if not needed.

.. code-block:: json

    { "traffic": { "stream-delay-calculation": false } }

Another option is to setup the traffic streams with a rate of 0.1 PPS,
meaning one packet every 10 seconds. This is enough to keep NAT translation
active but allows 1M streams with only 100K PPS. 

See also :ref:`performance guide <performance>` for further optimization. 