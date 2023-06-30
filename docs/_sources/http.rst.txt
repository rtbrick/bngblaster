.. _http:

HTTP Emulation
==============

In addition to its primary purpose of testing HTTP redirect capabilities,
the BNG Blaster's ability to emulate HTTP requests on top of any PPPoE or IPoE 
session offers several other valuable applications. One such application is the 
testing of filters or NAT (Network Address Translation) rules.

By emulating HTTP requests, the BNG Blaster allows testers to assess the 
effectiveness and accuracy of their configured filters or NAT rules.
Moreover, the BNG Blaster's flexibility in emulating HTTP requests on 
different session types, such as PPPoE or IPoE, allows for comprehensive 
testing across various network configurations. This versatility enables users 
to evaluate the performance and compatibility of the BNG (Broadband Network Gateway) 
device under test in different deployment scenarios.

HTTP Client
-----------

Following is a basic HTTP client configuration example.

.. code-block:: json

    {
        "interfaces": {
            "access": [
            {
                "interface": "eth1",
                "type": "ipoe",
                "outer-vlan": 7,
                "vlan-mode": "N:1",
                "http-client-group-id": 1
            }
        ]
        },
        "dhcp": {
            "enable": true,
        },
        "dhcpv6": {
            "enable": true
        },
        "http-client": [
            {
                "http-client-group-id": 1,
                "name": "CLIENT-1",
                "url": "blaster.rtbrick.com",
                "destination-ipv4-address": "10.10.10.10",
                "destination-port": 80
            }
        ]
    }

.. include:: ../configuration/http_client.rst

The association between the HTTP client and sessions is established through 
the use of the HTTP client group identifier (http-client-group-id). Multiple 
HTTP clients can be defined with the same HTTP client group identifier. 

For instance, if you define 4 HTTP clients with the same HTTP client group 
identifier and bind them to 100 sessions each, the BNG Blaster will generate 
a total of 400 HTTP client instances.

When a session becomes established, each HTTP client instance is automatically 
started by default. However, it is also possible to prevent automatic startup by 
setting the autostart parameter in the HTTP client definition to false. This allows 
for more control over when the HTTP client should begin operating.

In addition to automatic startup, the HTTP client can also be manually started or 
stopped using control commands. This gives users the flexibility to manage the HTTP 
client's operation according to their specific requirements.

Overall, the HTTP client functionality provides the ability to bind multiple clients 
to sessions using the HTTP client group identifier, allowing for efficient management 
and control over the initiation and termination of HTTP client instances.

.. code-block:: none
    
    $ sudo bngblaster-cli run.sock http-clients session-id 1 | jq .

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "http-clients": [
            {
                "session-id": 1,
                "http-client-group-id": 1,
                "name": "CLIENT-2",
                "url": "blaster.test.de",
                "destination-address": "10.10.10.12",
                "destination-port": 80,
                "state": "closed",
                "response": {
                    "minor-version": 1,
                    "status": 302,
                    "msg": "Found\r\nLocation: https://github.com/rtbrick/bngblaster\r\nContent-Length: 0\r\n\r\n",
                    "headers": [
                        {
                            "name": "Location",
                            "value": "https://github.com/rtbrick/bngblaster"
                        },
                        {
                            "name": "Content-Length",
                            "value": "0"
                        }
                    ]
                }
            },
            {
                "session-id": 1,
                "http-client-group-id": 1,
                "name": "CLIENT-1",
                "url": "blaster.test.de",
                "destination-address": "10.10.10.11",
                "destination-port": 80,
                "state": "closed",
                "response": {
                    "minor-version": 1,
                    "status": 200,
                    "msg": "OK\r\nServer: BNG-Blaster\r\n\r\n",
                    "headers": [
                        {
                            "name": "Server",
                            "value": "BNG-Blaster"
                        }
                    ]
                }
            }
        ]
    }


The output above demonstrates the responses of two HTTP client instances. However, 
if any of the requests are marked as closed or terminated, it is possible to restart 
them using the HTTP client start command. This command can be applied to either all 
sessions simultaneously or just a specific session. By initiating the HTTP client 
start command, you can resume the execution of the previously closed requests and 
continue interacting with the server. 


.. code-block:: none
    
    $ sudo bngblaster-cli run.sock http-clients-start session-id 1 | jq .

.. code-block:: none
    
    $ sudo bngblaster-cli run.sock http-clients-stop | jq .


HTTP Server
-----------

Following is a basic HTTP server configuration example.

.. code-block:: json

    {
        "interfaces": {
            "access": [
                {
                    "interface": "eth1",
                    "type": "ipoe",
                    "outer-vlan": 7,
                    "vlan-mode": "N:1",
                    "http-client-group-id": 1
                }
            ]
            "network": [
                {
                    "interface": "eth2",
                    "address": "10.10.10.10.1/24",
                    "gateway": "10.10.10.1",
                    "address-ipv6": "fc66:1337:7331::1/64",
                    "gateway-ipv6": "fc66:1337:7331::2",
                }
            ]
        },
        "dhcp": {
            "enable": true,
        },
        "dhcpv6": {
            "enable": true
        },
        "http-client": [
            {
                "http-client-group-id": 1,
                "name": "CLIENT-1",
                "url": "blaster.rtbrick.com",
                "destination-ipv4-address": "10.10.10.10",
                "destination-port": 80
            }
        ],
        "http-server": [
            {
                "name": "SERVER",
                "network-interface": "eth2"
                "ipv4-address": "10.10.10.10",
                "port": 80,
            }
        ]
    }

.. include:: ../configuration/http_server.rst

The BNG Blaster offers the capability to emulate a lightweight HTTP server on 
top of any network interface function. This functionality allows the BNG Blaster 
to simulate the behavior of an HTTP server, enabling various testing and 
evaluation scenarios.
