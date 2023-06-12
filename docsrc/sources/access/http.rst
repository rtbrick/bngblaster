.. _http:

HTTP
----

Client Configuration
~~~~~~~~~~~~~~~~~~~~

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

Server Configuration
~~~~~~~~~~~~~~~~~~~~

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
