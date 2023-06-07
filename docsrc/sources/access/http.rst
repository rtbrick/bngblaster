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
