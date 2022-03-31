.. _l2bsa:

L2BSA
-----

The A10NSP interface emulates an layer two provider interface. The term A10
refers to the end-to-end ADSL network reference model from TR-025.

Following a basic PPPoE/A10NSP configuration example which is
detailed explained in the configuration section.

.. code-block:: json

    {
        "interfaces": {
            "a10nsp": [
                {
                    "interface": "eth4",
                    "qinq": true,
                    "mac": "02:00:00:ff:ff:01"
                },
                {
                    "interface": "eth5",
                    "qinq": true,
                    "mac": "02:00:00:ff:ff:01"
                }
            ],
            "access": [
                {
                    "__comment__": "PPPoE",
                    "interface": "eth1",
                    "type": "pppoe",
                    "outer-vlan-min": 1,
                    "outer-vlan-max": 4000,
                    "inner-vlan": 7,
                    "stream-group-id": 1
                }
            ]
        },
        "pppoe": {
            "reconnect": true,
            "discovery-timeout": 3,
            "discovery-retry": 10,
            "host-uniq": true,
            "vlan-priority": 6
        },
        "dhcpv6": {
            "enable": false
        },
        "session-traffic": {
            "autostart": true,
            "ipv4-pps": 10
        },
        "streams": [
            {
                "stream-group-id": 2,
                "name": "PPPOE-S1",
                "type": "ipv4",
                "direction": "both",
                "priority": 128,
                "length": 256,
                "pps": 10,
                "a10nsp-interface": "eth4"
            },
            {
                "stream-group-id": 2,
                "name": "PPPOE-S2",
                "type": "ipv4",
                "direction": "both",
                "priority": 128,
                "length": 256,
                "pps": 10,
                "a10nsp-interface": "eth5"
            }
        ]
    }
