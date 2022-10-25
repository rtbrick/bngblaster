.. _interfaces:

Interfaces
==========

The BNG Blaster distinguishes between interface links and interface functions.
An interface link can be considered as the actual interface with all the 
corresponding IO settings. This is similar but not the same as physical interfaces
in typical router implementations. One or more interface functions can be attached
to those links, similar to logical interfaces. The BNG Blaster supports three types 
of interface functions, ``network``, ``access``, and ``a10nsp``.

All interfaces are optional but at least one interface is required to start 
the BNG Blaster.

Interface Settings
------------------

The following configuration allows to overwrite the global default interface settings. 

.. code-block:: json

    {
        "interfaces": {
            "tx-interval": 0.1,
            "rx-interval": 0.1,
            "io-slots": 2048,
        }
    }


.. include:: configuration/interfaces.rst

The supported IO modes are listed with ``bngblaster -v`` but except
``packet_mmap_raw`` all other modes are currently considered as experimental. In
the default mode (``packet_mmap_raw``) all packets are received in a Packet MMAP
ring buffer and send directly trough RAW packet sockets.

The default ``tx-interval`` and ``rx-interval`` of ``1.0`` (1ms) allows precise timestamps 
and high throughput. Those values can be further increased (e.g. ``0.1``) for higher throughput 
or decreased (e.g. ``5.0``) for lower system load.

It might be also needed to increase the ``io-slots`` from the default value of ``4096`` to 
reach the desired throughput. The actual meaning of IO slots depends on the selected IO mode. 
For Packet MMAP it defines the maximum number of packets in the ring buffer.

Links
-----

.. _links:

.. include:: configuration/interfaces_links.rst

The BNG Blaster implements all protocols in userspace. Therefore the user interfaces 
must not have an IP address configured in the host operating system, to prevent the received 
packets are handled by Kernel. 

All used interfaces must be in an operational state up.

.. code-block:: none

    sudo ip link set dev <interface> up

It is not possible to send packets larger than the interface MTU which is 1500 per default
but for PPPoE with multiple VLAN headers this might be not enough for large packets.
Therefore the interface MTU should be increased using the following commands.

.. code-block:: none
    
    sudo ip link set mtu 9000 dev <interface>


This can be also archived via netplan using the following configuration for each BNG Blaster
interface.

.. code-block:: yaml

    network:
    version: 2
    renderer: networkd
    ethernets:
        eth1:
        dhcp4: no
        dhcp6: no
        link-local: []
        mtu: 9000
        eth2:
        dhcp4: no
        dhcp6: no
        link-local: []
        mtu: 9000

It might be also needed to increase the hardware and software queue size of your
network interfaces for higher throughput. 

The command ``ethtool -g <interface>`` shows the currently applied and maximum 
hardware queue size.

.. code-block:: none

    $ sudo ethtool -g ens5f1
    Ring parameters for ens5f1:
    Pre-set maximums:
    RX:             4096
    RX Mini:        0
    RX Jumbo:       0
    TX:             4096
    Current hardware settings:
    RX:             512
    RX Mini:        0
    RX Jumbo:       0
    TX:             512

The currently applied settings can be change with the following command: 

.. code-block:: none

    sudo ethtool -G ens5f1 tx 4096 rx 4096

You can even change the software queue size:

.. code-block:: none

    sudo ip link set txqueuelen 4096 dev ens5f1

Link Aggregation (LAG)
----------------------

.. _lag:

.. include:: configuration/interfaces_lag.rst

Network Interfaces
------------------

.. _network-interface:

The network interfaces are used for traffic and routing protocols. 

Those interfaces can communicate with the configured gateway only.
Meaning that all traffic sent from the network interface will be sent 
to the learned MAC address of the configured gateway. 

The network interface behaves like a router. It accepts all traffic sent 
to its own MAC address. This allows to send and receive traffic for prefixes 
advertised via routing protocols or configured via static routes on the 
connected device under test.

The BNG Blaster responds to all ICMP echo requests sent to its own MAC address. 

.. include:: configuration/interfaces_network.rst

The BNG Blaster supports multiple network interfaces
as shown in the example below.

.. code-block:: json

    {
        "interfaces": {
            "tx-interval": 1,
            "rx-interval": 1,
            "io-slots": 4096,
            "network": [
                {
                    "interface": "eth2",
                    "address": "10.0.0.1",
                    "gateway": "10.0.0.2",
                    "address-ipv6": "fc66:1337:7331::1",
                    "gateway-ipv6": "fc66:1337:7331::2"
                },
                {
                    "interface": "eth3",
                    "address": "10.0.1.1",
                    "gateway": "10.0.1.2",
                    "address-ipv6": "fc66:1337:7331:1::1",
                    "gateway-ipv6": "fc66:1337:7331:1::2"
                }
            ],
        }
    }

Using multiple network interfaces requires to select which network interface
to be used. If not explicitly configured one of the interface is selected 
automatically. Therefore, the configuration option ``network-interface`` 
is supported in different sections.

Access Interfaces
-----------------

.. _access-interface:

The access interfaces are used to emulate PPPoE and IPoE clients.

.. include:: configuration/interfaces_access.rst

For all modes, it is possible to configure between zero and three VLAN
tags on the access interface. The VLAN identifier ``0`` disables the
corresponding VLAN header. 

.. code-block:: none

    [ethernet][outer-vlan][inner-vlan][third-vlan][pppoe]...


Untagged
~~~~~~~~
.. code-block:: json

    {
        "access": {
            "interface": "eth1",
            "outer-vlan-min": 0,
            "outer-vlan-max": 0,
            "inner-vlan-min": 0,
            "inner-vlan-max": 0
        }
    }

Single Tagged
~~~~~~~~~~~~~
.. code-block:: json

    {
        "access": {
            "interface": "eth1",
            "outer-vlan-min": 1,
            "outer-vlan-max": 4049,
            "inner-vlan-min": 0,
            "inner-vlan-max": 0
        }
    }


Double Tagged
~~~~~~~~~~~~~
.. code-block:: json

    {
        "access": {
            "interface": "eth1",
            "outer-vlan-min": 1,
            "outer-vlan-max": 4049,
            "inner-vlan-min": 7,
            "inner-vlan-max": 7
        }
    }

Triple Tagged
~~~~~~~~~~~~~
.. code-block:: json

    {
        "access": {
            "interface": "eth1",
            "outer-vlan-min": 10,
            "outer-vlan-max": 20,
            "inner-vlan-min": 128,
            "inner-vlan-max": 4000,
            "third-vlan": 7
        }
    }

The BNG Blaster supports also multiple access interfaces
or VLAN ranges as shown in the example below.

.. code-block:: json

    {
        "access": [
            {
                "interface": "eth1",
                "type": "pppoe",
                "username": "pta@rtbrick.com",
                "outer-vlan-min": 1000,
                "outer-vlan-max": 1999,
                "inner-vlan-min": 7,
                "inner-vlan-max": 7
            },
            {
                "interface": "eth1",
                "type": "pppoe",
                "username": "l2tp@rtbrick.com",
                "outer-vlan-min": 2000,
                "outer-vlan-max": 2999,
                "inner-vlan-min": 7,
                "inner-vlan-max": 7
            },
            {
                "interface": "eth3",
                "type": "pppoe",
                "username": "test@rtbrick.com",
                "outer-vlan-min": 128,
                "outer-vlan-max": 4000,
                "inner-vlan-min": 7,
                "inner-vlan-max": 7
            },
            {
                "interface": "eth4",
                "type": "ipoe",
                "outer-vlan-min": 8,
                "outer-vlan-max": 9,
                "address": "200.0.0.1",
                "address-iter": "0.0.0.4",
                "gateway": "200.0.0.2",
                "gateway-iter": "0.0.0.4"
            }
        ]
    }


The configuration attributes for username, agent-remote-id and agent-circuit-id
support also some variable substitution. The variable ``{session-global}`` will
be replaced with a number starting from 1 and incremented for every new session.
where as the variable ``{session}`` is incremented per interface section.

In VLAN mode ``N:1`` only one VLAN combination is supported per access interface section.
This means that only VLAN min or max is considered as VLAN identifier.

.. code-block:: json

    {
        "access": [
            {
                "interface": "eth1",
                "type": "pppoe",
                "vlan-mode": "N:1",
                "username": "test@rtbrick.com",
                "outer-vlan-min": 7
            },
            {
                "interface": "eth2",
                "type": "pppoe",
                "vlan-mode": "N:1",
                "username": "test@rtbrick.com",
                "outer-vlan-min": 2000,
                "inner-vlan-min": 7,
            },
        ]
    }

A10NSP Interfaces
-----------------

.. _a10nsp-interface:

The A10NSP interface emulates an layer two provider interface. The term A10
refers to the end-to-end ADSL network reference model from TR-025.

The A10NSP interface is required for :ref:`L2BSA <l2bsa>` tests.  

.. include:: configuration/interfaces_a10nsp.rst

The BNG Blaster supports multiple A10NSP interfaces
as shown in the example below.

.. code-block:: json

    {
        "interfaces": {
            "tx-interval": 1,
            "rx-interval": 1,
            "a10nsp": [
                {
                    "interface": "eth4",
                    "qinq": true,
                    "mac": "02:00:00:ff:ff:01"
                },
                {
                    "interface": "eth5",
                    "qinq": false,
                    "mac": "02:00:00:ff:ff:02"
                }
            ],
        }
    }

You can define multiple interfaces with the same MAC
address to emulate some static link aggregation (without LACP).
