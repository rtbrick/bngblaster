.. _lspgen:

LSPGEN
------

The BNG Blaster includes a tool called ``lspgen`` which is able to generate 
ISIS and OSPF topologies with the corresponding link state packets for export 
as MRT and PCAP files. Initially, ``lspgen`` was developed exclusively for ISIS, 
hence its name. However, with the introduction of OSPF support in BNG Blaster, 
``lspgen`` has been enhanced to accommodate OSPF topologies as well.

The default protocol is ISIS which can be changed using the argument ``-P ospf2``. 

.. code-block:: none

    $ lspgen --help

          ____   __   ____         _        __            ,/
         / __ \ / /_ / __ ) _____ (_)_____ / /__        ,'/
        / /_/ // __// __  |/ ___// // ___// //_/      ,' /
       / _, _// /_ / /_/ // /   / // /__ / ,<       ,'  /_____,
      /_/ |_| \__//_____//_/   /_/ \___//_/|_|    .'____    ,'
          __   _____ ____  ______                      /  ,'
         / /  / ___// __ \/ ____/__  ____             / ,'
        / /   \__ \/ /_/ / / __/ _ \/ __ \           /,'
       / /______/ / ____/ /_/ /  __/ / / /          /
      /_____/____/_/    \____/\___/_/ /_/
    
    Usage: lspgen [OPTIONS]
    
      -v --version
      -a --area <args>
      -P --protocol isis|ospf2
      -K --authentication-key <args>
      -T --authentication-type none|simple|md5
      -r --read-config-file <args>
      -w --write-config-file <args>
      -C --connector <args>
      -S --control-socket <args>
      -l --ipv4-link-prefix <args>
      -L --ipv6-link-prefix <args>
      -n --ipv4-node-prefix <args>
      -N --ipv6-node-prefix <args>
      -x --ipv4-external-prefix <args>
      -X --ipv6-external-prefix <args>
      -M --lsp-lifetime <args>
      -z --no-ipv4
      -Z --no-ipv6
      -y --no-sr
      -e --external-count <args>
      -g --graphviz-file <args>
      -h --help
      -m --mrt-file <args>
      -c --node-count <args>
      -p --pcap-file <args>
      -f --stream-file <args>
      -s --seed <args>
      -q --sequence <args>
      -Q --quit-loop
      -V --level <args>
      -t --log normal|debug|lsp|lsdb|packet|ctrl|error 

You can generate random topologies or define a topology manually 
using configuration files.

Connector
^^^^^^^^^

The connector (``-C --connector <args>``) represents the link between the generated
topology and the attached BNG Blaster instance. 

For ISIS topologies, the connector must be set to the ``system-id`` of the ISIS
instance to which this topology is attached. In the BNG Blaster configuration, 
the ``system-id`` of the root node from the generated toplogy must be referenced. 

.. image:: ../images/bbl_isis.png
    :alt: ISIS

.. code-block:: none

    $ lspgen -a 49.0001/24 -K secret123 -T md5 -C 1921.6800.1001 -m isis.mrt
    ...
    Sep 04 10:50:55.780109 Generating a graph of 10 nodes and 20 links
    Sep 04 10:50:55.780127  Root node 1921.6800.0000.00 (node1)
    ...

.. code-block:: json

    {
        "isis": [
            {
                "instance-id": 1,
                "area": [
                    "49.0001/24",
                ],
                "system-id": "1921.6800.1001",
                "router-id": "192.168.1.1",
                "hostname": "R1",
                "level1-auth-key": "secret123",
                "level1-auth-type": "md5",
                "external": {
                    "mrt-file": "isis.mrt",
                    "connections": [
                        {
                            "system-id": "1921.6800.0000.00"
                        }
                    ]
                }
            }
        ]
    }

This is simlar for OSPFv2 but here the connector is constructed based on remote router-id 
and local link IPv4 address (``remote-router-id:local-ipv4-address``). 

.. image:: ../images/bbl_ospf.png
    :alt: OSPF

.. code-block:: none

    $ lspgen -P ospf2 -m ospf.mrt -n 10.10.0.1 --connector "10.0.0.11:10.0.0.2" -p lspgen.pcap
    ...
    Sep 04 11:02:59.242810 Generating a graph of 10 nodes and 20 links
    Sep 04 11:02:59.242827  Root node 10.10.0.1 (node1)
    ...

.. code-block:: json

    {
        "ospf": [
            {
                "instance-id": 1,
                "version": 2,
                "router-id": "10.0.0.11",
                "hostname": "R1"
                "external": {
                    "mrt-file": "ospf.mrt",
                    "connections": [
                        {
                            "router-id": "10.10.0.1",
                            "local-ipv4-address": "10.0.0.1",
                        }
                    ]
                }
            }
        ]
    }

Random Topologies
^^^^^^^^^^^^^^^^^

The following example generates a random topology with 1000 nodes. 

.. code-block:: none

    lspgen -m isis.mrt -c 1000 -K <secret> -T md5

The arguments ``-K`` and ``-T`` add a valid authentication TLV
to the generated LSPs in the MRT file. 

Those topologies could be even exported as configuration file 
with the argument ``-w`` and later imported with the argument ``-r``.
This allows the generation of a large random topology that can be modified
manually. 

Topology from Configuration File
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In addition to randomly generated topologies, it is also possible to 
create them specifically using configuration. 

.. note::

    This option is currently supported for ISIS only!

The following example shows the configuration for a topology 
with three nodes.

.. code-block:: json

    {
        "level1": [
            {
                "node_id": "1337.0000.0001",
                "hostname": "R1",
                "area_list": [
                    "49.1337/24"
                ],
                "protocol_list": [
                    "ipv4"
                ],
                "ipv4_address_list": [
                    "10.13.37.1"
                ],
                "ipv4_prefix_list": [
                    {
                        "ipv4_prefix": "10.13.37.1/32",
                        "metric": 0,
                        "segment_id": 30005,
                        "node_flag": true
                    },
                    {
                        "ipv4_prefix": "10.0.1.0/24",
                        "metric": 1000
                    },
                    {
                        "ipv4_prefix": "10.0.2.0/24",
                        "metric": 1000
                    }
                ],
                "capability_list": [
                    {
                        "router_id": "10.13.37.1",
                        "mpls_ipv4_flag": true,
                        "mpls_ipv6_flag": false,
                        "srgb_base": 100000,
                        "srgb_range": 36000
                    }
                ],
                "neighbor_list": [
                    {
                        "remote_node_id": "1337.0000.0000.00",
                        "metric": 10
                    },
                    {
                        "remote_node_id": "1337.0000.0002.00",
                        "metric": 10
                    },
                    {
                        "remote_node_id": "0204.0000.0003.00",
                        "metric": 10
                    }
                ]
            },
            {
                "node_id": "1337.0000.0002",
                "hostname": "R2",
                "area_list": [
                    "49.1337/24"
                ],
                "protocol_list": [
                    "ipv4"
                ],
                "ipv4_address_list": [
                    "10.13.37.2"
                ],
                "ipv4_prefix_list": [
                    {
                        "ipv4_prefix": "10.13.37.2/32",
                        "metric": 0,
                        "segment_id": 30003,
                        "node_flag": true
                    }
                ],
                "capability_list": [
                    {
                        "router_id": "10.13.37.2",
                        "mpls_ipv4_flag": true,
                        "mpls_ipv6_flag": false,
                        "srgb_base": 100000,
                        "srgb_range": 36000
                    }
                ],
                "neighbor_list": [
                    {
                        "remote_node_id": "1337.0000.0001.00",
                        "metric": 10
                    }
                ]
            },
            {
                "node_id": "1337.0000.3",
                "hostname": "R3",
                "area_list": [
                    "49.1337/24"
                ],
                "protocol_list": [
                    "ipv4"
                ],
                "ipv4_address_list": [
                    "10.13.37.3"
                ],
                "ipv4_prefix_list": [
                    {
                        "ipv4_prefix": "10.13.37.3/32",
                        "metric": 0,
                        "segment_id": 30003,
                        "node_flag": true
                    }
                ],
                "capability_list": [
                    {
                        "router_id": "10.13.37.3",
                        "mpls_ipv4_flag": true,
                        "mpls_ipv6_flag": false,
                        "srgb_base": 100000,
                        "srgb_range": 36000
                    }
                ],
                "neighbor_list": [
                    {
                        "remote_node_id": "1337.0000.0001.00",
                        "metric": 10
                    }
                ]
            }
        ]
    }