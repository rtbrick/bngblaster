Reports
=======

The BNG Blaster can generate detailed result reports
at the end of the test execution. 

Session Setup Rate
------------------

The BNG Blaster measures the session setup time and rate. The setup time is the time 
difference between the first session started and the last session established. The 
setup rate is measured in calls per second (CPS) and calculated by the number of 
sessions established divided by the setup time.

.. code-block:: none

                  sessions established
    setup rate =  --------------------
                      setup time

This value is internally calculated every second to derive the minimum, maximum 
and average setup rate. To better understand how those three values are derived, 
you can also think about a job that stores the actual setup rate every second 
into a time series database. Now you can search for the minimum and maximum value 
in this database and finally calculate the average over all entries. The result 
would be the same as the minimum, maximum and average setup rate calculated
by BNG Blaster. 

The following table gives an example of how those values are calculated on a particular
example with 200 sessions set up over 4 seconds. The first 100 sessions 
have been established in one second followed by decreased setup rate.

.. list-table::
   :widths: 14 25 25 12 12 12
   :header-rows: 1

   * - Seconds
     - Sessions Established
     - Setup Rate
     - MIN
     - AVG
     - MAX
   * - 1
     - 100
     - 100
     - 100
     - 100
     - 100
   * - 2
     - 150
     - 75
     - 75
     - 88
     - 100
   * - 3
     - 150
     - 50
     - 50
     - 75
     - 100
   * - 4
     - 200
     - 50
     - 50
     - 69
     - 100

Standard Output Reports
-----------------------

.. code-block:: none

        ____   __   ____         _        __                                  ,/
        / __ \ / /_ / __ ) _____ (_)_____ / /__                              ,'/
        / /_/ // __// __  |/ ___// // ___// //_/                            ,' /
    / _, _// /_ / /_/ // /   / // /__ / ,<                             ,'  /_____,
    /_/ |_| \__//_____//_/   /_/ \___//_/|_|                          .'____    ,'
        ____   _   _  ______   ____   _               _                    /  ,'
        / __ ) / | / // ____/  / __ ) / /____ _ _____ / /_ ___   ____      / ,'
        / __  |/  |/ // / __   / __  |/ // __ `// ___// __// _ \ / ___/    /,'
    / /_/ // /|  // /_/ /  / /_/ // // /_/ /(__  )/ /_ /  __// /       /
    /_____//_/ |_/ \____/  /_____//_/ \__,_//____/ \__/ \___//_/

    Report:
    =======
    Sessions PPPoE: 4000 IPoE: 0
    Sessions established: 4000/4000
    DHCPv6 sessions established: 0
    Setup Time: 4048 ms
    Setup Rate: 988.14 CPS (MIN: 988.14 AVG: 4352.28 MAX: 17021.28)
    Flapped: 0

    Interface: eth1
    --------------------------------------------------------------
    TX:                    163654 packets         24936136 bytes
    TX Polled:                  0
    TX IO Error:                0
    RX:                    180455 packets         25267731 bytes
    RX Protocol Error:          0 packets
    RX Unknown:                 0 packets
    RX Polled:               6661
    RX IO Error:                0

    A10NSP Interface: eth1
    TX:                    163654 packets   24936136 bytes
    RX:                    180455 packets   25267731 bytes
    TX Stream:             115654 packets
    RX Stream:             115654 packets (0 loss)
    Session-Traffic:
        TX IPv4:              57827 packets
        RX IPv4:              57827 packets (0 loss)
        TX IPv6:                  0 packets
        RX IPv6:                  0 packets (0 loss)
        TX IPv6PD:                0 packets
        RX IPv6PD:                0 packets (0 loss)

    Interface: eth2
    --------------------------------------------------------------
    TX:                    180854 packets         26000677 bytes
    TX Polled:                  0
    TX IO Error:                0
    RX:                    163655 packets         24281590 bytes
    RX Protocol Error:          0 packets
    RX Unknown:                 0 packets
    RX Polled:               6704
    RX IO Error:                0

    Access Interface: eth2
    TX:                    180854 packets         26000677 bytes
    RX:                    163655 packets         24281590 bytes
    RX Multicast:               0 packets                0 loss
    TX Stream:             115654 packets
    RX Stream:             115654 packets                0 loss
    Session-Traffic:
        TX IPv4:              57827 packets
        RX IPv4:              57827 packets                0 loss
        TX IPv6:                  0 packets
        RX IPv6:                  0 packets                0 loss
        TX IPv6PD:                0 packets
        RX IPv6PD:                0 packets                0 loss

    Access Interface Protocol Packet Stats:
    ARP    TX:          0 RX:          0
    PADI   TX:       4000 RX:          0
    PADO   TX:          0 RX:       4000
    PADR   TX:       4000 RX:          0
    PADS   TX:          0 RX:       4000
    PADT   TX:       4000 RX:          0
    LCP    TX:      12000 RX:      12000
    PAP    TX:       4000 RX:       4000
    CHAP   TX:          0 RX:          0
    IPCP   TX:      16000 RX:      16000
    IP6CP  TX:       8000 RX:       8000
    IGMP   TX:          0 RX:          0
    ICMP   TX:          0 RX:          0
    DHCP   TX:          0 RX:          0
    DHCPv6 TX:          0 RX:          0
    ICMPv6 TX:      13200 RX:          0
    IPv4 Fragmented       RX:          0

    Access Interface Protocol Timeout Stats:
    LCP Echo Request:          0
    LCP Request:               0
    IPCP Request:              0
    IP6CP Request:             0
    PAP:                       0
    CHAP:                      0
    DHCP Request:              0
    DHCPv6 Request:            0
    ICMPv6 RS:              9200

    Session Traffic (Global):
    --------------------------------------------------------------
    Config:
        IPv4    PPS:           1
        IPv6    PPS:           0
        IPv6PD  PPS:           0
    Verified Traffic Flows: 8000/8000
        Downstream IPv4:       4000
        Downstream IPv6:          0
        Downstream IPv6PD:        0
        Upstream IPv4:         4000
        Upstream IPv6:            0
        Upstream IPv6PD:          0
    Violations (>1s): 0
        Downstream IPv4:          0
        Downstream IPv6:          0
        Downstream IPv6PD:        0
        Upstream IPv4:            0
        Upstream IPv6:            0
        Upstream IPv6PD:          0
    First Sequence Number Received:
        Downstream IPv4    MIN:      1 ( 1.00s) AVG:      1 ( 1.00s) MAX:      1 ( 1.00s)
        Downstream IPv6    MIN:      0 ( 0.00s) AVG:      0 ( 0.00s) MAX:      0 ( 0.00s)
        Downstream IPv6PD  MIN:      0 ( 0.00s) AVG:      0 ( 0.00s) MAX:      0 ( 0.00s)
        Upstream IPv4      MIN:      1 ( 1.00s) AVG:      1 ( 1.00s) MAX:      1 ( 1.00s)
        Upstream IPv6      MIN:      0 ( 0.00s) AVG:      0 ( 0.00s) MAX:      0 ( 0.00s)
        Upstream IPv6PD    MIN:      0 ( 0.00s) AVG:      0 ( 0.00s) MAX:      0 ( 0.00s)

    Traffic Streams:
    --------------------------------------------------------------
    Verified Traffic Flows: 8000/8000
    First Sequence Number Received  MIN:        1 MAX:        1
    Flow Receive Packet Loss        MIN:        0 MAX:        0
    Flow Receive Delay (msec)       MIN:    0.009 MAX:    7.249


JSON Reports
------------

A detailed JSON report is generated if enabled using the optional 
argument ``-J <filename>``.

.. code-block:: json
        
    {
        "report": {
            "sessions": 4000,
            "sessions-pppoe": 4000,
            "sessions-ipoe": 0,
            "sessions-established": 4000,
            "sessions-flapped": 0,
            "setup-time-ms": 4046,
            "setup-rate-cps": 988.6,
            "setup-rate-cps-min": 988.6,
            "setup-rate-cps-avg": 4214,
            "setup-rate-cps-max": 16330,
            "dhcp-sessions-established": 0,
            "dhcpv6-sessions-established": 0,
            "interfaces": [
                {
                    "name": "eth1",
                    "type": "Interface",
                    "tx-packets": 139642,
                    "tx-bytes": 20229784,
                    "tx-polled": 0,
                    "tx-io-error": 0,
                    "rx-packets": 154042,
                    "rx-bytes": 20479757,
                    "rx-protocol-error": 0,
                    "rx-unknown": 0,
                    "rx-polled": 20479757,
                    "rx-io-error": 0
                },
                {
                    "name": "eth2",
                    "type": "Interface",
                    "tx-packets": 154442,
                    "tx-bytes": 21107125,
                    "tx-polled": 0,
                    "tx-io-error": 0,
                    "rx-packets": 139642,
                    "rx-bytes": 19671216,
                    "rx-protocol-error": 0,
                    "rx-unknown": 0,
                    "rx-polled": 19671216,
                    "rx-io-error": 0
                }
            ],
            "access-interfaces": [
                {
                    "name": "eth2",
                    "tx-packets": 154442,
                    "rx-packets": 139642,
                    "rx-multicast-packets": 0,
                    "rx-multicast-packets-loss": 0,
                    "tx-stream-packets": 91642,
                    "rx-stream-packets": 91642,
                    "rx-stream-packets-loss": 0,
                    "tx-session-packets-ipv4": 45821,
                    "rx-session-packets-ipv4": 45821,
                    "rx-session-packets-ipv4-loss": 0,
                    "rx-session-packets-ipv4-wrong-session": 0,
                    "tx-session-packets-ipv4-avg-pps-max": 4000,
                    "rx-session-packets-ipv4-avg-pps-max": 4000,
                    "tx-session-packets-ipv6": 0,
                    "rx-session-packets-ipv6": 0,
                    "rx-session-packets-ipv6-loss": 0,
                    "rx-session-packets-ipv6-wrong-session": 0,
                    "tx-session-packets-ipv6-avg-pps-max": 0,
                    "rx-session-packets-ipv6avg-pps-max": 0,
                    "tx-session-packets-ipv6pd": 0,
                    "rx-session-packets-ipv6pd": 0,
                    "rx-session-packets-ipv6pd-loss": 0,
                    "rx-session-packets-ipv6pd-wrong-session": 0,
                    "tx-session-packets-ipv6pd-avg-pps-max": 0,
                    "rx-session-packets-ipv6pd-avg-pps-max": 0,
                    "protocol-stats": {
                        "tx-arp": 0,
                        "rx-arp": 0,
                        "tx-padi": 4000,
                        "rx-pado": 4000,
                        "tx-padr": 4000,
                        "rx-pads": 4000,
                        "tx-padt": 4000,
                        "rx-padt": 0,
                        "tx-lcp": 12000,
                        "rx-lcp": 12000,
                        "tx-pap": 4000,
                        "rx-pap": 4000,
                        "tx-chap": 0,
                        "rx-chap": 0,
                        "tx-ipcp": 16000,
                        "rx-ipcp": 16000,
                        "tx-ip6cp": 8000,
                        "rx-ip6cp": 8000,
                        "tx-igmp": 0,
                        "rx-igmp": 0,
                        "tx-icmp": 0,
                        "rx-icmp": 0,
                        "tx-dhcp": 0,
                        "rx-dhcp": 0,
                        "tx-dhcpv6": 0,
                        "rx-dhcpv6": 0,
                        "tx-icmpv6": 10800,
                        "rx-icmpv6": 0,
                        "rx-ipv4-fragmented": 0,
                        "lcp-echo-timeout": 0,
                        "lcp-request-timeout": 0,
                        "ipcp-request-timeout": 0,
                        "ip6cp-request-timeout": 0,
                        "pap-timeout": 0,
                        "chap-timeout": 0,
                        "dhcp-timeout": 0,
                        "dhcpv6-timeout": 0,
                        "icmpv6-rs-timeout": 0
                    }
                }
            ],
            "a10nsp-interfaces": [
                {
                    "name": "eth1",
                    "tx-packets": 139642,
                    "rx-packets": 154042,
                    "tx-stream-packets": 91642,
                    "rx-stream-packets": 91642,
                    "rx-stream-packets-loss": 0,
                    "tx-session-packets-ipv4": 45821,
                    "rx-session-packets-ipv4": 45821,
                    "rx-session-packets-ipv4-loss": 0,
                    "tx-session-packets-ipv4-avg-pps-max": 4000,
                    "rx-session-packets-ipv4-avg-pps-max": 4000,
                    "tx-session-packets-ipv6": 0,
                    "rx-session-packets-ipv6": 0,
                    "rx-session-packets-ipv6-loss": 0,
                    "tx-session-packets-ipv6-avg-pps-max": 0,
                    "rx-session-packets-ipv6-avg-pps-max": 0,
                    "tx-session-packets-ipv6pd": 0,
                    "rx-session-packets-ipv6pd": 0,
                    "rx-session-packets-ipv6pd-loss": 0,
                    "tx-session-packets-ipv6pd-avg-pps-max": 0,
                    "rx-session-packets-ipv6pd-avg-pps-max": 0
                }
            ],
            "session-traffic": {
                "config-ipv4-pps": 1,
                "config-ipv6-pps": 0,
                "config-ipv6pd-pps": 0,
                "total-flows": 8000,
                "verified-flows": 8000,
                "verified-flows-downstream-ipv4": 4000,
                "verified-flows-downstream-ipv6": 0,
                "verified-flows-downstream-ipv6pd": 0,
                "verified-flows-upstream-ipv4": 4000,
                "verified-flows-upstream-ipv6": 0,
                "verified-flows-upstream-ipv6pd": 0,
                "violated-flows-downstream-ipv4": 0,
                "violated-flows-downstream-ipv6": 0,
                "violated-flows-downstream-ipv6pd": 0,
                "violated-flows-upstream-ipv4": 0,
                "violated-flows-upstream-ipv6": 0,
                "violated-flows-upstream-ipv6pd": 0,
                "first-seq-rx-downstream-ipv4-min": 1,
                "first-seq-rx-downstream-ipv4-avg": 1,
                "first-seq-rx-downstream-ipv4-max": 1,
                "first-seq-rx-downstream-ipv6-min": 0,
                "first-seq-rx-downstream-ipv6-avg": 0,
                "first-seq-rx-downstream-ipv6-max": 0,
                "first-seq-rx-downstream-ipv6pd-min": 0,
                "first-seq-rx-downstream-ipv6pd-avg": 0,
                "first-seq-rx-downstream-ipv6pd-max": 0,
                "first-seq-rx-upstream-ipv4-min": 1,
                "first-seq-rx-upstream-ipv4-avg": 1,
                "first-seq-rx-upstream-ipv4-max": 1,
                "first-seq-rx-upstream-ipv6-min": 0,
                "first-seq-rx-upstream-ipv6-avg": 0,
                "first-seq-rx-upstream-ipv6-max": 0,
                "first-seq-rx-upstream-ipv6pd-min": 0,
                "first-seq-rx-upstream-ipv6pd-avg": 0,
                "first-seq-rx-upstream-ipv6pd-max": 0,
                "first-seq-rx-downstream-ipv4-min-seconds": 1,
                "first-seq-rx-downstream-ipv4-avg-seconds": 1,
                "first-seq-rx-downstream-ipv4-max-seconds": 1,
                "first-seq-rx-downstream-ipv6-min-seconds": 0,
                "first-seq-rx-downstream-ipv6-avg-seconds": 0,
                "first-seq-rx-downstream-ipv6-max-seconds": 0,
                "first-seq-rx-downstream-ipv6pd-min-seconds": 0,
                "first-seq-rx-downstream-ipv6pd-avg-seconds": 0,
                "first-seq-rx-downstream-ipv6pd-max-seconds": 0,
                "first-seq-rx-upstream-ipv4-min-seconds": 1,
                "first-seq-rx-upstream-ipv4-avg-seconds": 1,
                "first-seq-rx-upstream-ipv4-max-seconds": 1,
                "first-seq-rx-upstream-ipv6-min-seconds": 0,
                "first-seq-rx-upstream-ipv6-avg-seconds": 0,
                "first-seq-rx-upstream-ipv6-max-seconds": 0,
                "first-seq-rx-upstream-ipv6pd-min-seconds": 0,
                "first-seq-rx-upstream-ipv6pd-avg-seconds": 0,
                "first-seq-rx-upstream-ipv6pd-max-seconds": 0
            },
            "traffic-streams": {
                "total-flows": 8000,
                "verified-flows": 8000,
                "first-seq-rx-min": 1,
                "first-seq-rx-max": 1,
                "flow-rx-packet-loss-min": 0,
                "flow-rx-packet-loss-max": 0,
                "flow-rx-delay-min": 6779,
                "flow-rx-delay-max": 6940868
            }
        }
    }

The optional argument ``-j sessions`` allows to include per session statistics
in the report file. Similar to ``-j streams`` which allows for including per stream
statistics. Both options can be also combined.

Those extensive JSON reports could be easily verified with simple python scripts to 
extract the desired results. 

.. code-block:: python

    #!/usr/bin/env python3
    import json

    # Open JSON report ...
    with open('report.json') as f:
        data = json.load(f)
        # Analyze data ...