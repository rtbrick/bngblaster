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

    Report:
    ==============================================================================
    Test Duration: 139s
    Sessions PPPoE: 1000 IPoE: 0
    Sessions established: 1000/1000
    DHCPv6 sessions established: 1000
    Setup Time: 55661 ms
    Setup Rate: 17.97 CPS (MIN: 15.01 AVG: 18.03 MAX: 19.36)
    Flapped: 0

    Interface: eth1
    ------------------------------------------------------------------------------
      TX:                    111410 packets         12654727 bytes
      TX Polled:                  0
      TX IO Error:                0
      RX:                    110161 packets         12300031 bytes
      RX Protocol Error:          0 packets
      RX Unknown:                 5 packets
      RX Polled:              93709
      RX IO Error:                0

    Access Interface: eth1
      TX:                    111410 packets         12654727 bytes
      RX:                    110156 packets         12299556 bytes
      RX Multicast:               0 packets                0 loss
      Session-Traffic:
        TX IPv4:              33319 packets
        RX IPv4:              32641 packets                0 loss
        TX IPv6:              33319 packets
        RX IPv6:              32635 packets                0 loss
        TX IPv6PD:            33311 packets
        RX IPv6PD:            32633 packets                0 loss

    Access Interface Protocol Packet Stats:
      ARP    TX:          0 RX:          0
      PADI   TX:       1104 RX:          0
      PADO   TX:          0 RX:        500
      PADR   TX:        500 RX:          0
      PADS   TX:          0 RX:        500
      PADT   TX:        127 RX:        373
      LCP    TX:       4880 RX:       4880
      PAP    TX:          0 RX:          0
      CHAP   TX:       1700 RX:       1000
      IPCP   TX:       1500 RX:       1500
      IP6CP  TX:       1000 RX:       1000
      IGMP   TX:          0 RX:          0
      ICMP   TX:          0 RX:          0
      DHCP   TX:          0 RX:          0
      DHCPv6 TX:        500 RX:        500
      ICMPv6 TX:       1000 RX:       1840
      IPv4 Fragmented       RX:          0

    Access Interface Protocol Timeout Stats:
      LCP Echo Request:          0
      LCP Request:               0
      IPCP Request:              0
      IP6CP Request:             0
      PAP:                       0
      CHAP:                    350
      DHCP Request:              0
      DHCPv6 Request:            0
      ICMPv6 RS:                 0

    Interface: eth2
    ------------------------------------------------------------------------------
      TX:                    108580 packets         12360218 bytes
      TX Polled:                  0
      TX IO Error:                0
      RX:                    106881 packets         11982029 bytes
      RX Protocol Error:          0 packets
      RX Unknown:                 5 packets
      RX Polled:              95265
      RX IO Error:                0

    Access Interface: eth2
      TX:                    108580 packets         12360218 bytes
      RX:                    106876 packets         11981554 bytes
      RX Multicast:               0 packets                0 loss
      Session-Traffic:
        TX IPv4:              32465 packets
        RX IPv4:              31896 packets                0 loss
        TX IPv6:              32465 packets
        RX IPv6:              31895 packets                0 loss
        TX IPv6PD:            32461 packets
        RX IPv6PD:            31894 packets                0 loss

    Access Interface Protocol Packet Stats:
      ARP    TX:          0 RX:          0
      PADI   TX:       1102 RX:          0
      PADO   TX:          0 RX:        500
      PADR   TX:        844 RX:          0
      PADS   TX:          0 RX:        500
      PADT   TX:         78 RX:        422
      LCP    TX:       4343 RX:       4343
      PAP    TX:        822 RX:        500
      CHAP   TX:          0 RX:          0
      IPCP   TX:       1500 RX:       1500
      IP6CP  TX:       1000 RX:       1000
      IGMP   TX:          0 RX:          0
      ICMP   TX:          0 RX:          0
      DHCP   TX:          0 RX:          0
      DHCPv6 TX:        500 RX:        500
      ICMPv6 TX:       1000 RX:       1816
      IPv4 Fragmented       RX:          0

    Access Interface Protocol Timeout Stats:
      LCP Echo Request:          0
      LCP Request:               0
      IPCP Request:              0
      IP6CP Request:             0
      PAP:                     322
      CHAP:                      0
      DHCP Request:              0
      DHCPv6 Request:            0
      ICMPv6 RS:                 0

    Interface: eth3
    ------------------------------------------------------------------------------
      TX:                    197523 packets         21009053 bytes
      TX Polled:                  0
      TX IO Error:                0
      RX:                    188259 packets         20425245 bytes
      RX Protocol Error:          0 packets
      RX Unknown:                 0 packets
      RX Polled:              74810
      RX IO Error:                0

    Network Interface: eth3
      TX:                    197523 packets         21009053 bytes
      RX:                    188259 packets         20425245 bytes
      TX Multicast:               0 packets
      Session-Traffic:
        TX IPv4:              65784 packets
        RX IPv4:              64537 packets                0 loss
        TX IPv6:              65784 packets
        RX IPv6:              61793 packets                0 loss
        TX IPv6PD:            65772 packets
        RX IPv6PD:            61790 packets                0 loss

    Session Traffic (Global):
    ------------------------------------------------------------------------------
      Config:
        PPS IPv4:                    1
        PPS IPv6:                    1
        PPS IPv6PD:                  1
      Verified Traffic Flows:     6000/6000 (100.00%)
        Downstream IPv4:          1000
        Downstream IPv6:          1000
        Downstream IPv6PD:        1000
        Upstream IPv4:            1000
        Upstream IPv6:            1000
        Upstream IPv6PD:          1000
      Violations:               >1s             >1s-2s   >2s-3s      >3s
        Downstream IPv4:        623 ( 10.38%)      199      224      200
        Downstream IPv6:        624 ( 10.40%)      200      218      206
        Downstream IPv6PD:      624 ( 10.40%)      200      227      197
        Upstream IPv4:          623 ( 10.38%)      199      224      200
        Upstream IPv6:          624 ( 10.40%)      200      218      206
        Upstream IPv6PD:        624 ( 10.40%)      200      227      197
        Total:                 3742 ( 62.37%)     1198     1338     1206
      First Sequence Received:  MIN                AVG               MAX
        Downstream IPv4           1 ( 1.00s)         2 ( 2.00s)        4 ( 4.00s)
        Downstream IPv6           1 ( 1.00s)         2 ( 2.00s)        4 ( 4.00s)
        Downstream IPv6PD         1 ( 1.00s)         2 ( 2.00s)        4 ( 4.00s)
        Upstream IPv4             1 ( 1.00s)         2 ( 2.00s)        4 ( 4.00s)
        Upstream IPv6             1 ( 1.00s)         2 ( 2.00s)        4 ( 4.00s)
        Upstream IPv6PD           1 ( 1.00s)         2 ( 2.00s)        4 ( 4.00s)



JSON Reports
------------

A detailed JSON report is generated if enabled using the optional 
argument ``-J <filename>``.

.. code-block:: json
        
{
      "report": {
        "sessions": 1000,
        "sessions-pppoe": 1000,
        "sessions-ipoe": 0,
        "sessions-established": 1000,
        "sessions-flapped": 0,
        "setup-time-ms": 55661,
        "setup-rate-cps": 17.97,
        "setup-rate-cps-min": 15.01,
        "setup-rate-cps-avg": 18.03,
        "setup-rate-cps-max": 19.36,
        "dhcp-sessions-established": 0,
        "dhcpv6-sessions-established": 1000,
        "interfaces": [
          {
            "name": "SN-6-L1",
            "type": "Interface",
            "tx-packets": 111410,
            "tx-bytes": 12654727,
            "tx-polled": 0,
            "tx-io-error": 0,
            "rx-packets": 110161,
            "rx-bytes": 12300031,
            "rx-protocol-error": 0,
            "rx-unknown": 5,
            "rx-polled": 12300031,
            "rx-io-error": 0
          },
          {
            "name": "SN-5-L1",
            "type": "Interface",
            "tx-packets": 108580,
            "tx-bytes": 12360218,
            "tx-polled": 0,
            "tx-io-error": 0,
            "rx-packets": 106881,
            "rx-bytes": 11982029,
            "rx-protocol-error": 0,
            "rx-unknown": 5,
            "rx-polled": 11982029,
            "rx-io-error": 0
          },
          {
            "name": "SN-2-S1",
            "type": "Interface",
            "tx-packets": 197523,
            "tx-bytes": 21009053,
            "tx-polled": 0,
            "tx-io-error": 0,
            "rx-packets": 188259,
            "rx-bytes": 20425245,
            "rx-protocol-error": 0,
            "rx-unknown": 0,
            "rx-polled": 20425245,
            "rx-io-error": 0
          }
        ],
        "network-interfaces": [
          {
            "name": "SN-2-S1",
            "tx-packets": 197523,
            "tx-multicast-packets": 0,
            "rx-packets": 188259,
            "tx-stream-packets": 197340,
            "rx-stream-packets": 188120,
            "rx-stream-packets-loss": 0,
            "tx-session-packets-ipv4": 65784,
            "rx-session-packets-ipv4": 64537,
            "rx-session-packets-ipv4-loss": 0,
            "tx-session-packets-ipv4-avg-pps-max": 1000,
            "rx-session-packets-ipv4-avg-pps-max": 1000,
            "tx-session-packets-ipv6": 65784,
            "rx-session-packets-ipv6": 61793,
            "rx-session-packets-ipv6-loss": 0,
            "tx-session-packets-ipv6-avg-pps-max": 1000,
            "rx-session-packets-ipv6-avg-pps-max": 1000,
            "tx-session-packets-ipv6pd": 65772,
            "rx-session-packets-ipv6pd": 61790,
            "rx-session-packets-ipv6pd-loss": 0,
            "tx-session-packets-ipv6pd-avg-pps-max": 1000,
            "rx-session-packets-ipv6pd-avg-pps-max": 1000
          }
        ],
        "access-interfaces": [
          {
            "name": "SN-6-L1",
            "tx-packets": 111410,
            "rx-packets": 110156,
            "rx-multicast-packets": 0,
            "rx-multicast-packets-loss": 0,
            "tx-stream-packets": 99949,
            "rx-stream-packets": 97909,
            "rx-stream-packets-loss": 0,
            "tx-session-packets-ipv4": 33319,
            "rx-session-packets-ipv4": 32641,
            "rx-session-packets-ipv4-loss": 0,
            "rx-session-packets-ipv4-wrong-session": 0,
            "tx-session-packets-ipv4-avg-pps-max": 500,
            "rx-session-packets-ipv4-avg-pps-max": 500,
            "tx-session-packets-ipv6": 33319,
            "rx-session-packets-ipv6": 32635,
            "rx-session-packets-ipv6-loss": 0,
            "rx-session-packets-ipv6-wrong-session": 0,
            "tx-session-packets-ipv6-avg-pps-max": 500,
            "rx-session-packets-ipv6avg-pps-max": 500,
            "tx-session-packets-ipv6pd": 33311,
            "rx-session-packets-ipv6pd": 32633,
            "rx-session-packets-ipv6pd-loss": 0,
            "rx-session-packets-ipv6pd-wrong-session": 0,
            "tx-session-packets-ipv6pd-avg-pps-max": 500,
            "rx-session-packets-ipv6pd-avg-pps-max": 500,
            "protocol-stats": {
              "tx-arp": 0,
              "rx-arp": 0,
              "tx-padi": 1104,
              "rx-pado": 500,
              "tx-padr": 500,
              "rx-pads": 500,
              "tx-padt": 127,
              "rx-padt": 373,
              "tx-lcp": 4880,
              "rx-lcp": 4880,
              "tx-pap": 0,
              "rx-pap": 0,
              "tx-chap": 1700,
              "rx-chap": 1000,
              "tx-ipcp": 1500,
              "rx-ipcp": 1500,
              "tx-ip6cp": 1000,
              "rx-ip6cp": 1000,
              "tx-igmp": 0,
              "rx-igmp": 0,
              "tx-icmp": 0,
              "rx-icmp": 0,
              "tx-dhcp": 0,
              "rx-dhcp": 0,
              "tx-dhcpv6": 500,
              "rx-dhcpv6": 500,
              "tx-icmpv6": 1000,
              "rx-icmpv6": 1840,
              "rx-ipv4-fragmented": 0,
              "lcp-echo-timeout": 0,
              "lcp-request-timeout": 0,
              "ipcp-request-timeout": 0,
              "ip6cp-request-timeout": 0,
              "pap-timeout": 0,
              "chap-timeout": 350,
              "dhcp-timeout": 0,
              "dhcpv6-timeout": 0,
              "icmpv6-rs-timeout": 0
            }
          },
          {
            "name": "SN-5-L1",
            "tx-packets": 108580,
            "rx-packets": 106876,
            "rx-multicast-packets": 0,
            "rx-multicast-packets-loss": 0,
            "tx-stream-packets": 97391,
            "rx-stream-packets": 95685,
            "rx-stream-packets-loss": 0,
            "tx-session-packets-ipv4": 32465,
            "rx-session-packets-ipv4": 31896,
            "rx-session-packets-ipv4-loss": 0,
            "rx-session-packets-ipv4-wrong-session": 0,
            "tx-session-packets-ipv4-avg-pps-max": 500,
            "rx-session-packets-ipv4-avg-pps-max": 500,
            "tx-session-packets-ipv6": 32465,
            "rx-session-packets-ipv6": 31895,
            "rx-session-packets-ipv6-loss": 0,
            "rx-session-packets-ipv6-wrong-session": 0,
            "tx-session-packets-ipv6-avg-pps-max": 500,
            "rx-session-packets-ipv6avg-pps-max": 500,
            "tx-session-packets-ipv6pd": 32461,
            "rx-session-packets-ipv6pd": 31894,
            "rx-session-packets-ipv6pd-loss": 0,
            "rx-session-packets-ipv6pd-wrong-session": 0,
            "tx-session-packets-ipv6pd-avg-pps-max": 500,
            "rx-session-packets-ipv6pd-avg-pps-max": 500,
            "protocol-stats": {
              "tx-arp": 0,
              "rx-arp": 0,
              "tx-padi": 1102,
              "rx-pado": 500,
              "tx-padr": 844,
              "rx-pads": 500,
              "tx-padt": 78,
              "rx-padt": 422,
              "tx-lcp": 4343,
              "rx-lcp": 4343,
              "tx-pap": 822,
              "rx-pap": 500,
              "tx-chap": 0,
              "rx-chap": 0,
              "tx-ipcp": 1500,
              "rx-ipcp": 1500,
              "tx-ip6cp": 1000,
              "rx-ip6cp": 1000,
              "tx-igmp": 0,
              "rx-igmp": 0,
              "tx-icmp": 0,
              "rx-icmp": 0,
              "tx-dhcp": 0,
              "rx-dhcp": 0,
              "tx-dhcpv6": 500,
              "rx-dhcpv6": 500,
              "tx-icmpv6": 1000,
              "rx-icmpv6": 1816,
              "rx-ipv4-fragmented": 0,
              "lcp-echo-timeout": 0,
              "lcp-request-timeout": 0,
              "ipcp-request-timeout": 0,
              "ip6cp-request-timeout": 0,
              "pap-timeout": 322,
              "chap-timeout": 0,
              "dhcp-timeout": 0,
              "dhcpv6-timeout": 0,
              "icmpv6-rs-timeout": 0
            }
          }
        ],
        "session-traffic": {
          "config-ipv4-pps": 1,
          "config-ipv6-pps": 1,
          "config-ipv6pd-pps": 1,
          "total-flows": 6000,
          "verified-flows": 6000,
          "verified-flows-downstream-ipv4": 1000,
          "verified-flows-downstream-ipv6": 1000,
          "verified-flows-downstream-ipv6pd": 1000,
          "verified-flows-upstream-ipv4": 1000,
          "verified-flows-upstream-ipv6": 1000,
          "verified-flows-upstream-ipv6pd": 1000,
          "violated-flows-downstream-ipv4-3s": 200,
          "violated-flows-downstream-ipv6-3s": 206,
          "violated-flows-downstream-ipv6pd-3s": 197,
          "violated-flows-upstream-ipv4-3s": 200,
          "violated-flows-upstream-ipv6-3s": 206,
          "violated-flows-upstream-ipv6pd-3s": 197,
          "violated-flows-downstream-ipv4-2s": 224,
          "violated-flows-downstream-ipv6-2s": 218,
          "violated-flows-downstream-ipv6pd-2s": 227,
          "violated-flows-upstream-ipv4-2s": 224,
          "violated-flows-upstream-ipv6-2s": 218,
          "violated-flows-upstream-ipv6pd-2s": 227,
          "violated-flows-downstream-ipv4-1s": 199,
          "violated-flows-downstream-ipv6-1s": 200,
          "violated-flows-downstream-ipv6pd-1s": 200,
          "violated-flows-upstream-ipv4-1s": 199,
          "violated-flows-upstream-ipv6-1s": 200,
          "violated-flows-upstream-ipv6pd-1s": 200,
          "first-seq-rx-downstream-ipv4-min": 1,
          "first-seq-rx-downstream-ipv4-avg": 2,
          "first-seq-rx-downstream-ipv4-max": 4,
          "first-seq-rx-downstream-ipv6-min": 1,
          "first-seq-rx-downstream-ipv6-avg": 2,
          "first-seq-rx-downstream-ipv6-max": 4,
          "first-seq-rx-downstream-ipv6pd-min": 1,
          "first-seq-rx-downstream-ipv6pd-avg": 2,
          "first-seq-rx-downstream-ipv6pd-max": 4,
          "first-seq-rx-upstream-ipv4-min": 1,
          "first-seq-rx-upstream-ipv4-avg": 2,
          "first-seq-rx-upstream-ipv4-max": 4,
          "first-seq-rx-upstream-ipv6-min": 1,
          "first-seq-rx-upstream-ipv6-avg": 2,
          "first-seq-rx-upstream-ipv6-max": 4,
          "first-seq-rx-upstream-ipv6pd-min": 1,
          "first-seq-rx-upstream-ipv6pd-avg": 2,
          "first-seq-rx-upstream-ipv6pd-max": 4,
          "first-seq-rx-downstream-ipv4-min-seconds": 1,
          "first-seq-rx-downstream-ipv4-avg-seconds": 2,
          "first-seq-rx-downstream-ipv4-max-seconds": 4,
          "first-seq-rx-downstream-ipv6-min-seconds": 1,
          "first-seq-rx-downstream-ipv6-avg-seconds": 2,
          "first-seq-rx-downstream-ipv6-max-seconds": 4,
          "first-seq-rx-downstream-ipv6pd-min-seconds": 1,
          "first-seq-rx-downstream-ipv6pd-avg-seconds": 2,
          "first-seq-rx-downstream-ipv6pd-max-seconds": 4,
          "first-seq-rx-upstream-ipv4-min-seconds": 1,
          "first-seq-rx-upstream-ipv4-avg-seconds": 2,
          "first-seq-rx-upstream-ipv4-max-seconds": 4,
          "first-seq-rx-upstream-ipv6-min-seconds": 1,
          "first-seq-rx-upstream-ipv6-avg-seconds": 2,
          "first-seq-rx-upstream-ipv6-max-seconds": 4,
          "first-seq-rx-upstream-ipv6pd-min-seconds": 1,
          "first-seq-rx-upstream-ipv6pd-avg-seconds": 2,
          "first-seq-rx-upstream-ipv6pd-max-seconds": 4
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