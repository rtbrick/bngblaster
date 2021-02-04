# Reports

The BNG Blaster is able to generate detailed result reports 
at the end of of the test execution. 

## Standard Output Reports

```

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

Sessions PPPoE: 500 IPoE: 0
Sessions established: 500/500
DHCPv6 sessions established: 500
Setup Time: 396 ms
Setup Rate: 1262.63 CPS (MIN: 1262.63 AVG: 1262.63 MAX: 1262.63)
Flapped: 0

Network Interface ( eth2 ):
  TX:                     25503 packets
  RX:                     24254 packets
  TX Session:              8500 packets
  RX Session:              8248 packets (0 loss)
  TX Session IPv6:         8500 packets
  RX Session IPv6:         8000 packets (0 loss)
  TX Session IPv6PD:       8500 packets
  RX Session IPv6PD:       8000 packets (0 loss)
  TX Multicast:               0 packets
  RX Drop Unknown:            1 packets
  TX Encode Error:            0
  RX Decode Error:            0 packets
  TX Send Failed:             0
  TX No Buffer:               0
  TX Poll Kernel:             0
  RX Poll Kernel:          3932

Access Interface ( eth1 ):
  TX:                     33250 packets
  RX:                     34047 packets
  TX Session:              8500 packets
  RX Session:              8248 packets (0 loss, 0 wrong session)
  TX Session IPv6:         8500 packets
  RX Session IPv6:         8000 packets (0 loss, 0 wrong session)
  TX Session IPv6PD:       8500 packets
  RX Session IPv6PD:       8000 packets (0 loss, 0 wrong session)
  RX Multicast:               0 packets (0 loss)
  RX Drop Unknown:            1 packets
  TX Encode Error:        33250 packets
  RX Decode Error:            0 packets
  TX Send Failed:             0
  TX No Buffer:               0
  TX Poll Kernel:             0
  RX Poll Kernel:          3932

  Access Interface Protocol Packet Stats:
    ARP    TX:          0 RX:          0
    PADI   TX:        500 RX:          0
    PADO   TX:          0 RX:        500
    PADR   TX:        500 RX:          0
    PADS   TX:          0 RX:        500
    PADT   TX:          1 RX:        499
    LCP    TX:       2249 RX:       2249
    PAP    TX:        250 RX:        250
    CHAP   TX:        250 RX:        500
    IPCP   TX:       1500 RX:       1500
    IP6CP  TX:       1500 RX:       1500
    IGMP   TX:          0 RX:       1298
    ICMP   TX:          0 RX:          0
    ICMPv6 TX:        500 RX:        500
    DHCPv6 TX:        500 RX:        500

  Access Interface Protocol Timeout Stats:
    LCP Echo Request:          0
    LCP Request:               0
    IPCP Request:              0
    IP6CP Request:             0
    PAP:                       0
    CHAP:                      0
    ICMPv6 RS:                 0
    DHCPv6 Request:            0

Session Traffic:
  Config:
    IPv4    PPS:           1
    IPv6    PPS:           1
    IPv6PD  PPS:           1
  Verified Traffic Flows: 3000/3000
    Access  IPv4:        500
    Access  IPv6:        500
    Access  IPv6PD:      500
    Network IPv4:        500
    Network IPv6:        500
    Network IPv6PD:      500
  First Sequence Number Received:
    Access  IPv4    MIN:        1 MAX:        2
    Access  IPv6    MIN:        2 MAX:        2
    Access  IPv6PD  MIN:        2 MAX:        2
    Network IPv4    MIN:        1 MAX:        2
    Network IPv6    MIN:        2 MAX:        2
    Network IPv6PD  MIN:        2 MAX:        2
```

## JSON Reports

A detailed JSON report is generated if enabled using the optional argument `-J <filename>` 
as shown in the example below.  

```json
{
  "report": {
    "sessions": 500,
    "sessions-pppoe": 500,
    "sessions-ipoe": 0,
    "sessions-established": 500,
    "sessions-flapped": 0,
    "setup-time-ms": 396,
    "setup-rate-cps": 1263,
    "setup-rate-cps-min": 1263,
    "setup-rate-cps-avg": 1263,
    "setup-rate-cps-max": 1263,
    "dhcpv6-sessions-established": 500,
    "network-interfaces": [
      {
        "name": "eth2",
        "tx-packets": 25503,
        "rx-packets": 24254,
        "tx-session-packets": 8500,
        "rx-session-packets": 8248,
        "rx-session-packets-loss": 0,
        "tx-session-packets-avg-pps-max": 500,
        "rx-session-packets-avg-pps-max": 500,
        "tx-session-packets-ipv6": 8500,
        "rx-session-packets-ipv6": 8000,
        "rx-session-packets-ipv6-loss": 0,
        "tx-session-packets-avg-pps-max-ipv6": 500,
        "rx-session-packets-avg-pps-max-ipv6": 500,
        "tx-session-packets-ipv6pd": 8500,
        "rx-session-packets-ipv6pd": 8000,
        "rx-session-packets-ipv6pd-loss": 0,
        "tx-session-packets-avg-pps-max-ipv6pd": 500,
        "rx-session-packets-avg-pps-max-ipv6pd": 500,
        "tx-multicast-packets": 0
      }
    ],
    "access-interfaces": [
      {
        "name": "eth1",
        "tx-packets": 33250,
        "rx-packets": 34047,
        "tx-session-packets": 8500,
        "rx-session-packets": 8248,
        "rx-session-packets-loss": 0,
        "rx-session-packets-wrong-session": 0,
        "tx-session-packets-avg-pps-max": 500,
        "rx-session-packets-avg-pps-max": 500,
        "tx-session-packets-ipv6": 8500,
        "rx-session-packets-ipv6": 8000,
        "rx-session-packets-ipv6-loss": 0,
        "rx-session-packets-ipv6-wrong-session": 0,
        "tx-session-packets-avg-pps-max-ipv6": 500,
        "rx-session-packets-avg-pps-max-ipv6": 500,
        "tx-session-packets-ipv6pd": 8500,
        "rx-session-packets-ipv6pd": 8000,
        "rx-session-packets-ipv6pd-loss": 0,
        "rx-session-packets-ipv6pd-wrong-session": 0,
        "tx-session-packets-avg-pps-max-ipv6pd": 500,
        "rx-session-packets-avg-pps-max-ipv6pd": 500,
        "rx-multicast-packets": 0,
        "rx-multicast-packets-loss": 0,
        "protocol-stats": {
          "arp-tx": 0,
          "arp-rx": 0,
          "padi-tx": 500,
          "pado-rx": 500,
          "padr-tx": 500,
          "pads-rx": 500,
          "padt-tx": 1,
          "padt-rx": 499,
          "lcp-tx": 2249,
          "lcp-rx": 2249,
          "pap-tx": 250,
          "pap-rx": 250,
          "chap-tx": 250,
          "chap-rx": 500,
          "ipcp-tx": 1500,
          "ipcp-rx": 1500,
          "ip6cp-tx": 1500,
          "ip6cp-rx": 1500,
          "igmp-tx": 0,
          "igmp-rx": 1298,
          "icmp-tx": 0,
          "icmp-rx": 0,
          "icmpv6-tx": 500,
          "icmpv6-rx": 500,
          "dhcpv6-tx": 500,
          "dhcpv6-rx": 500,
          "lcp-echo-timeout": 0,
          "lcp-request-timeout": 0,
          "ipcp-request-timeout": 0,
          "ip6cp-request-timeout": 0,
          "pap-timeout": 0,
          "chap-timeout": 0,
          "icmpv6-rs-timeout": 0,
          "dhcpv6-timeout": 0
        }
      }
    ],
    "session-traffic": {
      "config-ipv4-pps": 1,
      "config-ipv6-pps": 1,
      "config-ipv6pd-pps": 1,
      "total-flows": 3000,
      "verified-flows": 3000,
      "verified-flows-access-ipv4": 500,
      "verified-flows-access-ipv6": 500,
      "verified-flows-access-ipv6pd": 500,
      "verified-flows-network-ipv4": 500,
      "verified-flows-network-ipv6": 500,
      "verified-flows-network-ipv6pd": 500,
      "first-seq-rx-access-ipv4-min": 1,
      "first-seq-rx-access-ipv4-max": 2,
      "first-seq-rx-access-ipv6-min": 2,
      "first-seq-rx-access-ipv6-max": 2,
      "first-seq-rx-access-ipv6pd-min": 2,
      "first-seq-rx-access-ipv6pd-max": 2,
      "first-seq-rx-network-ipv4-min": 1,
      "first-seq-rx-network-ipv4-max": 2,
      "first-seq-rx-network-ipv6-min": 2,
      "first-seq-rx-network-ipv6-max": 2,
      "first-seq-rx-network-ipv6pd-min": 2,
      "first-seq-rx-network-ipv6pd-max": 2
    }
  }
}
```

## Interface Statistics

## Session Traffic Statistics

Those statistics are related to the test traffic send between PPPoE sessions
and the network interface.  

Flow | Description  
---- | -----------
Access RX | Network traffic received on access interface (downstream)
Access TX | Network traffic send from access interface (Upstream)
Network RX | Access traffic received on network interface (Upstream)
Network TX | Access traffic send from network interface (downstream)

### Verified Traffic Flows

Counts the verified traffic flows per type and direction.

The `Access IPv4` tells how many sessions have successfully received
session verification traffic IPv4 traffic on the access interface. Similar
for IPv6 or IPv6PD (prefix delegation). Session verification traffic received 
on the network interface is counted similar using the `Network IP...` statistics. 

Assuming session traffic is enabled for IPv4, IPv6 and IPv6PD, in this case 
all statics should be equal matching the number of sessions. 

*Example report output for 100 sessions:*
```
Session Traffic:
  Config:
    IPv4    PPS:           1
    IPv6    PPS:           1
    IPv6PD  PPS:           1
  Verified Traffic Flows: 3000/3000
    Access  IPv4:        500
    Access  IPv6:        500
    Access  IPv6PD:      500
    Network IPv4:        500
    Network IPv6:        500
    Network IPv6PD:      500
  First Sequence Number Received:
    Access  IPv4    MIN:        1 MAX:        2
    Access  IPv6    MIN:        2 MAX:        2
    Access  IPv6PD  MIN:        2 MAX:        2
    Network IPv4    MIN:        1 MAX:        2
    Network IPv6    MIN:        2 MAX:        2
    Network IPv6PD  MIN:        2 MAX:        2
```

JSON:
```json
{
    "session-traffic": {
      "config-ipv4-pps": 1,
      "config-ipv6-pps": 1,
      "config-ipv6pd-pps": 1,
      "total-flows": 3000,
      "verified-flows": 3000,
      "verified-flows-access-ipv4": 500,
      "verified-flows-access-ipv6": 500,
      "verified-flows-access-ipv6pd": 500,
      "verified-flows-network-ipv4": 500,
      "verified-flows-network-ipv6": 500,
      "verified-flows-network-ipv6pd": 500,
      "first-seq-rx-access-ipv4-min": 1,
      "first-seq-rx-access-ipv4-max": 2,
      "first-seq-rx-access-ipv6-min": 2,
      "first-seq-rx-access-ipv6-max": 2,
      "first-seq-rx-access-ipv6pd-min": 2,
      "first-seq-rx-access-ipv6pd-max": 2,
      "first-seq-rx-network-ipv4-min": 1,
      "first-seq-rx-network-ipv4-max": 2,
      "first-seq-rx-network-ipv6-min": 2,
      "first-seq-rx-network-ipv6-max": 2,
      "first-seq-rx-network-ipv6pd-min": 2,
      "first-seq-rx-network-ipv6pd-max": 2
    }
}
```

### First Sequence Number Received

If session traffic is enabled, the BNG Blaster will start sending bidirectional 
traffic between PPPoE session and network interface as soon as the session is 
established using the rate as configured starting with sequence number 1 for 
each flow. 

*Example config output with 1 packet per second:*
```json
{
    "session-traffic": {
        "ipv4-pps": 1,
        "ipv6-pps": 1,
        "ipv6pd-pps": 1
    }
}
```

Assuming the first sequence number received for given flow is 5 
combined with a rate of 1 PPS would mean that it took between 4 
and 5 seconds until forwarding is working. 

*Example report output with 1 packet per second:*
```
STDOUT:

  First Sequence Number Received:
    Access  IPv4    MIN:        1 MAX:        1
    Access  IPv6    MIN:        1 MAX:        1
    Access  IPv6PD  MIN:        1 MAX:        1
    Network IPv4    MIN:        1 MAX:        1
    Network IPv6    MIN:        1 MAX:        1
    Network IPv6PD  MIN:        1 MAX:        1
```
JSON:
```json
{
      "first-seq-rx-access-ipv4-min": 1,
      "first-seq-rx-access-ipv4-max": 1,
      "first-seq-rx-access-ipv6-min": 1,
      "first-seq-rx-access-ipv6-max": 1,
      "first-seq-rx-access-ipv6pd-min": 1,
      "first-seq-rx-access-ipv6pd-max": 1,
      "first-seq-rx-network-ipv4-min": 1,
      "first-seq-rx-network-ipv4-max": 1,
      "first-seq-rx-network-ipv6-min": 1,
      "first-seq-rx-network-ipv6-max": 1,
      "first-seq-rx-network-ipv6pd-min": 1,
      "first-seq-rx-network-ipv6pd-max": 1
}
```
