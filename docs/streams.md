# Traffic Streams

Traffic streams allow to test QoS using BNG Blaster. 

## Configuration

```json
{
    "interfaces": {
        "tx-interval": 0.1,
        "rx-interval": 0.1,
        "io-slots": 2048,
        "network": {
            "interface": "eth2",
            "address": "10.0.0.1",
            "gateway": "10.0.0.2",
            "address-ipv6": "fc66:1337:7331::1",
            "gateway-ipv6": "fc66:1337:7331::2"
        },
        "access": [
        {
            "interface": "eth1",
            "outer-vlan-min": 1000,
            "outer-vlan-max": 1000,
            "inner-vlan-min": 7,
            "inner-vlan-max": 7,
            "stream-group-id": 1
        },
        {
            "interface": "eth1",
            "outer-vlan-min": 1001,
            "outer-vlan-max": 4000,
            "inner-vlan-min": 7,
            "inner-vlan-max": 7,
            "stream-group-id": 2 
        }
     ]  
    },
    "sessions": {
        "count": 100
    },
    "pppoe": {
        "host-uniq": true,
        "vlan-priority": 6
    },
    "ppp": {
        "mru": 1492,
        "authentication": {
            "username": "user{session-global}@rtbrick.com",
            "password": "test",
            "timeout": 5,
            "retry": 30
        },
        "ipcp": {
            "enable": true
        },
        "ip6cp": {
            "enable": true
        }
    },
    "dhcpv6": {
        "enable": true,
        "rapid-commit": true
    },
    "access-line": {
        "agent-remote-id": "DEU.RTBRICK.{session-global}",
        "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:{session-global}",
        "rate-up": 1024,
        "rate-down": 16384,
        "dsl-type": 5
    },
    "streams": [
        {
            "name": "BestEffort",
            "stream-group-id": 1,
            "type": "ipv4", 
            "direction": "both",
            "length": 1000,
            "pps": 1000
        },
        {
            "name": "Voice",
            "stream-group-id": 1,
            "type": "ipv4", 
            "direction": "downstream",
            "priority": 128,
            "vlan-priority": 2,
            "network-ipv4-address": "10.0.0.10",
            "length": 1000,
            "pps": 100
        },
        {
            "name": "BestEffort",
            "stream-group-id": 2,
            "type": "ipv4", 
            "direction": "both",
            "length": 1000,
            "pps": 1
        }
    ]
}
```

## Check Session Stream Information

The `session-streams` command returns detailed stream statistics per session. 

`$ sudo ./cli.py run.sock session-streams session-id 1`
```json
{
    "status": "ok",
    "code": 200,
    "session-streams": {
        "session-id": 1,
        "rx-packets": 59670,
        "tx-packets": 54610,
        "rx-accounting-packets": 59655,
        "tx-accounting-packets": 0,
        "rx-pps": 1100,
        "tx-pps": 1000,
        "rx-bps-l2": 9028800,
        "tx-bps-l2": 8240000,
        "rx-mbps-l2": 9.0288,
        "tx-mbps-l2": 8.24,
        "streams": [
            {
                "name": "BestEffort",
                "direction": "upstream",
                "flow-id": 1,
                "rx-first-seq": 362,
                "rx-last-seq": 54593,
                "rx-tos-tc": 0,
                "rx-outer-vlan-pbit": 0,
                "rx-inner-vlan-pbit": 0,
                "rx-len": 1014,
                "tx-len": 1030,
                "rx-packets": 54232,
                "tx-packets": 54594,
                "rx-loss": 0,
                "rx-delay-nsec-min": 37650,
                "rx-delay-nsec-max": 98595049,
                "rx-pps": 1000,
                "tx-pps": 1000,
                "tx-bps-l2": 8240000,
                "rx-bps-l2": 8112000,
                "rx-bps-l3": 8000000,
                "tx-mbps-l2": 8.24,
                "rx-mbps-l2": 8.112,
                "rx-mbps-l3": 8.0
            },
            {
                "name": "BestEffort",
                "direction": "downstream",
                "flow-id": 2,
                "rx-first-seq": 362,
                "rx-last-seq": 54593,
                "rx-tos-tc": 0,
                "rx-outer-vlan-pbit": 0,
                "rx-inner-vlan-pbit": 0,
                "rx-len": 1026,
                "tx-len": 1014,
                "rx-packets": 54232,
                "tx-packets": 54594,
                "rx-loss": 0,
                "rx-delay-nsec-min": 43550,
                "rx-delay-nsec-max": 98903960,
                "rx-pps": 1000,
                "tx-pps": 1000,
                "tx-bps-l2": 8112000,
                "rx-bps-l2": 8208000,
                "rx-bps-l3": 8000000,
                "tx-mbps-l2": 8.112,
                "rx-mbps-l2": 8.208,
                "rx-mbps-l3": 8.0
            },
            {
                "name": "Voice",
                "direction": "downstream",
                "flow-id": 3,
                "rx-first-seq": 37,
                "rx-last-seq": 5458,
                "rx-tos-tc": 128,
                "rx-outer-vlan-pbit": 0,
                "rx-inner-vlan-pbit": 0,
                "rx-len": 1026,
                "tx-len": 1014,
                "rx-packets": 5422,
                "tx-packets": 5458,
                "rx-loss": 0,
                "rx-delay-nsec-min": 41700,
                "rx-delay-nsec-max": 96548542,
                "rx-pps": 100,
                "tx-pps": 100,
                "tx-bps-l2": 811200,
                "rx-bps-l2": 820800,
                "rx-bps-l3": 800000,
                "tx-mbps-l2": 0.8112,
                "rx-mbps-l2": 0.8208,
                "rx-mbps-l3": 0.8
            }
        ]
    }
}
```

The `rx-outer-vlan-pbit` might be wrong depending on network interface driver and 
optional VLAN offloading. 

The measured `rx-delay-nsec-min/max` depends also on the actual test environment 
and maximum host IO delay.

## Start/Stop Session Stream Information

Session stream traffic can be started/stopped dynamically
using the commands `stream-traffic-enabled` and `stream-traffic-disabled`.

`$ sudo ./cli.py run.sock stream-traffic-disabled session-id 1`

Those commands start/stop the traffic for all sessions if invoked without
session identifier. 

`$ sudo ./cli.py run.sock stream-traffic-disabled`

