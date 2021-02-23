# Legal Interception (LI)

The BNG Blaster can be used to emulate a mediation device providing detailed statistics
about the received flows. Today only the BCM QMX LI header format is supported but further
headers can be easily integrated. 

*BCM QMX LI Header Format*
```
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| D   | PT    | SPT | LIID                                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The functionality is automatically enabled on the network interface
and works combined with sessions in one instance or as standalone 
mediation device as shown in the following example. 

```json
{
    "interfaces": {
        "tx-interval": 10,
        "rx-interval": 1,
        "network": {
            "interface": "eth2",
            "address": "100.0.0.10",
            "gateway": "100.0.0.2"
        }
    }
}

The received flows can be queried using the control socket. 

`$ sudo ./cli.py run.sock li-flows`
```json
{
    "status": "ok",
    "code": 200,
    "li-flows": [
        {
            "source-address": "1.1.1.1",
            "source-port": 49152,
            "destination-address": "1.1.1.2",
            "destination-port": 49152,
            "direction": "downstream",
            "packet-type": "ethernet",
            "sub-packet-type": "double-tagged",
            "liid": 4194301,
            "bytes-rx": 94,
            "packets-rx": 1,
            "packets-rx-ipv4": 0,
            "packets-rx-ipv4-tcp": 0,
            "packets-rx-ipv4-udp": 0,
            "packets-rx-ipv4-host-internal": 0
        },
        {
            "source-address": "1.1.1.1",
            "source-port": 49152,
            "destination-address": "1.1.1.2",
            "destination-port": 49152,
            "direction": "upstream",
            "packet-type": "ethernet",
            "sub-packet-type": "double-tagged",
            "liid": 4194301,
            "bytes-rx": 160720,
            "packets-rx": 820,
            "packets-rx-ipv4": 820,
            "packets-rx-ipv4-tcp": 0,
            "packets-rx-ipv4-udp": 0,
            "packets-rx-ipv4-host-internal": 820
        }
    ]
}
```

The `packets-rx-ipv4-host-internal` refers to the IPv4 protocol number 61 (any host internal protocol)
which is used by some network testers as default type for traffic streams. 