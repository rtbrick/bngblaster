# BGP

The Border Gateway Protocol (BGP) is a standardized exterior gateway protocol
designed to exchange routing and reachability information among autonomous systems
(AS) on the internet. BGP is classified as a path-vector routing protocol, and it 
makes routing decisions based on paths, network policies, or rule-sets configured 
by a network administrator.

Following an example ISIS configuration with one instance 
attached to two network interfaces.

```json
{
    "interfaces": {
        "network": [
            {
                "interface": "eth1",
                "address": "10.0.1.2/24",
                "gateway": "10.0.1.1"
            }
        ]
    },
    "bgp": [
        {
            "local-ipv4-address": "10.0.1.2",
            "peer-ipv4-address": "10.0.1.1",
            "raw-update-file": "test.bgp",
            "local-as": 65001,
            "peer-as": 65001
        }
    ]
}
```

## Limitations

Currently only IPv4 sessions are supported.

## RAW Update Files

The BNG Blaster is able to inject BGP update messages 
from a pre-compiled RAW update file into the defined 
session. 


