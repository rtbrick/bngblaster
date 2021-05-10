# IPoE

The BNG Blaster is able to emulate IP over Ethernet (IPoE)
subscribers with static and dynamic address assignment 
supporting 1:1 and N:1 VLAN mode. 

**INFO**: Currently there is only IPv4 support for IPoE. 

## Static Addresses

Static addresses means that the IP address and gateway is assigned
statically as shown in the example below.

```json
{
    "interfaces": {
        "access": [
        {
            "interface": "eth1",
            "type": "ipoe",
            "vlan-mode": "1:1",
            "outer-vlan-min": 128,
            "outer-vlan-max": 4000,
            "address": "200.0.0.1",
            "address-iter": "0.0.0.4",
            "gateway": "200.0.0.2",
            "gateway-iter": "0.0.0.4",
        }
     ]
    }
}
```

## DHCP 

The most common case for IPoE is using DHCP as shown below. 

```json
{
    "interfaces": {
        "access": [
        {
            "interface": "eth1",
            "type": "ipoe",
            "outer-vlan": 7,
            "vlan-mode": "N:1"
        }
     ]  
    },
    "dhcp": {
        "enable": true,
    },
    "access-line": {
        "agent-remote-id": "DEU.RTBRICK.{session-global}",
        "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:{session-global}"
    }
}
```

`$ sudo ./cli.py run.sock session-info session-id 1`
```json
{
    "status": "ok",
    "code": 200,
    "session-information": {
        "type": "ipoe",
        "session-id": 1,
        "session-state": "Established",
        "interface": "veth2",
        "outer-vlan": 0,
        "inner-vlan": 0,
        "mac": "02:00:00:00:00:01",
        "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:1",
        "agent-remote-id": "DEU.RTBRICK.1",
        "ipv4-address": "100.0.0.100",
        "ipv4-netmask": "255.255.255.0",
        "ipv4-gateway": "100.0.0.1",
        "dhcp-state": "Bound",
        "dhcp-server": "100.0.0.1",
        "dhcp-lease-time": 60,
        "dhcp-lease-expire": 59,
        "dhcp-lease-expire-t1": 29,
        "dhcp-lease-expire-t2": 51,
        "dhcp-tx-discover": 1,
        "dhcp-tx-request": 2,
        "dhcp-tx-release": 0,
        "dhcp-rx-offer": 1,
        "dhcp-rx-ack": 2,
        "dhcp-rx-nak": 0,
        "tx-packets": 8,
        "rx-packets": 11,
        "rx-fragmented-packets": 0
    }
}
```