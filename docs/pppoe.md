# PPPoE

Emulating PPP over Ethernet (PPPoE) sessions was initial
use case of the BNG Blaster supporting 1:1 and N:1 VLAN
mode.

Following a basic PPPoE configuration example which is 
detailed explained in the configuration section.

```json
{
    "interfaces": {
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
                "type": "pppoe",
                "outer-vlan-min": 1000,
                "outer-vlan-max": 1999,
                "inner-vlan-min": 1,
                "inner-vlan-max": 4049,
                "authentication-protocol": "PAP"
            },
            {
                "interface": "eth1",
                "type": "pppoe",
                "outer-vlan-min": 2000,
                "outer-vlan-max": 2999,
                "inner-vlan-min": 1,
                "inner-vlan-max": 4049,
                "authentication-protocol": "CHAP"
            }
        ]
    },
    "sessions": {
        "count": 1000,
        "session-time": 0,
        "max-outstanding": 800,
        "start-rate": 400,
        "stop-rate": 400
    },
    "pppoe": {
        "reconnect": true,
        "discovery-timeout": 3,
        "discovery-retry": 10
    },
    "ppp": {
        "mru": 1492,
        "authentication": {
            "username": "user{session-global}@rtbrick.com",
            "password": "test",
            "timeout": 5,
            "retry": 30
        },
        "lcp": {
            "conf-request-timeout": 1,
            "conf-request-retry": 10,
            "keepalive-interval": 30,
            "keepalive-retry": 3
        },
        "ipcp": {
            "enable": true,
            "request-ip": true,
            "request-dns1": true,
            "request-dns2": true,
            "conf-request-timeout": 1,
            "conf-request-retry": 10
        },
        "ip6cp": {
            "enable": true,
            "conf-request-timeout": 1,
            "conf-request-retry": 10
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
        "rate-down": 16384
    },
    "session-traffic": {
        "ipv4-pps": 1,
        "ipv6-pps": 1,
        "ipv6pd-pps": 1
    }
}
```

The control socket command `session-info session-id <id>` provides
detailed information for IPOE sessions. 

`$ sudo bngblaster-cli run.sock session-info session-id 1 | jq .`
```json
{
    "status": "ok",
    "code": 200,
    "session-information": {
        "type": "pppoe",
        "session-id": 1,
        "session-state": "Established",
        "interface": "eth1",
        "outer-vlan": 1000,
        "inner-vlan": 1,
        "mac": "02:00:00:00:00:01",
        "username": "user1@rtbrick.com",
        "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:1",
        "agent-remote-id": "DEU.RTBRICK.1",
        "lcp-state": "Opened",
        "ipcp-state": "Opened",
        "ip6cp-state": "Opened",
        "ipv4-address": "10.100.128.0",
        "ipv4-dns1": "10.0.0.3",
        "ipv4-dns2": "10.0.0.4",
        "ipv6-prefix": "fc66:1000:1::/64",
        "ipv6-delegated-prefix": "fc66:2000::/56",
        "ipv6-dns1": "fc66::3",
        "ipv6-dns2": "fc66::4",
        "dhcpv6-state": "Bound",
        "dhcpv6-dns1": "fc66::3",
        "dhcpv6-dns2": "fc66::4",
        "tx-packets": 10036,
        "rx-packets": 10083,
        "rx-fragmented-packets": 0,
        "session-traffic": {
            "total-flows": 6,
            "verified-flows": 6,
            "first-seq-rx-access-ipv4": 2,
            "first-seq-rx-access-ipv6": 3,
            "first-seq-rx-access-ipv6pd": 3,
            "first-seq-rx-network-ipv4": 2,
            "first-seq-rx-network-ipv6": 3,
            "first-seq-rx-network-ipv6pd": 3,
            "access-tx-session-packets": 3266,
            "access-rx-session-packets": 3265,
            "access-rx-session-packets-loss": 0,
            "network-tx-session-packets": 3266,
            "network-rx-session-packets": 3265,
            "network-rx-session-packets-loss": 0,
            "access-tx-session-packets-ipv6": 3266,
            "access-rx-session-packets-ipv6": 3264,
            "access-rx-session-packets-ipv6-loss": 0,
            "network-tx-session-packets-ipv6": 3266,
            "network-rx-session-packets-ipv6": 3264,
            "network-rx-session-packets-ipv6-loss": 0,
            "access-tx-session-packets-ipv6pd": 3266,
            "access-rx-session-packets-ipv6pd": 3264,
            "access-rx-session-packets-ipv6pd-loss": 0,
            "network-tx-session-packets-ipv6pd": 3266,
            "network-rx-session-packets-ipv6pd": 3264,
            "network-rx-session-packets-ipv6pd-loss": 0
        }
    }
}
```