# L2TPv2

The BNG Blaster is able to emulate L2TPv2 (RFC2661) LNS servers to 
be able to test the L2TPv2 LAC functionality of the BNG device under 
test. 

## Configuration

Following an example with 30 L2TP LNS servers.

```json
{
    "interfaces": {
        "network": {
            "interface": "eth2",
            "address": "10.0.0.1",
            "gateway": "10.0.0.2",
            "address-ipv6": "fc66:1337:7331:8::10",
            "gateway-ipv6": "fc66:1337:7331:8::1"
        },
        "access": [
            {
                "interface": "eth1",
                "outer-vlan-min": 1,
                "outer-vlan-max": 4000,
                "inner-vlan-min": 7,
                "inner-vlan-max": 7,
                "authentication-protocol": "PAP"
            },
            {
                "interface": "eth1",
                "outer-vlan-min": 1,
                "outer-vlan-max": 4000,
                "inner-vlan-min": 8,
                "inner-vlan-max": 8,
                "authentication-protocol": "CHAP"
            }
        ]
    },
    "pppoe": {
        "reconnect": true,
        "discovery-timeout": 3,
        "discovery-retry": 10
    },
    "ppp": {
        "mru": 1492,
        "authentication": {
            "username": "blaster@l2tp.de",
            "password": "test",
            "timeout": 1,
            "retry": 60
        },
        "lcp": {
            "conf-request-timeout": 5,
            "conf-request-retry": 30,
            "keepalive-interval": 30,
            "keepalive-retry": 3
        },
        "ipcp": {
            "enable": true
        },
        "ip6cp": {
            "enable": true
        }
    },
    "access-line": {
        "agent-remote-id": "DEU.RTBRICK.{session}",
        "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:{session}",
        "rate-up": 1024,
        "rate-down": 16384
    },
    "l2tp-server": [
        {
            "name": "LNS1",
            "address": "10.0.0.11",
            "secret": "test1",
            "receive-window-size": 8
        },
        {
            "name": "LNS2",
            "address": "10.0.0.12",
            "secret": "test2",
            "receive-window-size": 8
        },
        {
            "name": "LNS3",
            "address": "10.0.0.13",
            "secret": "test3",
            "receive-window-size": 8
        },
        {
            "name": "LNS4",
            "address": "10.0.0.14",
            "secret": "test4",
            "receive-window-size": 8
        },
        {
            "name": "LNS5",
            "address": "10.0.0.15",
            "secret": "test5",
            "receive-window-size": 8
        },
        {
            "name": "LNS6",
            "address": "10.0.0.16",
            "secret": "test6",
            "receive-window-size": 8
        },
        {
            "name": "LNS7",
            "address": "10.0.0.17",
            "secret": "test7",
            "receive-window-size": 8
        },
        {
            "name": "LNS8",
            "address": "10.0.0.18",
            "secret": "test8",
            "receive-window-size": 8
        },
        {
            "name": "LNS9",
            "address": "10.0.0.19",
            "secret": "test9",
            "receive-window-size": 8
        },
        {
            "name": "LNS10",
            "address": "10.0.0.20",
            "secret": "test10",
            "receive-window-size": 8
        },
        {
            "name": "LNS11",
            "address": "10.0.0.21",
            "secret": "test11",
            "receive-window-size": 8
        },
        {
            "name": "LNS12",
            "address": "10.0.0.22",
            "secret": "test12",
            "receive-window-size": 8
        },
        {
            "name": "LNS13",
            "address": "10.0.0.23",
            "secret": "test13",
            "receive-window-size": 8
        },
        {
            "name": "LNS14",
            "address": "10.0.0.24",
            "secret": "test14",
            "receive-window-size": 8
        },
        {
            "name": "LNS15",
            "address": "10.0.0.25",
            "secret": "test15",
            "receive-window-size": 8
        },
        {
            "name": "LNS16",
            "address": "10.0.0.26",
            "secret": "test16",
            "receive-window-size": 8
        },
        {
            "name": "LNS17",
            "address": "10.0.0.27",
            "secret": "test17",
            "receive-window-size": 8
        },
        {
            "name": "LNS18",
            "address": "10.0.0.28",
            "secret": "test18",
            "receive-window-size": 8
        },
        {
            "name": "LNS19",
            "address": "10.0.0.29",
            "secret": "test19",
            "receive-window-size": 8
        },
        {
            "name": "LNS20",
            "address": "10.0.0.30",
            "secret": "test20",
            "receive-window-size": 8
        },
        {
            "name": "LNS21",
            "address": "10.0.0.31",
            "secret": "test21",
            "receive-window-size": 8
        },
        {
            "name": "LNS22",
            "address": "10.0.0.32",
            "secret": "test22",
            "receive-window-size": 8
        },
        {
            "name": "LNS23",
            "address": "10.0.0.33",
            "secret": "test23",
            "receive-window-size": 8
        },
        {
            "name": "LNS24",
            "address": "10.0.0.34",
            "secret": "test24",
            "receive-window-size": 8
        },
        {
            "name": "LNS25",
            "address": "10.0.0.35",
            "secret": "test25",
            "receive-window-size": 8
        },
        {
            "name": "LNS26",
            "address": "10.0.0.36",
            "secret": "test26",
            "receive-window-size": 8
        },
        {
            "name": "LNS27",
            "address": "10.0.0.37",
            "secret": "test27",
            "receive-window-size": 8
        },
        {
            "name": "LNS28",
            "address": "10.0.0.38",
            "secret": "test28",
            "receive-window-size": 8
        },
        {
            "name": "LNS29",
            "address": "10.0.0.39",
            "secret": "test29",
            "receive-window-size": 8
        },
        {
            "name": "LNS30",
            "address": "10.0.0.40",
            "secret": "test30",
            "receive-window-size": 8
        }
    ],
    "session-traffic": {
        "autostart": true,
        "ipv4-pps": 1
    }
}
```

## Receive Tunnel Information

`$ sudo ./cli.py run.sock l2tp-tunnels`
```json
{
    "status": "ok",
    "code": 200,
    "l2tp-tunnels": [
        {
            "state": "Established",
            "server-name": "LNS1",
            "server-address": "10.0.0.11",
            "tunnel-id": 1,
            "peer-tunnel-id": 50011,
            "peer-name": "BNG",
            "peer-address": "10.0.0.2",
            "peer-vendor": "RtBrick, Inc.",
            "secret": "test1",
            "control-packets-rx": 102,
            "control-packets-rx-dup": 0,
            "control-packets-rx-out-of-order": 0,
            "control-packets-tx": 102,
            "control-packets-tx-retry": 0,
            "data-packets-rx": 1406,
            "data-packets-tx": 206
        }
    ]
}
```

## Receive Session Information

The `l2tp-sessions` command returns all L2TP sessions. 

`$ sudo ./cli.py run.sock l2tp-sessions`
```json
{
    "status": "ok",
    "code": 200,
    "l2tp-sessions": [
        {
            "state": "Established",
            "tunnel-id": 1,
            "session-id": 1,
            "peer-tunnel-id": 50011,
            "peer-session-id": 32867,
            "peer-proxy-auth-name": "blaster@l2tp.de",
            "peer-called-number": "N/A",
            "peer-calling-number": "N/A",
            "peer-sub-address": "N/A",
            "peer-tx-bps": 48000,
            "peer-rx-bps": 1000,
            "peer-ari": "DEU.RTBRICK.1",
            "peer-aci": "0.0.0.0/0.0.0.0 eth 0:1",
            "data-packets-rx": 79,
            "data-packets-tx": 79,
            "data-ipv4-packets-rx": 15,
            "data-ipv4-packets-tx": 15
        }
    ]
}
```

This output can be also filtered to return only sessions
of a given tunnel. 

`sudo ./cli.py run.sock l2tp-sessions tunnel-id 1` 

It is also possible to display a single session. 

`$ sudo ./cli.py run.sock l2tp-sessions tunnel-id 1 session-id 1`

## RFC5515 

The Agent-Circuit-Id and Agent-Remote-Id AVP defined in RFC5515
is supported and stored for each session if received. Received
CSUN messages are processed correctly and via control socket it
is possible to send also CSURQ requests to the LAC. 

## Variable Data Header

The L2TP protocol allows different data header options resulting in 
variable header lengths. The most common options can be tested with just 
four servers as shown in the example below. 

```json
{
    "l2tp-server": [
        {
            "name": "LNS1",
            "address": "10.0.0.11",
            "secret": "test1",
            "receive-window-size": 8,
            "congestion-mode": "default",
            "data-control-priority": true
        },
        {
            "name": "LNS2",
            "address": "10.0.0.12",
            "secret": "test2",
            "receive-window-size": 8,
            "congestion-mode": "default",
            "data-control-priority": true,
            "data-length": true
        },
        {
            "name": "LNS3",
            "address": "10.0.0.11",
            "secret": "test3",
            "receive-window-size": 8,
            "congestion-mode": "default",
            "data-control-priority": true,
            "data-offset": true
        },
        {
            "name": "LNS4",
            "address": "10.0.0.12",
            "secret": "test4",
            "receive-window-size": 8,
            "congestion-mode": "default",
            "data-control-priority": true,
            "data-length": true,
            "data-offset": true
        }
    ]
}
```