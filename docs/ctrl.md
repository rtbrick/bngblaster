# Control Socket

The control socket is an unix domain stream socket which allows the control daemon to 
interact with the BNG Blaster using JSON RPC. This interface was primary developed for
then BNG Blaster Controller but can be also used manually or by other tools like the 
simple CLI tool (`cli.py`) for interactive communication with the BNG Blaster. 

The control socket will be optionally enabled by providing the path to the socket file 
using the argument `-S` (`bngblaster -S test.socket`).

`$ cat command.json | jq .`
```json
{
  "command": "session-counters"
}
```
`$ cat command.json | sudo nc -U test.socket | jq .`
```json
{
    "status": "ok",
    "code": 200,
    "session-counters": {
        "sessions": 3,
        "sessions-established": 3,
        "sessions-flapped": 3,
        "dhcpv6-sessions-established": 3
    }
}
```

Each request must contain at least the `command` element which carries 
the actual command which is invoked with optional arguments. 

`$ cat command.json | jq .`
```json
{
    "command": "session-info",
    "arguments": {
        "outer-vlan": 1,
        "inner-vlan": 1
    }
}
```

`$ cat command.json | sudo nc -U test.socket | jq .`
```json
{
    "status": "ok",
    "code": 200,
    "session-information": {
        "type": "pppoe",
        "username": "local@rtbrick.com",
        "agent-circuit-id": "0.0.0.0/0.0.0.0 eth 0:1",
        "agent-remote-id": "DEU.RTBRICK.1",
        "session-state": "Established",
        "lcp-state": "Opened",
        "ipcp-state": "Closed",
        "ip6cp-state": "Opened",
        "ipv6-prefix": "fc66:1337:0:8::/64",
        "ipv6-delegated-prefix": "fc66:1338:0:800::/56",
        "session-traffic": {
            "first-seq-rx-access-ipv4": 0,
            "first-seq-rx-access-ipv6": 1,
            "first-seq-rx-access-ipv6pd": 1,
            "first-seq-rx-network-ipv4": 0,
            "first-seq-rx-network-ipv6": 1,
            "first-seq-rx-network-ipv6pd": 1,
            "access-tx-session-packets": 0,
            "access-rx-session-packets": 0,
            "access-rx-session-packets-loss": 0,
            "network-tx-session-packets": 0,
            "network-rx-session-packets": 0,
            "network-rx-session-packets-loss": 0,
            "access-tx-session-packets-ipv6": 25,
            "access-rx-session-packets-ipv6": 25,
            "access-rx-session-packets-ipv6-loss": 0,
            "network-tx-session-packets-ipv6": 25,
            "network-rx-session-packets-ipv6": 25,
            "network-rx-session-packets-ipv6-loss": 0,
            "access-tx-session-packets-ipv6pd": 25,
            "access-rx-session-packets-ipv6pd": 25,
            "access-rx-session-packets-ipv6pd-loss": 0,
            "network-tx-session-packets-ipv6pd": 25,
            "network-rx-session-packets-ipv6pd": 25,
            "network-rx-session-packets-ipv6pd-loss": 0
        }
    }
}
```

The response contains at least the status element with the value `ok` and status code `2xx` 
if request was successfully. The status can be also set to `warning` or
`error` with corresponding error code and an optional error message. 

`$ cat command.json | sudo nc -U test.socket | jq .`
```json
{
    "status": "warning",
    "code": 404,
    "message": "session not found"
}
```

## Control Socket Commands

### Global Commands

Attribute | Description 
--------- | -----------
`interfaces` | List all interfaces with index
`session-counters` | Return session counters
`terminate` | Terminate all sessions similar to sending SIGINT (ctr+c)
`session-traffic` | Display session traffic statistics | |
`session-traffic-enabled` | Enable session traffic for all sessions
`session-traffic-disabled` | Disable session traffic for all sessions
`multicast-traffic-start` | Start sending multicast traffic from network interface 
`multicast-traffic-stop` | Stop sending multicast traffic from network interface
`li-flows` | List all LI flows with detailed statistics

### Session Commands

The following commands must be execute with interface index and VLAN of the session
for which the command is executed. The interface index (`ifindex`) can be requests using
the `interfaces` command or skipped. The first access interface is automatically used if 
the argument `ifindex` is not present in the command. 

`$ cat command.json | jq .`
```json
{
    "command": "session-info",
    "arguments": {
        "ifindex": 10,
        "outer-vlan": 1,
        "inner-vlan": 1
    }
}
```

Attribute | Description | Mandatory Arguments | Optional Arguments
--------- | ----------- | ------------------- | ------------------ 
`session-info` | Session information | |
`terminate` | Terminate session | |
`ipcp-open`| Open IPCP | |
`ipcp-close` |Close IPCP | |
`ip6cp-open`| Open IP6CP | |
`ip6cp-close` |Close IP6CP | |
`session-traffic-enabled` | Enable session traffic | |
`session-traffic-disabled` | Disable session traffic | |
`igmp-join` | Join group | `group` | `source1`, `source2`, `source3`
`igmp-leave` | Leave group | `group` |
`igmp-info` | IGMP information | |

### L2TP Commands

Attribute | Description | Mandatory Arguments | Optional Arguments
--------- | ----------- | ------------------- | ------------------ 
`l2tp-tunnels` | L2TP tunnel information | |
`l2tp-sessions` | L2TP session information | | `tunnel-id`, `session-id`
`l2tp-csurq`| Send L2TP CSURQ | `tunnel-id` | `sessions`

The L2TP CSURQ command expects the local tunnel-id and a list of remote 
session-id for which a connect speed update is requested.

`$ cat command.json | jq .`
```json
{
    "command": "l2tp-csurq",
    "arguments": {
        "tunnel-id": 1,
        "sessions": [
            1,
            2,
            3,
            4
        ]
    }
}
```

This command can be executed as shown below using the CLI tool. 

`$ sudo ./cli.py run.sock l2tp-csurq tunnel-id 1 sessions [1,2,3,4]` 