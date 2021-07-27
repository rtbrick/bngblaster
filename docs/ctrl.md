# Control Socket

The control socket is an unix domain stream socket which allows the control daemon to
interact with the BNG Blaster using JSON RPC. This interface was primary developed for
the BNG Blaster Controller but can be also used manually or by other tools like the
simple CLI tool `bngblaster-cli` for interactive communication with the BNG Blaster.

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
        "session-id": 1
    }
}
```

`$ cat command.json | sudo nc -U test.socket | jq .`
```json
{
    "status": "ok",
    "code": 200,
    "session-info": {
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
        "tx-packets": 30,
        "rx-packets": 26,
        "rx-fragmented-packets": 0,
        "session-traffic": {
            "total-flows": 6,
            "verified-flows": 6,
            "first-seq-rx-access-ipv4": 2,
            "first-seq-rx-access-ipv6": 2,
            "first-seq-rx-access-ipv6pd": 1,
            "first-seq-rx-network-ipv4": 2,
            "first-seq-rx-network-ipv6": 2,
            "first-seq-rx-network-ipv6pd": 1,
            "access-tx-session-packets": 5,
            "access-rx-session-packets": 4,
            "access-rx-session-packets-loss": 0,
            "network-tx-session-packets": 5,
            "network-rx-session-packets": 4,
            "network-rx-session-packets-loss": 0,
            "access-tx-session-packets-ipv6": 5,
            "access-rx-session-packets-ipv6": 4,
            "access-rx-session-packets-ipv6-loss": 0,
            "network-tx-session-packets-ipv6": 5,
            "network-rx-session-packets-ipv6": 4,
            "network-rx-session-packets-ipv6-loss": 0,
            "access-tx-session-packets-ipv6pd": 4,
            "access-rx-session-packets-ipv6pd": 4,
            "access-rx-session-packets-ipv6pd-loss": 0,
            "network-tx-session-packets-ipv6pd": 4,
            "network-rx-session-packets-ipv6pd": 4,
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

## BNG Blaster CLI

The python script `bngblaster-cli` provides a simple CLI tool
for interactive communication with the BNG Blaster.

```
$ sudo bngblaster-cli
BNG Blaster Control Socket Client

bngblaster-cli <socket> <command> [arguments]

Examples:
    bngblaster-cli run.sock session-info session-id 1
    bngblaster-cli run.sock igmp-join session-id 1 group 239.0.0.1 source1 1.1.1.1 source2 2.2.2.2 source3 3.3.3.3
    bngblaster-cli run.sock igmp-info session-id 1
    bngblaster-cli run.sock l2tp-csurq tunnel-id 1 sessions [1,2]
```

`$ sudo bngblaster-cli run.sock session-counters | jq .`
```json
{
  "status": "ok",
  "code": 200,
  "session-counters": {
    "sessions": 1,
    "sessions-established": 1,
    "sessions-flapped": 0,
    "dhcpv6-sessions-established": 1
  }
}
```
## Control Socket Commands

### Global Commands

Attribute | Description
--------- | -----------
`interfaces` | List all interfaces with index
`session-counters` | Return session counters
`terminate` | Terminate all sessions similar to sending SIGINT (ctr+c)
`session-traffic` | Display session traffic statistics
`session-traffic-start` (Alias: `session-traffic-enabled`) | Start sending session traffic for all sessions
`session-traffic-stop` (Alias: `session-traffic-disabled`) | Stop sending session traffic for all sessions
`stream-traffic-start` (Alias: `stream-traffic-enabled`)  | Start sending stream traffic for all sessions
`stream-traffic-stop` (Alias: `stream-traffic-disabled`) | Stop sending stream traffic for all sessions
`multicast-traffic-start` | Start sending multicast traffic from network interface
`multicast-traffic-stop` | Stop sending multicast traffic from network interface
`li-flows` | List all LI flows with detailed statistics
`sessions-pending` | List all sessions not established
`cfm-cc-start` | Start EOAM CFM CC
`cfm-cc-stop` | Stop EOAM CFM CC
`cfm-cc-rdi-on` | Set EOAM CFM CC RDI
`cfm-cc-rdi-off` | Unset EOAM CFM CC RDI

### Session Commands

The following commands must be execute with either `session-id` or alternative with
interface index and VLAN of the session for which the command is executed. The interface
index (`ifindex`) can be requests using the `interfaces` command or skipped. The first
access interface is automatically used if the argument `ifindex` is not present in the
command. For N:1 sessions only `session-id` is supported because multiple sessions can
be assigned to a single VLAN in this mode.

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
`ipcp-open` | Open IPCP | |
`ipcp-close` | Close IPCP | |
`ip6cp-open`| Open IP6CP | |
`ip6cp-close` | Close IP6CP | |
`session-traffic-start` (Alias: `session-traffic-enabled`) | Enable session traffic | |
`session-traffic-stop` (Alias: `session-traffic-disabled`) | Disable session traffic | |
`session-streams` | Session traffic stream information | |
`stream-traffic-start` (Alias: `stream-traffic-enabled`) | Enable session stream traffic | |
`stream-traffic-stop` (Alias: `stream-traffic-disabled`) | Disable session stream traffic | |
`igmp-join` | Join group | `group` | `source1`, `source2`, `source3`
`igmp-leave` | Leave group | `group` |
`igmp-info` | IGMP information | |
`cfm-cc-start` | Start EOAM CFM CC
`cfm-cc-stop` | Stop EOAM CFM CC
`cfm-cc-rdi-on` | Set EOAM CFM CC RDI
`cfm-cc-rdi-off` | Unset EOAM CFM CC RDI

The `session-id` is the same as used for `{session-global}` in the
configuration section. This number starts with 1 and is increased
per session added. In example if username is configured as
`user{session-global}@rtbrick.com` and logged in user is
`user10@rtbrick.com` the `session-id` of this user is `10`.

### L2TP Commands

Attribute | Description | Mandatory Arguments | Optional Arguments
--------- | ----------- | ------------------- | ------------------
`l2tp-tunnels` | L2TP tunnel information | |
`l2tp-sessions` | L2TP session information | | `tunnel-id`, `session-id`
`l2tp-csurq`| Send L2TP CSURQ | `tunnel-id` | `sessions`
`l2tp-tunnel-terminate` | Terminate L2TP tunnel | `tunnel-id` | `result-code`, `error-code`, `error-message`
`l2tp-session-terminate` | Terminate L2TP session | `session-id` | `result-code`, `error-code`, `error-message`, `disconnect-code`, `disconnect-protocol`, `disconnect-direction`, `disconnect-message`

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

`$ sudo bngblaster-cli run.sock l2tp-csurq tunnel-id 1 sessions [1,2,3,4]`

The L2TP session terminate command allows to test result (RFC2661) and disconnect (RFC3145) codes. 

`$ sudo bngblaster-cli run.sock l2tp-session-terminate session-id 1 result-code 2 error-message "LCP request" disconnect-code 3 disconnect-message "LCP terminate request"`
