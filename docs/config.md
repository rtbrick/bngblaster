# Configuration

Following an example configuration file which is explained in detail below. 
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
                "outer-vlan-min": 1000,
                "outer-vlan-max": 1999,
                "inner-vlan-min": 1,
                "inner-vlan-max": 4049,
                "authentication-protocol": "PAP"
            },
            {
                "interface": "eth1",
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

## Interfaces

This section describes all attributes of the `interfaces` hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`tx-interval` | TX ring polling interval in milliseconds | 5
`rx-interval` | RX ring polling interval in milliseconds | 5
`qdisc-bypass` | Bypass the kernel's qdisc layer | true
`io-mode` | IO mode | packet_mmap

WARNING: Try to disable `qdisc-bypass` if BNG Blaster is not sending traffic!
This issue was frequently seen on Ubuntu 20.04. 

The supported IO modes are listed with `bngblaster -v` but except
`packet_mmap` all other modes are currently considered as experimental. 

### Network Interface

`"interfaces": { "network": { ... } }`

Attribute | Description | Default 
--------- | ----------- | -------
`interface` | Network interface name (e.g. eth0, ...)
`address` | `Local network interface IPv4 address
`gateway` | Gateway network interface IPv4 address
`address-ipv6` | Local network interface IPv6 address (implicitly /64) | - 
`gateway-ipv6` | Gateway network interface IPv6 address (implicitly /64)
`vlan` | Network interface VLAN | 0 (untagged)


### Access Interfaces

`"interfaces": { "access": { ... } }`

Attribute | Description | Default 
--------- | ----------- | -------
`interface` | Access interface name (e.g. eth0, ...)
`type` | Switch the access type between `pppoe` (PPP over Ethernet) and `ipoe` (IP over Ethernet) | pppoe
`vlan-mode` | Set VLAN mode `1:1` or `N:1` | 1:1
`outer-vlan-min` |Outer VLAN minimum value | 0 (untagged)
`outer-vlan-max` | Outer VLAN maximum value | 0 (untagged)
`inner-vlan-min` | Inner VLAN minimum value | 0 (untagged)
`inner-vlan-max` |Inner VLAN maximum value | 0 (untagged)
`third-vlan` | Add a fixed third VLAN (most inner VLAN) as required for some lab environments | 0 (untagged)
`address` | Static IPv4 base address (IPoE only)
`address-iter` |Static IPv4 base address iterator (IPoE only)
`gateway` |Static IPv4 gateway address (IPoE only)
`gateway` |Static IPv4 gateway address iterator (IPoE only)
`username` | Optionally overwrite the username from authentication section per access configuration 
`password` | Optionally overwrite the password from authentication section per access configuration
`authentication-protocol` | Optionally overwrite the username from authentication section per access configuration
`agent-circuit-id` | Optionally overwrite the agent-circuit-id from access-line section per access configuration
`agent-remote-id` | Optionally overwrite the agent-remote-id from access-line section per access configuration
`rate-up` | Optionally overwrite the rate-up from access-line section per access configuration
`rate-down` | Optionally overwrite the rate-down from access-line section per access configuration
`dsl-type` | Optionally overwrite the dsl-type from access-line section per access configuration
`ipcp` | Optionally enable/disable PPP IPCP per access configuration
`ip6cp` | Optionally enable/disable PPP IP6CP per access configuration
`ipv4` | Optionally enable/disable IPoE IPv4 per access configuration
`ipv6` | Optionally enable/disable IPoE IPv4 per access configuration
`dhcp` | Optionally enable/disable DHCP per access configuration
`dhcpv6` | Optionally enable/disable DHCPv6 per access configuration


**WARNING**: DHCP (IPv4) is currently not supported!

But for all modes it is possible to configure between zero and three VLAN
tags on the access interface as shown below.

```
[ethernet][outer-vlan][inner-vlan][third-vlan][pppoe]...
```

**Untagged**

With untagged only one session is possible. 
```json
{
    "access": {
        "interface": "eth1",
        "outer-vlan-min": 0,
        "outer-vlan-max": 0,
        "inner-vlan-min": 0,
        "inner-vlan-max": 0
    }
}
```

**Single Tagged**
```json
{
    "access": {
        "interface": "eth1",
        "outer-vlan-min": 1,
        "outer-vlan-max": 4049,
        "inner-vlan-min": 0,
        "inner-vlan-max": 0
    }
}
```

**Double Tagged**
```json
{
    "access": {
        "interface": "eth1",
        "outer-vlan-min": 1,
        "outer-vlan-max": 4049,
        "inner-vlan-min": 7,
        "inner-vlan-max": 7
    }
}
```

**Triple Tagged**
```json
{
    "access": {
        "interface": "eth1",
        "outer-vlan-min": 10,
        "outer-vlan-max": 20,
        "inner-vlan-min": 128,
        "inner-vlan-max": 4000,
        "third-vlan": 7
    }
}
```

The BNG Blaster supports also multiple access interfaces
or VLAN ranges as shown in the example below. 

```json
{
    "access": [
        {
            "interface": "eth1",
            "type": "pppoe",
            "username": "pta@rtbrick.com",
            "outer-vlan-min": 1000,
            "outer-vlan-max": 1999,
            "inner-vlan-min": 7,
            "inner-vlan-max": 7
        },
        {
            "interface": "eth1",
            "type": "pppoe",
            "username": "l2tp@rtbrick.com",
            "outer-vlan-min": 2000,
            "outer-vlan-max": 2999,
            "inner-vlan-min": 7,
            "inner-vlan-max": 7
        },
        {
            "interface": "eth3",
            "type": "pppoe",
            "username": "test@rtbrick.com",
            "outer-vlan-min": 128,
            "outer-vlan-max": 4000,
            "inner-vlan-min": 7,
            "inner-vlan-max": 7
        },
        {
            "interface": "eth4",
            "type": "ipoe",
            "outer-vlan-min": 8,
            "outer-vlan-max": 9,
            "address": "200.0.0.1",
            "address-iter": "0.0.0.4",
            "gateway": "200.0.0.2",
            "gateway-iter": "0.0.0.4"
        }
    ]
}
```

There is actually no hard limit in the amount of access interfaces but
the resource usage will grow with the amount of interfaces. 

The number of network interfaces is limited to one!

Both network and access interfaces are optional but obviously at least 
one interface is required to start the BNG Blaster. 

The configuration attributes for username, agent-remote-id and agent-circuit-id
support also some variable substitution. The variable `{session-global}` will
be replaced with a number starting from 1 and incremented for every new session. 
where as the variable `{session}` is incremented per interface section. 

In VLAN mode `N:1` only one VLAN combination is supported per access interface section. 
This means that only VLAN min or max is considered as VLAN identifer. 

```json
{
    "access": [
        {
            "interface": "eth1",
            "type": "pppoe",
            "vlan-mode": "N:1",
            "username": "test@rtbrick.com",
            "outer-vlan-min": 7
        },
        {
            "interface": "eth2",
            "type": "pppoe",
            "vlan-mode": "N:1",
            "username": "test@rtbrick.com",
            "outer-vlan-min": 2000,
            "inner-vlan-min": 7,
        },
    ]
}
```

## Sessions

This section describes all attributes of the `sessions` hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`count` | Sessions (PPPoE + IPoE) | 1
`max-outstanding` | Max outstanding sessions | 800
`start-rate` | Setup request rate in sessions per second | 400
`stop-rate` | Teardown request rate in sessions per second | 400
`iterate-vlan-outer` | Iterate on outer VLAN first | false

Per default sessions are created by iteration over inner VLAN range first and outer VLAN second. 
Which can be changed by `iterate-vlan-outer` to iterate on outer VLAN first and inner VLAN second.

Therefore the following configuration generates the sessions on VLAN (outer:inner) 1:3, 1:4, 2:3, 2:4 per default or alternative 1:3, 2:3, 1:4, 2:4 with `iterate-vlan-outer` enabled. 
```json
{
    "outer-vlan-min": 1,
    "outer-vlan-max": 2,
    "inner-vlan-min": 3,
    "inner-vlan-max": 4
}
``` 

## IPoE

This section describes all attributes of the `ipoe` (IP over Ethernet) hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`ipv4` | Enable/disable IPv4 | true (enabled)
`ipv6` | Enable/disable IPv6 | true (enabled)

## PPPoE

This section describes all attributes of the `pppoe` (PPP over Ethernet) hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`session-time` | Max PPPoE session time in seconds | 0 (infinity)
`reconnect` | Automatically reconnect sessions if terminated | false
`discovery-timeout` | PPPoE discovery (PADI and PADR) timeout in seconds | 5
`discovery-retry` | PPPoE discovery (PADI and PADR) max retry | 10
`service-name` | PPPoE discovery service name | 
`host-uniq` | PPPoE discovery host-uniq | false
`vlan-priority` | VLAN PBIT for all PPPoE/PPP control traffic | 0 

## PPP

This section describes all attributes of the `ppp` hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`mru` | Define the maximum receive unit proposed via PPP | 1492

### PPP Authentication 

`"ppp": { "authentication": { ... } }`

Attribute | Description | Default 
--------- | ----------- | -------
`username` | Username | user{session-global}@rtbrick.com
`password` |Password | test
`timeout` | Authentication request timeout in seconds | 5
`retry` | Authentication request max retry | 30
`protocol` | This value can be set to `PAP` or `CHAP` to reject the other protocol | allow PAP and CHAP

### PPP LCP 

`"ppp": { "lcp": { ... } }`

Attribute | Description | Default 
--------- | ----------- | -------
`conf-request-timeout` | LCP configuration request timeout in seconds | 5
`conf-request-retry` | LCP configuration request max retry | 10
`keepalive-interval` | LCP echo request interval in seconds (0 means disabled) | 30
`keepalive-retry` | PPP LCP echo request max retry | 3

### PPP IPCP

`"ppp": { "ipcp": { ... } }`

Attribute | Description | Default 
--------- | ----------- | -------
`enable` | This option allows to enable or disable the IPCP protocol | true
`request-ip` | Include IP-Address	with 0.0.0.0 in initial LCP configuration request | true
`request-dns1` | Request Primary DNS Server Address (option 129) | true
`request-dns2` | Request Secondary DNS Server Address (option 131) | true
`conf-request-timeout` | IPCP configuration request timeout in seconds | 5
`conf-request-retry` | IPCP configuration request max retry | 10

### PPP IP6CP

`"ppp": { "ipcp": { ... } }`

Attribute | Description | Default 
--------- | ----------- | -------
`enable` | This option allows to enable or disable the IP6CP protocol | true
`conf-request-timeout` | IP6CP configuration request timeout in seconds | 5
`conf-request-retry` | IP6CP configuration request max retry | 10

## Access-Line

This section describes all attributes of the `access-line` hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`agent-circuit-id` | Agent-Circuit-Id | 0.0.0.0/0.0.0.0 eth 0:{session-global}
`agent-remote-id` | Agent-Remote-Id | DEU.RTBRICK.{session-global}
`rate-up` | Actual-Data-Rate-Upstream | 0
`rate-down` | Actual-Data-Rate-Downstream | 0
`dsl-type` | DSL-Type | 0

## DHCP

This section describes all attributes of the `dhcp` hierarchy. 

**WARNING**: DHCP (IPv4) is currently not supported!

Attribute | Description | Default 
--------- | ----------- | -------
`enable` | This option allows to enable or disable DHCP | true

## DHCPv6

This section describes all attributes of the `dhcpv6` hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`enable` | This option allows to enable or disable DHCPv6 | true
`rapid-commit` | DHCPv6 rapid commit (2 way handshake) | true

## IGMP

This section describes all attributes of the `igmp` hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`version` | IGMP protocol version (1, 2 or 3) | 3
`combined-leave-join` | Combine leave and join records within a single IGMPv3 report | true
`start-delay` | Delay between session established and initial IGMP join in seconds | 1
`group` | Multicast group base address (e.g. 239.0.0.1) | 0.0.0.0 (disabled)
`group-iter` | Multicast group iterator | 0.0.0.1
`group-count` | Multicast group count | 1
`source` | Multicast source address (e.g. 1.1.1.1) | 0.0.0.0 (ASM)
`zapping-interval` | IGMP channel zapping interval in seconds | 0 (disabled)
`zapping-count` | Define the amount of channel changes before starting view duration | 0 (disabled)
`view-duration` | Define the view duration in seconds | 0 (disabled)
`send-multicast-traffic` | Generate multicast traffic | false
`multicast-traffic-length` | Multicast traffic IP length | 76
`multicast-traffic-tos` | Multicast traffic TOS priority | 0

Per default join and leave requests are send using dedicated reports. The option `combined-leave-join` allows 
the combination of leave and join records within a single IGMPv3 report using multiple group records. 
This option is applicable to IGMP version 3 only!

If `send-multicast-traffic` is true, the BNG Blaster generates multicast traffic on the network interface 
based on the specified group and source attributes mentioned before. This traffic includes some special 
signatures for faster processing and more detailed analysis.

If group is set to 293.0.0.1 with group-iter of 0.0.0.2, source 1.1.1.1 and group-count 3 the result are the following 
three groups (S.G) 1.1.1.1,239.0.0.1, 1.1.1.1,239.0.0.3 and 1.1.1.1,239.0.0.5. 

## Session-Traffic

This section describes all attributes of the `session-traffic` hierarchy. 

Attribute | Description | Default 
--------- | ----------- | -------
`autostart` | Automatically start session traffic after session is established | true 
`ipv4-pps` | Generate bidirectional IPv4 traffic between network interface and all session framed IPv4 addresses | 0 (disabled)
`ipv6-pps` | Generate bidirectional IPv6 traffic between network interface and all session framed IPv6 addresses | 0 (disabled)
`ipv6pd-pps` | Generate bidirectional Ipv6 traffic between network interface and all session delegated IPv6 addresses | 0 (disabled)

## l2TP Server

This section describes all attributes of the `l2tp-server` (LNS) hierarchy. 

The BNG Blaster supports multiple L2TPv2 servers (LNS) over the network interface
as shown in the example below. 

```json
{
    "interfaces": {
        "network": {
            "interface": "eth2",
            "address": "10.0.0.1",
            "gateway": "10.0.0.2"
        }
    },
    "l2tp-server": [
         {
            "name": "LNS1",
            "address": "10.0.0.10",
            "secret": "test1",
        },
        {
            "name": "LNS2",
            "address": "10.0.0.11",
            "secret": "test2",
        },
    ]
}
```

There is actually no hard limit in the amount of L2TP servers. 

Attribute | Description | Default 
--------- | ----------- | -------
`name` | Mandatory L2TP LNS server hostname (AVP 7) | 
`address` | Mandatory L2TP server address |
`secret` | Tunnel secret |
`receive-window-size` | Control messages receive window size | 4
`max-retry` | Control messages max retry | 30
`congestion-mode` | Control messages congestion mode | default
`data-control-priority` | Set the priority bit in the L2TP header for all non-IP data packets (LCP, IPCP, ...) | false
`data-length` | Set length bit for all data packets | false
`data-offset` | Set offset bit with offset zero for all data packets | false
`control-tos` | L2TP control traffic (SCCRQ, ICRQ, ...) TOS priority | 0
`data-control-tos` | Set the L2TP tunnel TOS priority (outer IPv4 header) for all non-IP data packets (LCP, IPCP, ...) | 0

The BNG Blaster supports different congestion modes for the 
reliable delivery of control messages. The `default` mode
is described in RFC2661 appendix A (Control Channel Slow Start and 
Congestion Avoidance). The mode `slow` uses a fixed control window
size of 1 where `aggressive` sticks to max permitted based on peer 
received window size. 