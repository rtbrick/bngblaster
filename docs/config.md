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

This section describes all attributes of the `interfaces` hierarchy
which allows to modify how to send and receive traffic.

```json
{
    "interfaces": {
        "tx-interval": 0.1,
        "rx-interval": 0.1,
        "io-slots": 2048,
    }
}
```

Attribute | Description | Default
--------- | ----------- | -------
`tx-interval` | TX ring polling interval in milliseconds | 5.0
`rx-interval` | RX ring polling interval in milliseconds | 5.0
`qdisc-bypass` | Bypass the kernel's qdisc layer | true
`io-mode` | IO mode | packet_mmap_raw
`io-slots` | IO slots (ring size) | 1024
`io-stream-max-ppi` | IO traffic stream max packets per interval | 32

The `tx-interval` and `rx-interval` should be set to at to at least `1.0` (1ms)
if more precise timestamps are needed. This is recommended for IGMP join/leave
or QoS delay measurements. For higher packet rates (>1g) it might be needed to
increase the `io-slots` from the default value of `1024` to `2048` or more.

The supported IO modes are listed with `bngblaster -v` but except
`packet_mmap_raw` all other modes are currently considered as experimental. In
the default mode (`packet_mmap_raw`) all packets are received in a Packet MMAP
ring buffer and send directly trough RAW packet sockets.

**WARNING**: Disable `qdisc-bypass` only if BNG Blaster is not sending traffic!

The interfaces used in BNG Blaster do not need IP addresses configured in the host
operating system but they need to be in up state.

```
sudo ip link set dev <interface> up
```

It is not possible to send packets larger than the interface MTU which is 1500 per default
but for PPPoE with multiple VLAN headers this might be not enough for large packets.
Therefore the interface MTU should be increased using the following commands.

```
sudo ip link set mtu 9000 dev <interface>
```

This can be also archived via netplan using the following configuration for each BNG Blaster
interface.

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth1:
      dhcp4: no
      dhcp6: no
      link-local: []
      mtu: 9000
    eth2:
      dhcp4: no
      dhcp6: no
      link-local: []
      mtu: 9000
```

The number of interfaces is currently limited to 32!

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
`gateway-mac`| Optional set gateway MAC address manually
`gateway-resolve-wait` | Sessions will not start until gateways are resolved | true

The BNG Blaster supports also multiple access interfaces
or VLAN ranges as shown in the example below.

```json
{
    "interfaces": {
        "tx-interval": 1,
        "rx-interval": 1,
        "io-slots": 4096,
        "network": [
            {
                "interface": "eth2",
                "address": "10.0.0.1",
                "gateway": "10.0.0.2",
                "address-ipv6": "fc66:1337:7331::1",
                "gateway-ipv6": "fc66:1337:7331::2"
            },
            {
                "interface": "eth3",
                "address": "10.0.1.1",
                "gateway": "10.0.1.2",
                "address-ipv6": "fc66:1337:7331:1::1",
                "gateway-ipv6": "fc66:1337:7331:1::2"
            }
        ],
    }
}
```

Using multiple network interfaces requires to select which network interface
to be used otherwise one of the interface is selected automatically. Therefore
the option `network-interface` is supported in different sections.

### Access Interfaces

`"interfaces": { "access": { ... } }`

Attribute | Description | Default
--------- | ----------- | -------
`interface` | Access interface name (e.g. eth0, ...)
`network-interface` | Select the corresponding network interface for this session |
`type` | Switch the access type between `pppoe` (PPP over Ethernet) and `ipoe` (IP over Ethernet) | pppoe
`vlan-mode` | Set VLAN mode `1:1` or `N:1` | 1:1
`qinq` | Set outer VLAN ethertype to QinQ (0x88a8) | false
`outer-vlan-min` | Outer VLAN minimum value | 0 (untagged)
`outer-vlan-max` | Outer VLAN maximum value | 0 (untagged)
`outer-vlan` |Set outer-vlan-min/max equally
`inner-vlan-min` | Inner VLAN minimum value | 0 (untagged)
`inner-vlan-max` | Inner VLAN maximum value | 0 (untagged)
`inner-vlan` |Set inner-vlan-min/max equally
`third-vlan` | Add a fixed third VLAN (most inner VLAN) as required for some lab environments | 0 (untagged)
`address` | Static IPv4 base address (IPoE only)
`address-iter` | Static IPv4 base address iterator (IPoE only)
`gateway` | Static IPv4 gateway address (IPoE only)
`gateway-iter` | Static IPv4 gateway address iterator (IPoE only)
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
`ipv6` | Optionally enable/disable IPoE IPv6 per access configuration
`dhcp` | Optionally enable/disable DHCP per access configuration
`dhcpv6` | Optionally enable/disable DHCPv6 per access configuration
`igmp-autostart` | Optionally overwrite IGMP autostart per access configuration
`igmp-version` | Optionally overwrite IGMP protocol version (1, 2 or 3) per access configuration
`stream-group-id` | Optional stream group identifier
`access-line-profile-id` | Optional access-line-profile identifier
`cfm-cc` | Optionally enable/disable EOAM CFM CC (IPoE only) | false
`cfm-level` | Set EOAM CFM maintenance domain level | 0
`cfm-ma-id` | Set EOAM CFM maintenance association identifier | 0
`cfm-ma-name` | Set EOAM CFM maintenance association short name
`i1-start` | Iterator for usage in strings `{i1}` | 1
`i1-step` | Iterator step per session | 1
`i2-start` | Iterator for usage in strings `{i2}` | 1
`i2-step` | Iterator step per session | 1

For all modes it is possible to configure between zero and three VLAN
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


Both network and access interfaces are optional but obviously at least
one interface is required to start the BNG Blaster.

The configuration attributes for username, agent-remote-id and agent-circuit-id
support also some variable substitution. The variable `{session-global}` will
be replaced with a number starting from 1 and incremented for every new session.
where as the variable `{session}` is incremented per interface section.

In VLAN mode `N:1` only one VLAN combination is supported per access interface section.
This means that only VLAN min or max is considered as VLAN identifier.

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

### A10NSP Interface

`"interfaces": { "a10nsp": { ... } }`

Attribute | Description | Default
--------- | ----------- | -------
`interface` | A10nSP interface name (e.g. eth0, ...)
`qinq` | Set outer VLAN ethertype to QinQ (0x88a8) | false
`mac`| Optional set gateway interface address manually

The BNG Blaster supports also multiple A10NSP interfaces
as shown in the example below.

```json
{
    "interfaces": {
        "tx-interval": 1,
        "rx-interval": 1,
        "a10nsp": [
            {
                "interface": "eth4",
                "qinq": true,
                "mac": "02:00:00:ff:ff:01"
            },
            {
                "interface": "eth5",
                "qinq": false,
                "mac": "02:00:00:ff:ff:02"
            }
        ],
    }
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
`arp-timeout` | Initial ARP resolve timeout/retry interval in seconds | 1
`arp-interval` | Periodic ARP interval in seconds (0 means disabled) | 300
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
`start-delay` | PPP LCP initial request delay in milliseconds | 0
`ignore-vendor-specific` | Ignore LCP vendor specific requests | false
`connection-status-message` | Accept LCP connection status messages | false

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

## DHCP

This section describes all attributes of the `dhcp` hierarchy.

Attribute | Description | Default
--------- | ----------- | -------
`enable` | This option allows to enable or disable DHCP | false
`broadcast` | DHCP broadcast flag | false
`timeout` | DHCP timeout in seconds | 5
`retry` | DHCP retry | 10
`release-interval` | DHCP release interval | 1
`release-retry` | DHCP release retry | 3
`tos` | IPv4 TOS for all DHCP control traffic | 0
`vlan-priority` | VLAN PBIT for all DHCP control traffic | 0

## DHCPv6

This section describes all attributes of the `dhcpv6` hierarchy.

Attribute | Description | Default
--------- | ----------- | -------
`enable` | This option allows to enable or disable DHCPv6 | true
`rapid-commit` | DHCPv6 rapid commit (2 way handshake) | true
`timeout` | DHCPv6 timeout in seconds | 5
`retry` | DHCPv6 retry | 10

## IGMP

This section describes all attributes of the `igmp` hierarchy.

Attribute | Description | Default
--------- | ----------- | -------
`autostart` | Automatically join after session is established | true
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
`network-interface` | Multicast traffic source interface |

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

## L2TP Server (LNS)

This section describes all attributes of the `l2tp-server` (LNS) hierarchy
as explained in [L2TPv2](l2tp).

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

## Traffic Streams

This section describes all attributes of the `streams` hierarchy
as explained in [Traffic Streams](streams).

Attribute | Description | Default
--------- | ----------- | -------
`name` | Mandatory stream name |
`stream-group-id` | Stream group identifier | 0 (raw)
`type` | Mandatory stream type (`ipv4`, `ipv6` or `ipv6pd`)  |
`direction` | Mandatory stream direction (`upstream`, `downstream` or `both`) | `both`
`priority` | IPv4 TOS / IPv6 TC | 0
`vlan-priority` | VLAN priority | 0
`length` | Layer 3 (IP + payload) traffic length (76 - 9000) | 128
`pps` | Stream traffic rate in packets per second | 1
`bps` | Stream traffic rate in bits per second (layer 3) |
`a10nsp-interface` | Select the corresponding A10NSP interface for this stream |
`network-interface` | Select the corresponding network interface for this stream |
`network-ipv4-address` | Overwrite network interface IPv4 address |
`network-ipv6-address` | Overwrite network interface IPv6 address |
`destination-ipv4-address` | Overwrite the IPv4 destination address |
`destination-ipv6-address` | Overwrite the IPv6 destination address |
`threaded` | Run those streams in separate threads | false
`thread-group` | Assign this stream to thread group (1-255) | 0 (thread per stream)

For L2TP downstream traffic the IPv4 TOS is applied to the outer IPv4 and inner IPv4 header.

The `pps` option supports also float numbers like 0.1, or 2.5 PPS and has priority over `bps`
where second is only a helper to calculate the `pps` based on given `bps` and `length`.

## Access-Line

This section describes all attributes of the `access-line` hierarchy.

Attribute | Description | Default
--------- | ----------- | -------
`agent-circuit-id` | Agent-Circuit-Id |
`agent-remote-id` | Agent-Remote-Id |
`rate-up` | Actual Data Rate Upstream |
`rate-down` | Actual Data Rate Downstream |
`dsl-type` | DSL-Type |

## Access-Line-Profiles

This section describes all attributes of the `access-line-profiles` hierarchy.

Attribute | Description | Default
--------- | ----------- | -------
`access-line-profile-id` | Mandatory access-line-profile identifier
`act-up` | Actual Data Rate Upstream | 0
`act-down` | Actual Data Rate Downstream | 0
`min-up` | Minimum Data Rate Upstream | 0
`min-down` | Minimum Data Rate Downstream | 0
`att-up` | Attainable DataRate Upstream | 0
`att-down` | Attainable DataRate Downstream | 0
`max-up` | Maximum Data Rate Upstream | 0
`max-down` | Maximum Data Rate Downstream | 0
`min-up-low` | Min Data Rate Upstream in low power state | 0
`min-down-low` | Min Data Rate Downstream in low power state | 0
`max-interl-delay-up` | Max Interleaving Delay Upstream | 0
`act-interl-delay-up` | Actual Interleaving Delay Upstream | 0
`max-interl-delay-down` | Max Interleaving Delay Downstream | 0
`act-interl-delay-down` | Actual Interleaving Delay Downstream | 0
`data-link-encaps` | Data Link Encapsulation | 0
`dsl-type` | DSL Type | 0
`pon-type` | PON Access Type | 0
`etr-up` | Expected Throughput (ETR) Upstream | 0
`etr-down` | Expected Throughput (ETR) Downstream | 0
`attetr-up` | Attainable Expected Throughput (ATTETR) Upstream | 0
`attetr-down` | Attainable Expected Throughput (ATTETR) Downstream | 0
`gdr-up` | Gamma Data Rate (GDR) Upstream | 0
`gdr-down` | Gamma Data Rate (GDR) Downstream | 0
`attgdr-up` | Attainable Gamma Data Rate (ATTGDR) Upstream | 0
`attgdr-down` | Attainable Gamma Data Rate (ATTGDR) Downstream | 0
`ont-onu-avg-down` | ONT/ONU Average Data Rate Downstream | 0
`ont-onu-peak-down` | ONT/ONUPeak Data Rate Downstream | 0
`ont-onu-max-up` | ONT/ONU Maximum Data Rate Upstream | 0
`ont-onu-ass-up` | ONT/ONU Assured Data Rate Upstream | 0
`pon-max-up` | PON Tree Maximum Data Rate Upstream | 0
`pon-max-down` | PON Tree Maximum Data Rate Downstream | 0

Attributes with value set to 0 will not be send.

The values for `rate-up`, `rate-down` and `dsl-type` defined in the
access-line or interface section have priority over those defined
here.

```json
{
    "access-line-profiles": [
        {
            "access-line-profile-id": 1,
            "act-up": 2000,
            "act-down": 16000,
            "min-up": 64,
            "min-down": 1024,
            "att-up": 2048,
            "att-down": 16384,
            "max-up": 2040,
            "max-down": 16380,
            "min-up-low": 32,
            "min-down-low": 1024,
            "max-interl-delay-up": 100,
            "act-interl-delay-up": 10,
            "max-interl-delay-down": 100,
            "act-interl-delay-down": 10,
            "data-link-encaps": 525061,
            "dsl-type": 5,
        },
        {
            "access-line-profile-id": 2,
            "act-up": 40000,
            "act-down": 100000,
            "pon-type": 1,
            "etr-up": 40000,
            "etr-down": 100000,
            "attetr-up": 40000,
            "attetr-down": 100000,
            "gdr-up": 40000,
            "gdr-down": 100000,
            "attgdr-up": 40000,
            "attgdr-down": 100000,
            "ont-onu-avg-down": 100000,
            "ont-onu-peak-down": 100000,
            "ont-onu-max-up": 40000,
            "ont-onu-ass-up": 40000,
            "pon-max-up": 1000000,
            "pon-max-down": 2400000
        }
    ]
}
```