# Traffic Streams

Traffic streams allow to test QoS using BNG Blaster.

![BBL Interactive Streams](images/bbl_streams.png "BNG Blaster")

## Configuration

Following a simple example using streams as described in
[Configuration](config).

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
        "tx-accounting-packets": 54594,
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

The measured `rx-delay-nsec-min/max` shows the minimum and maximum calculated delay
in nanosecond. The delay is calculated by subtracting the send and receive timestamp.
The send timestamp is stored in the BBL header (see section Traffic). This calculated
result depends also on the actual test environment, configured rx-interval and host IO
delay.

Traffic streams will start as soon as the session is established using the rate as configured
starting with sequence number 1 for each flow. The attribute `rx-first-seq` stores the first
sequence number received. Assuming the first sequence number received for given flow is 1000
combined with a rate of 1000 PPS would mean that it took around 1 second until forwarding is
working. After first packet is received for a given flow, for every further packet it checks
if there is a gap between last and new sequence number which is than reported as loss.

The `rx/tx-accounting-packets` are all packets which should be counted in the session volume
accounting of the BNG, meaning session rx/tx packets excluding control traffic.

Each flow can be queried separately using jsonpath expression with name and direction or flow-id.

`$ sudo ./cli.py run.sock session-streams session-id 1 | jq '."session-streams".streams[] | select(.name == "BE" and .direction == "downstream" )'`
```json
{
  "name": "BE",
  "direction": "downstream",
  "flow-id": 2,
  "rx-first-seq": 33,
  "rx-last-seq": 27040,
  "rx-tos-tc": 213,
  "rx-outer-vlan-pbit": 0,
  "rx-inner-vlan-pbit": 0,
  "rx-len": 126,
  "tx-len": 114,
  "rx-packets": 27008,
  "tx-packets": 27040,
  "rx-loss": 0,
  "rx-delay-nsec-min": 50450,
  "rx-delay-nsec-max": 10561572,
  "rx-pps": 99,
  "tx-pps": 99,
  "tx-bps-l2": 90288,
  "rx-bps-l2": 99792,
  "rx-bps-l3": 79200,
  "tx-mbps-l2": 0.090288,
  "rx-mbps-l2": 0.099792,
  "rx-mbps-l3": 0.0792
}
```

## RAW Streams

Streams with default `stream-group-id` set to zero are considered as raw streams not
bound to any session which is supported in downstream only. For those streams the
destination address must be explicitly set.

```json
{
    "streams": [
        {
            "name": "RAW",
            "type": "ipv4",
            "direction": "downstream",
            "priority": 128,
            "network-ipv4-address": "10.0.0.20",
            "destination-ipv4-address": "1.1.1.1",
            "length": 256,
            "pps": 1
        }
    ]
}
```

If `destination-ipv4-address` is set to a multicast IP address (224.0.0.0 - 239.255.255.255),
the BNG Blaster will set the the destination MAC address to the corresponding
multicast MAC address.

## Threaded Streams

**WARNING**: The threading support is experimental and should be used with caution!

With threading enabled, those streams will be started in a dedicated thread per flow. This
means one thread per session and stream direction. A threaded , bidirectional stream assigned
to 10 sessions will therefore run in 20 threads.

In most environments we see that 200.000 PPS single threaded is working. Depending on actual setup this
can be also more. With threaded streams we are also able to scale up to three million PPS or more.

## Start/Stop Session Stream Information

Session stream traffic can be started/stopped dynamically
using the commands `stream-traffic-enabled` and `stream-traffic-disabled`.

`$ sudo ./cli.py run.sock stream-traffic-disabled session-id 1`

Those commands start/stop the traffic for all sessions if invoked without
session identifier.

`$ sudo ./cli.py run.sock stream-traffic-disabled`

