# Multicast

The BNG Blaster provides advanced functionalities for testing multicast 
over PPPoE sessions with focus on IPTV. Therefore IGMP version 1, 2 and 3
is implemented with support for up to 8 group records per session and 3 
sources per group. 

Multicast testing is supported using external multicast traffic like real 
world IPTV traffic or by generating multicast traffic on the network interface. 

## Generate Multicast Traffic

The BNG Blaster is recognizing loss using the BNG Blaster header sequence numbers. 
After first multicast traffic is received for a particular group, for every further 
packet it checks if there is a gap between last and new sequence number which is than 
reported as loss. The loss logging option (-l loss) allows also to search for the missing 
packets in the corresponding capture files (see test.log). 

It is also possible to start a dedicated BNG Blaster instance to generate mutlicast 
traffic which can be consumed by multiple BNG Blaster instances. The BNG Blaster 
header allows to do the same measurements on traffic generated from same or different 
BNG Blaster instance. 

The following example shows generates traffic for 100 multicast groups 
with one packet per millisecond for every group as required to measure the join and leave
delay in milliseconds. 
```json
{
    "interfaces": {
        "tx-interval": 1,
        "rx-interval": 10,
        "network": {
            "interface": "eth2",
            "address": "100.0.0.10",
            "gateway": "100.0.0.2"
        }
    },
    "igmp": {
        "group": "239.0.0.1",
        "group-iter": "0.0.0.1",
        "group-count": 100,
        "source": "100.0.0.10",
        "send-multicast-traffic": true
    }
}
```

## Manual Join/Leave Testing

It is possible to join and leave multicast groups manually using the <<Control Socket>> as 
shown in the example below.

`$ sudo ./cli.py run.sock igmp-join outer-vlan 1 inner-vlan 1 group 232.1.1.1 source1 202.11.23.101 source2 202.11.23.102 source3 202.11.23.103`
```json
{
    "status": "ok"
}
```

`$ sudo ./cli.py run.sock igmp-info outer-vlan 1 inner-vlan 1`
```json
{
    "status": "ok",
    "igmp-groups": [
        {
            "group": "232.1.1.1",
            "igmp-sources": [
                "202.11.23.101",
                "202.11.23.102",
                "202.11.23.103"
            ],
            "packets": 1291,
            "loss": 0,
            "state": "active",
            "join-delay-ms": 139
        }
    ]
}
```

`$ sudo ./cli.py run.sock igmp-leave outer-vlan 1 inner-vlan 1 group 232.1.1.1 `
```json
{
    "status": "ok"
}
```

`$ sudo ./cli.py run.sock igmp-info outer-vlan 1 inner-vlan 1`
```json
{
    "status": "ok",
    "igmp-groups": [
        {
            "group": "232.1.1.1",
            "igmp-sources": [
                "202.11.23.101",
                "202.11.23.102",
                "202.11.23.103"
            ],
            "packets": 7456,
            "loss": 0,
            "state": "idle",
            "leave-delay-ms": 114
        }
    ]
}
```

## IPTV Zapping Test

A key element of IPTV services is the delay in changing channels. 
How long does it take to change from one channel to another, is 
the right channel received and the old channel stopped without overlap 
between old and new channel which may leads into traffic congestions if 
both channels are send at the same time. Verify that fast channel changes
(zapping) works reliable as well. 

The BNG Blaster is able to emulate different client zapping behaviors and 
measure the resulting join/leave delays and possible multicast traffic loss. 

The join delay is the time in milliseconds between sending join and receiving
first multicast packet of the requested group. The leave delay is the time between
sending leave and the last multicast packet received for this group. Multicast packets
received for the leaved group after first packet of joined group is received are counted 
as overlap. 

The following <<Configuration>> output shows an example for the `igmp` section 
for a typical zapping test.

```json
{
    "igmp": {
        "version": 3,
        "start-delay": 10,
        "group": "239.0.0.1",
        "group-iter": "0.0.0.1",
        "group-count": 20,
        "source": "100.0.0.10",
        "zapping-interval": 5,
        "zapping-count": 5,
        "zapping-view-duration": 30,
        "zapping-wait": false,
        "combined-leave-join": true,
        "send-multicast-traffic": true
    }
}
```

## Multicast Limitations

The BNG Blaster IGMP implementation supports up to 3 sources per group record
and 8 group records per session. 

The IGMP protocol stops working if IPCP has closed also if session IPCP renegotiates. 
The whole session needs to be disconnected to restart IGMP. 

The check for overlapping multicast traffic is supported for zapping tests only.
