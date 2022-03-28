# BGP

The Border Gateway Protocol (BGP) is a standardized exterior gateway protocol
designed to exchange routing and reachability information among autonomous systems
(AS) on the internet. BGP is classified as a path-vector routing protocol, and it 
makes routing decisions based on paths, network policies, or rule-sets configured 
by a network operator.

Following an example BGP configuration with one session.

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

## BGP Sessions

Every BGP session is opened with the capabilities for the following
address families:

+ IPv4 unicast
+ IPv4 labelled unicast
+ IPv6 unicast
+ IPv6 labelled unicast

## Limitations

BGP authentication is currently not supported but already 
planned as enhancement in one of the next releases. 

## RAW Update Files

The BNG Blaster is able to inject BGP messages from a pre-compiled 
RAW update file into the defined sessions. A RAW update file is not
more than a pre-compiled binary stream of BGP messages, typically
but not limited to update messages.

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 +                                                               +
 |                                                               |
 +                                                               +
 |                           Marker                              |
 +                                                               +
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Length               |      Type     | ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++++
 .
 .
 .
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 +                                                               +
 |                                                               |
 +                                                               +
 |                           Marker                              |
 +                                                               +
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Length               |      Type     | ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++++
```

Those files can be created using the included BGP RAW update generator
script `bgpupdate` or manually using libraries like scapy or converters
from PCAP or MRT files. 

The configured `raw-update-file` under the BGP session is loaded 
during Blaster startup phase and send as soon as the session is 
established. 

The `bgp-raw-update` command allows to send further updates during
the session lifetime.

`$ sudo bngblaster-cli run.sock bgp-raw-update file update1.bgp`

This allows in example to load a full table after session has
started and manually trigger a series of changes using incremental
updates files.

All BGP RAW update files are loaded once and can than be used by 
multiple sessions. Meaning if two or more sessions reference the 
same file identified by file name, this file is loaded once into 
memory and used by multiple sessions. 

Therefore for incremental updates, it may makes sense to pre-load
via `bgp-raw-update-files` configuration. 

```json
{
    "bgp": [
        {
            "local-ipv4-address": "10.0.1.2",
            "peer-ipv4-address": "10.0.1.1",
            "raw-update-file": "start.bgp",
            "local-as": 65001,
            "peer-as": 65001
        }
    ],
    "bgp-raw-update-files": [
        "update1.bgp",
        "update2.bgp"
    ]
}
```

Incremental updates not listed here will be loaded dynamically as soon
as referenced by first session.

## BGP RAW Update Generator

The BGP RAW update generator is a simple tool to generate BGP RAW update
streams for use with the BNG Blaster. 

```text
$ bgpupdate --help
usage: bgpupdate [-h] [-a ASN] -n ADDRESS [-N N] -p PREFIX [-P N] [-m LABEL]
                 [-M N] [-l LOCAL_PREF] [-f FILE] [-w] [--end-of-rib]
                 [--append] [--pcap FILE] [--log-level {warning,info,debug}]

optional arguments:
  -h, --help            show this help message and exit
  -a ASN, --asn ASN     autonomous system number
  -n ADDRESS, --next-hop-base ADDRESS
                        next-hop base address (IPv4 or IPv6)
  -N N, --next-hop-num N
                        next-hop count
  -p PREFIX, --prefix-base PREFIX
                        prefix base network (IPv4 or IPv6)
  -P N, --prefix-num N  prefix count
  -m LABEL, --label-base LABEL
                        label base
  -M N, --label-num N   label count
  -l LOCAL_PREF, --local-pref LOCAL_PREF
                        local preference
  -f FILE, --file FILE  output file
  -w, --withdraw        withdraw prefixes
  --end-of-rib          add end-of-rib message
  --append              append to file if exist
  --pcap FILE           write BGP updates to PCAP file
  --log-level {warning,info,debug}
                        logging Level
```

The python BGP RAW update generator is a python script which uses
scapy to build BGP messages. Therefore this tool can be easily 
modified, extend or used as blueprint for your own tools to generate
valid BGP update streams. 
