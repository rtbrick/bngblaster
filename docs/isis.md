# ISIS

The BNG Blaster is able to emulate ISIS.

Following an example ISIS configuration with one instance 
attached to two network interfaces.

```json
{
    "interfaces": {
        "network": [
            {
                "interface": "eth1",
                "address": "10.0.1.2/24",
                "gateway": "10.0.1.1",
                "address-ipv6": "fc66:1337:7331:1::2/64",
                "gateway-ipv6": "fc66:1337:7331:1::1",
                "isis-instance-id": 1,
                "isis-level": 1,
                "isis-l1-metric": 100,
            },
            {
                "interface": "eth2",
                "address": "10.0.2.2/24",
                "gateway": "10.0.2.1",
                "address-ipv6": "fc66:1337:7331:2::2/64",
                "gateway-ipv6": "fc66:1337:7331:2::1",
                "isis-instance-id": 1
            }
        ]
    },
    "isis": [
        {
            "instance-id": 1,
            "system-id": "0100.1001.0010",
            "router-id": "10.10.10.10",
            "hostname": "R1",
            "hello-padding": true,
            "lsp-lifetime": 65535,
            "level1-auth-key": "secret",
            "level1-auth-type": "md5",
            "sr-base": 2000,
            "sr-range": 3600
        }
    ]
}
```

All supported ISIS [configuration](config) options and 
[commands](ctrl) are detailed explained corresponding 
sections.

## MRT Files

The BNG Blaster is able to load LSP's from a MRT file as defined in 
[RFC6396](https://datatracker.ietf.org/doc/html/rfc6396).

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           Timestamp                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |             Type              |            Subtype            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             Length                            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                      Message... (variable)
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The message field contains the complete ISIS LSP PDU including 
the ISIS common header starting with `0x83`. 

Those files can be loaded at startup via configuration option 
`"isis": { "external": { "mrt-file": "<file>" } }` or alternative
via `isis-lsp-update` command. 

## Limitations

Currently only ISIS P2P links are supported. 

## Scapy 

The following example shows how to generate LSP's via Scapy 
and inject them using the `isis-lsp-update` command. 

```python
import sys
import socket
import os
import json

from scapy.contrib.isis import *

def error(*args, **kwargs):
    """print error and exit"""
    print(*args, file=sys.stderr, **kwargs)
    sys.exit(1)


def execute_command(socket_path, request):
    if os.path.exists(socket_path):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(socket_path)
            client.send(json.dumps(request).encode('utf-8'))
            data = ""
            while True:
                junk = client.recv(1024)
                if junk:
                    data += junk.decode('utf-8')
                else:
                    break
            print(json.dumps(json.loads(data), indent=4))
        except Exception as e:
            error(e)
        finally:
            client.close()
    else:
        error("socket %s not found" % socket_path)


def main():
    """main function"""
    socket_path = sys.argv[1]

    command = {
        "command": "isis-lsp-update",
        "arguments": {
            "instance": 1, 
            "pdu": []
        }    
    }

    tlvs = ISIS_AreaTlv(areas=ISIS_AreaEntry(areaid='49.0001'))
    pdu = ISIS_CommonHdr()/ISIS_L1_LSP(lifetime=65535, lspid='0102.0304.0506.00-00', seqnum=3, tlvs=tlvs)
    command["arguments"]["pdu"].append(pdu.build().hex())

    pdu = ISIS_CommonHdr()/ISIS_L1_LSP(lifetime=65535, lspid='0102.0304.0506.00-01', seqnum=3, tlvs=tlvs)
    command["arguments"]["pdu"].append(pdu.build().hex())

    execute_command(socket_path, command)


if __name__ == "__main__":
    main()

```