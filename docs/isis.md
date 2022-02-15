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

All supported configuration options are detailed explained 
in the configuration section.

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

## Limitations

Currently only ISIS P2P links are supported. 