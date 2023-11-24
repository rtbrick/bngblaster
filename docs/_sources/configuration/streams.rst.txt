.. code-block:: json

    { "streams": {} }

+--------------------------------+------------------------------------------------------------------+
| Attribute                      | Description                                                      |
+--------------------------------+------------------------------------------------------------------+
| **name**                       | | Mandatory stream name.                                         |
+--------------------------------+------------------------------------------------------------------+
| **stream-group-id**            | | Stream group identifier.                                       |
|                                | | Default: 0 (raw)                                               |
+--------------------------------+------------------------------------------------------------------+
| **type**                       | | Mandatory stream type (`ipv4`, `ipv6`, or `ipv6pd`).           |
+--------------------------------+------------------------------------------------------------------+
| **direction**                  | | Stream direction (`upstream`, `downstream`, or `both`).        |
|                                | | Default: `both`                                                |
+--------------------------------+------------------------------------------------------------------+
| **source-port**                | | Overwrite the default source port.                             |
|                                | | Default: 65056 Range: 0 - 65535                                |
+--------------------------------+------------------------------------------------------------------+
| **destination-port**           | | Overwrite the default destination port.                        |
|                                | | Default: 65056 Range: 0 - 65535                                |
+--------------------------------+------------------------------------------------------------------+
| **ipv4-df**                    | | Set IPv4 DF bit.                                               |
|                                | | Default: true                                                  |
+--------------------------------+------------------------------------------------------------------+
| **priority**                   | | IPv4 TOS / IPv6 TC.                                            |
|                                | | For L2TP downstream traffic, the IPv4 TOS is applied           |
|                                | | to the outer IPv4 and inner IPv4 header.                       |
|                                | | Default: 0 Range: 0 - 255                                      |
+--------------------------------+------------------------------------------------------------------+
| **vlan-priority**              | | VLAN priority.                                                 |
|                                | | Default: 0 Range: 0 - 7                                        |
+--------------------------------+------------------------------------------------------------------+
| **length**                     | | Layer 3 (IP header + payload) traffic length.                  |
|                                | | Default: 128 Range: 76 - 9000                                  |
+--------------------------------+------------------------------------------------------------------+
| **pps**                        | | Stream traffic rate in packets per second.                     |
|                                | | This value supports also float numbers like 0.1 or 2.5.        |
|                                | | In example 0.1 means one packet every 10 seconds.              |
|                                | | Default: 1.0                                                   |
+--------------------------------+------------------------------------------------------------------+
| **bps**                        | | Stream traffic rate in bits per second (layer 3).              |
|                                | | PPS has priority over bps where the second is only a helper    |
|                                | | to calculate the actual PPS based on given bps and length.     |
|                                | | The resulting rate in bps is the layer 3 rate because length   |
|                                | | is also the layer 3 length (IP header + payload).              |
|                                | | It is also supported to put the capital letters K (Kilo),      |
|                                | | M (Mega) or G (Giga) in front of bps for better readability.   |
|                                | | For example, ``"Gbps": 1``                                     |
|                                | | which is equal to ``"bps": 1000000000``.                       |
+--------------------------------+------------------------------------------------------------------+
| **setup-interval**             | | Set optional setup interval in seconds. If set, sent max 1     |
|                                | | packet per setup interval until stream becomes verified.       |
|                                | | After setup is done, the actual rate will be applied.          |
|                                | | For bidirectional streams (direction both), this requires both |
|                                | | directions to be verified.                                     |
|                                | | Default: 0 (disabled) Range: 0 - 900                           |
+--------------------------------+------------------------------------------------------------------+
| **a10nsp-interface**           | | Select the corresponding A10NSP interface for this stream.     |
+--------------------------------+------------------------------------------------------------------+
| **network-interface**          | | Select the corresponding network interface for this stream.    |
+--------------------------------+------------------------------------------------------------------+
| **network-ipv4-address**       | | Overwrite network interface IPv4 address.                      |
+--------------------------------+------------------------------------------------------------------+
| **network-ipv6-address**       | | Overwrite network interface IPv6 address.                      |
+--------------------------------+------------------------------------------------------------------+
| **destination-ipv4-address**   | | Overwrite the IPv4 destination address.                        |
+--------------------------------+------------------------------------------------------------------+
| **destination-ipv6-address**   | | Overwrite the IPv6 destination address.                        |
+--------------------------------+------------------------------------------------------------------+
| **access-ipv4-source-address** | | Overwrite the access IPv4 source address (client).             |
|                                | | This option can be used to test the BNG RPF functionality      |
|                                | | with traffic sent from source addresses different than those   |
|                                | | assigned to the client.                                        |
+--------------------------------+------------------------------------------------------------------+
| **access-ipv6-source-address** | | Overwrite the access IPv6 source address (client).             |
|                                | | This option can be used to test the BNG RPF functionality      |
|                                | | with traffic sent from source addresses different than those   |
|                                | | assigned to the client.                                        |
+--------------------------------+------------------------------------------------------------------+
| **max-packets**                | | Send a burst of N packets and stop.                            |
|                                | | Default: 0 (infinity)                                          |
+--------------------------------+------------------------------------------------------------------+
| **start-delay**                | | Wait N seconds after the session is established                |
|                                | | before starting the traffic stream.                            |
|                                | | Default: 0                                                     |
+--------------------------------+------------------------------------------------------------------+
| **tx-label1**                  | | MPLS send (TX) label (outer label).                            |
+--------------------------------+------------------------------------------------------------------+
| **tx-label1-exp**              | | EXP bits of the first label (outer label).                     |
|                                | | Default: 0                                                     |
+--------------------------------+------------------------------------------------------------------+
| **tx-label1-ttl**              | | TTL of the first label (outer label).                          |
|                                | | Default: 255                                                   |
+--------------------------------+------------------------------------------------------------------+
| **tx-label2**                  | | MPLS send (TX) label (inner label).                            |
+--------------------------------+------------------------------------------------------------------+
| **tx-label2-exp**              | | EXP bits of the second label (inner label).                    |
|                                | | Default: 0                                                     |
+--------------------------------+------------------------------------------------------------------+
| **tx-label2-ttl**              | | TTL of the second label (inner label).                         |
|                                | | Default: 255                                                   |
+--------------------------------+------------------------------------------------------------------+
| **rx-label1**                  | | Expected receive MPLS label (outer label).                     |
+--------------------------------+------------------------------------------------------------------+
| **rx-label2**                  | | Expected receive MPLS label (inner label).                     |
+--------------------------------+------------------------------------------------------------------+
| **ldp-ipv4-lookup-address**    | | Dynamically resolve outer label.                               |
+--------------------------------+------------------------------------------------------------------+
| **ldp-ipv6-lookup-address**    | | Dynamically resolve outer label.                               |
+--------------------------------+------------------------------------------------------------------+
| **nat**                        | | Enable NAT support.                                            |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
| **raw-tcp**                    | | Send RAW TCP traffic (UDP-like traffic with TCP header).       |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
