.. code-block:: json

    { "streams": {} }

+--------------------------------+------------------------------------------------------------------+
| Attribute                      | Description                                                      |
+================================+==================================================================+
| **name**                       | | Mandatory stream name.                                         |
+--------------------------------+------------------------------------------------------------------+
| **stream-group-id**            | | Stream group identifier.                                       |
|                                | | Default: 0 (raw) Range: 0 - 65535                              |
+--------------------------------+------------------------------------------------------------------+
| **type**                       | | Mandatory stream type (`ipv4`, `ipv6`, or `ipv6pd`).           |
+--------------------------------+------------------------------------------------------------------+
| **direction**                  | | Stream direction (`upstream`, `downstream`, or `both`).        |
|                                | | RAW streams (stream-group-id 0) support `downstream` only.     |
|                                | | Default: `both` (session streams), `downstream` (RAW streams)  |
+--------------------------------+------------------------------------------------------------------+
| **autostart**                  | | Enable stream autostart.                                       |
|                                | | Default: true                                                  |
+--------------------------------+------------------------------------------------------------------+
| **count**                      | | Number of instances of this stream                             |
|                                | | (per session for session streams).                             |
|                                | | Default: 1 Range: 1 - 65535                                    |
+--------------------------------+------------------------------------------------------------------+
| **source-port**                | | Overwrite the default source port.                             |
|                                | | For bidirectional streams (direction `both`), this is applied  |
|                                | | as source port in upstream and destination port in downstream. |
|                                | | Default: 65056 Range: 0 - 65535                                |
+--------------------------------+------------------------------------------------------------------+
| **source-port-step**           | | Increment the source port for each instance of this stream.    |
|                                | | See chapter Stream Iterators for details.                      |
|                                | | Default: 0 Range: 0 - 65535                                    |
+--------------------------------+------------------------------------------------------------------+
| **source-port-max**            | | Max source port before reset to `source-port`.                 |
|                                | | Default: 65535 Range: 0 - 65535                                |
+--------------------------------+------------------------------------------------------------------+
| **destination-port**           | | Overwrite the default destination port.                        |
|                                | | For bidirectional streams (direction `both`), this is applied  |
|                                | | as destination port in upstream and source port in downstream. |
|                                | | Default: 65056 Range: 0 - 65535                                |
+--------------------------------+------------------------------------------------------------------+
| **destination-port-step**      | | Increment the destination port for each instance of this       |
|                                | | stream. See chapter Stream Iterators for details.              |
|                                | | Default: 0 Range: 0 - 65535                                    |
+--------------------------------+------------------------------------------------------------------+
| **destination-port-max**       | | Max destination port before reset to `destination-port`.       |
|                                | | Default: 65535 Range: 0 - 65535                                |
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
| **inner-vlan-priority**        | | Inner VLAN priority.                                           |
|                                | | Default: **vlan-priority** Range: 0 - 7                        |
+--------------------------------+------------------------------------------------------------------+
| **length**                     | | Layer 3 (IP header + payload) traffic length.                  |
|                                | | The maximum length also depends on the I/O mode.               |
|                                | | Default: 128 Range: 76 - 9000                                  |
+--------------------------------+------------------------------------------------------------------+
| **ttl**                        | | TTL.                                                           |
|                                | | Default: 64 Range: 0 - 255                                     |
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
| **pps-upstream**               | | Optionally overwrite PPS in upstream to support bidirectional  |
|                                | | streams with different rates for upstream and downstream.      |
+--------------------------------+------------------------------------------------------------------+
| **bps-upstream**               | | Optionally overwrite bps in upstream to support bidirectional  |
|                                | | streams with different rates for upstream and downstream.      |
|                                | | The K, M and G prefixes are supported as well,                 |
|                                | | for example, ``"Gbps-upstream": 1``.                           |
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
| **destination-mac**            | | Overwrite destination MAC address (downstream only).           |
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
|                                | | Range: 0 - 1048575                                             |
+--------------------------------+------------------------------------------------------------------+
| **tx-label1-exp**              | | EXP bits of the first label (outer label).                     |
|                                | | Default: 0 Range: 0 - 7                                        |
+--------------------------------+------------------------------------------------------------------+
| **tx-label1-ttl**              | | TTL of the first label (outer label).                          |
|                                | | Default: 255 Range: 0 - 255                                    |
+--------------------------------+------------------------------------------------------------------+
| **tx-label2**                  | | MPLS send (TX) label (inner label).                            |
|                                | | Range: 0 - 1048575                                             |
+--------------------------------+------------------------------------------------------------------+
| **tx-label2-exp**              | | EXP bits of the second label (inner label).                    |
|                                | | Default: 0 Range: 0 - 7                                        |
+--------------------------------+------------------------------------------------------------------+
| **tx-label2-ttl**              | | TTL of the second label (inner label).                         |
|                                | | Default: 255 Range: 0 - 255                                    |
+--------------------------------+------------------------------------------------------------------+
| **rx-label1**                  | | Expected receive MPLS label (outer label).                     |
|                                | | Range: 0 - 1048575                                             |
+--------------------------------+------------------------------------------------------------------+
| **rx-label2**                  | | Expected receive MPLS label (inner label).                     |
|                                | | Range: 0 - 1048575                                             |
+--------------------------------+------------------------------------------------------------------+
| **ldp-ipv4-lookup-address**    | | Dynamically resolve outer label.                               |
+--------------------------------+------------------------------------------------------------------+
| **ldp-ipv6-lookup-address**    | | Dynamically resolve outer label.                               |
+--------------------------------+------------------------------------------------------------------+
| **bgp-evpn-rd**                | | Dynamically resolve inner label from a BGP EVPN route          |
|                                | | with this route distinguisher (e.g. 65001:100 or 10.0.0.1:5).  |
|                                | | Requires a BGP session with learn-routes and family evpn.      |
|                                | | Not supported with tx-label2.                                  |
+--------------------------------+------------------------------------------------------------------+
| **bgp-evpn-ethernet-tag**      | | Ethernet tag of the BGP EVPN route. Without bgp-evpn-mac and   |
|                                | | bgp-evpn-prefix, the label of the Ethernet A-D per EVI route   |
|                                | | (type 1) is used for EVPN VPWS (E-LINE) where stream packets   |
|                                | | are sent as Ethernet over MPLS to the destination-mac.         |
|                                | | EVPN VPWS requires this option to be set explicitly, RAW       |
|                                | | streams and destination-mac (unless vpws-arp is enabled).      |
|                                | | Default: 0 Range: 0 - 4294967295 (max 4294967294 for VPWS)     |
+--------------------------------+------------------------------------------------------------------+
| **bgp-evpn-esi**               | | ESI of the Ethernet A-D route (type 1). Not supported with     |
|                                | | bgp-evpn-mac or bgp-evpn-prefix.                               |
|                                | | Default: 00:00:00:00:00:00:00:00:00:00                         |
+--------------------------------+------------------------------------------------------------------+
| **vpws-vlan**                  | | Customer VLAN within the EVPN VPWS, E-LAN or L2VPN service.    |
|                                | | All vpws-* options require EVPN VPWS, E-LAN or L2VPN.          |
|                                | | Range: 1 - 4094                                                |
+--------------------------------+------------------------------------------------------------------+
| **vpws-inner-vlan**            | | Customer inner VLAN within the EVPN VPWS, E-LAN or L2VPN       |
|                                | | service.                                                       |
|                                | | Requires vpws-vlan.                                            |
|                                | | Range: 1 - 4094                                                |
+--------------------------------+------------------------------------------------------------------+
| **vpws-vlan-priority**         | | Customer VLAN priority. Requires vpws-vlan.                    |
|                                | | Default: 0 Range: 0 - 7                                        |
+--------------------------------+------------------------------------------------------------------+
| **vpws-inner-vlan-priority**   | | Customer inner VLAN priority. Requires vpws-inner-vlan.        |
|                                | | Default: 0 Range: 0 - 7                                        |
+--------------------------------+------------------------------------------------------------------+
| **vpws-qinq**                  | | Customer outer VLAN ethertype 0x88a8 instead of 0x8100.        |
|                                | | Requires vpws-vlan.                                            |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
| **vpws-arp**                   | | Reply to ARP, IPv6 neighbor solicitation and ICMP/ICMPv6       |
|                                | | echo requests for the network-ipv4-address or                  |
|                                | | network-ipv6-address received within the EVPN VPWS, E-LAN or   |
|                                | | L2VPN service. Without destination-mac (not E-LAN), the stream |
|                                | | waits until the customer MAC is learned from those requests.   |
|                                | | Requires stream type ipv4 with network-ipv4-address or ipv6    |
|                                | | with network-ipv6-address.                                     |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
| **rx-control-word**            | | Expect pseudowire control word for received Ethernet over      |
|                                | | MPLS traffic (e.g. EVPN VPWS or E-LAN).                        |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
| **tx-control-word**            | | Send pseudowire control word for EVPN VPWS, E-LAN or L2VPN     |
|                                | | traffic. EVPN VPWS and L2VPN streams add the control word also |
|                                | | if requested by the remote PE, which is not signaled for EVPN  |
|                                | | E-LAN.                                                         |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
| **bgp-evpn-elan**              | | EVPN E-LAN where stream packets are sent as Ethernet over MPLS |
|                                | | to the destination-mac (required) using label1 of the MAC/IP   |
|                                | | advertisement route (type 2) of this MAC address (known        |
|                                | | unicast) or the ingress replication label of the IMET route    |
|                                | | (type 3) with the same route distinguisher and Ethernet tag    |
|                                | | (unknown unicast). Requires RAW streams. Not supported with    |
|                                | | bgp-evpn-mac, bgp-evpn-prefix or bgp-evpn-esi.                 |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
| **bgp-l2vpn-rd**               | | Dynamically resolve the pseudowire label from the BGP L2VPN    |
|                                | | label block (RFC 6624) of the remote CE with this route        |
|                                | | distinguisher. Stream packets are sent as Ethernet over MPLS   |
|                                | | to the destination-mac (unless vpws-arp is enabled). Requires  |
|                                | | a BGP session with learn-routes and family l2vpn, RAW streams, |
|                                | | bgp-l2vpn-ce-id and bgp-l2vpn-local-ce-id. Not supported with  |
|                                | | bgp-evpn-rd or tx-label2.                                      |
+--------------------------------+------------------------------------------------------------------+
| **bgp-l2vpn-ce-id**            | | CE ID of the remote CE (L2VPN site identifier of the DUT).     |
|                                | | Range: 0 - 65535                                               |
+--------------------------------+------------------------------------------------------------------+
| **bgp-l2vpn-local-ce-id**      | | CE ID of the local CE emulated by the BNG Blaster, which must  |
|                                | | be covered by the label block of the remote CE. The label is   |
|                                | | label base + local CE ID - label block offset.                 |
|                                | | Range: 0 - 65535                                               |
+--------------------------------+------------------------------------------------------------------+
| **bgp-evpn-mac**               | | Use label2 of the MAC/IP advertisement route (type 2).         |
+--------------------------------+------------------------------------------------------------------+
| **bgp-evpn-ip**                | | IP address of the MAC/IP advertisement route (type 2).         |
|                                | | Requires bgp-evpn-mac.                                         |
+--------------------------------+------------------------------------------------------------------+
| **bgp-evpn-prefix**            | | Use the label of the IP prefix route (type 5). The address     |
|                                | | family must match the stream type. Not supported with          |
|                                | | bgp-evpn-mac.                                                  |
+--------------------------------+------------------------------------------------------------------+
| **nat**                        | | Enable NAT support.                                            |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
| **raw-tcp**                    | | Send RAW TCP traffic (UDP-like traffic with TCP header).       |
|                                | | Default: false                                                 |
+--------------------------------+------------------------------------------------------------------+
