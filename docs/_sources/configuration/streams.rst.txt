.. code-block:: json

    { "streams": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `name`
     - Mandatory stream name
     - 
   * - `stream-group-id`
     - Stream group identifier
     - 0 (raw)
   * - `type`
     - Mandatory stream type (`ipv4`, `ipv6` or `ipv6pd`)
     - 
   * - `direction`
     - Mandatory stream direction (`upstream`, `downstream` or `both`)
     - `both`
   * - `source-port`
     - Overwrite the default source port
     - 65056
   * - `destination-port`
     - Overwrite the default destination port
     - 65056
   * - `ipv4-df`
     - Set IPv4 DF bit
     - true
   * - `priority`
     - IPv4 TOS / IPv6 TC
     - 0
   * - `vlan-priority`
     - VLAN priority
     - 0
   * - `length`
     - Layer 3 (IP header + payload) traffic length (76 - 9000)
     - 128
   * - `pps`
     - Stream traffic rate in packets per second
     - 1
   * - `bps`
     - Stream traffic rate in bits per second (layer 3)
     - 
   * - `a10nsp-interface`
     - Select the corresponding A10NSP interface for this stream
     - 
   * - `network-interface`
     - Select the corresponding network interface for this stream
     - 
   * - `network-ipv4-address`
     - Overwrite network interface IPv4 address
     - 
   * - `network-ipv6-address`
     - Overwrite network interface IPv6 address
     - 
   * - `destination-ipv4-address`
     - Overwrite the IPv4 destination address
     - 
   * - `destination-ipv6-address`
     - Overwrite the IPv6 destination address
     - 
   * - `access-ipv4-source-address`
     - Overwrite the access IPv4 source address (client)
     - 
   * - `access-ipv6-source-address`
     - Overwrite the access IPv6 source address (client)
     - 
   * - `max-packets`
     - Send a burst of N packets and stop
     - 0 (infinity)
   * - `start-delay`
     - Wait N seconds after the session is established before starting
     - 0
   * - `tx-label1`
     - MPLS send (TX) label (outer label)
     - 
   * - `tx-label1-exp`
     - EXP bits of the first label (outer label)
     - 0
   * - `tx-label1-ttl`
     - TTL of the first label (outer label)
     - 255
   * - `tx-label2`
     - MPLS send (TX) label (inner label)
     - 
   * - `tx-label2-exp`
     - EXP bits of the second label (inner label)
     - 0
   * - `tx-label2-ttl`
     - TTL of the second label (inner label)
     - 255
   * - `rx-label1`
     - Expected receive MPLS label (outer label)
     - 
   * - `rx-label2`
     - Expected receive MPLS label (inner label)
     - 
   * - `ldp-ipv4-lookup-address`
     - Dynamically resolve outer label 
     - 

For L2TP downstream traffic, the IPv4 TOS is applied to the outer IPv4 
and inner IPv4 header.

The ``pps`` option supports also float numbers like 0.1, or 2.5 PPS and has 
priority over ``bps`` where the second is only a helper to calculate the ``pps`` 
based on given ``bps`` and ``length``. The resulting rate in ``bps`` is the 
layer 3 rate because ``length`` is also the layer 3 length (IP header + payload).
It is also supported to put the capital letters ``K`` (Kilo), ``M`` (Mega) 
or ``G`` (Giga) in front of ``bps`` for better readability. 
For example ``"Gbps": 1`` which is equal to ``"bps": 1000000000``. 

The options ``access-ipv4-source-address`` and ``access-ipv6-source-address`` 
can be used to test the BNG RPF functionality with traffic sent from source addresses 
different than those assigned to the client. 
