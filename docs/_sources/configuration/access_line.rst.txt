This feature is designed to simulate various access line attributes defined by the Broadband Forum, 
which are subsequently employed in protocols such as PPPoE discovery, DHCPv4, and DHCPv6 packets. 

The values defined in **access-line** section apply globally but can be overwritten in the 
access interface section. The strings agent-remote-id, agent-circuit-id, and 
access-aggregation-circuit-id support :ref:`variable substitution <variables>`.

.. code-block:: json

    { "access-line": {} }

+---------------------------------------------+------------------------------------------------------------+
| Attribute                                   | Description                                                |
+===================================+======================================================================+
| **agent-circuit-id**                        | | Agent-Circuit-Id (string).                               |
+---------------------------------------------+------------------------------------------------------------+
| **agent-remote-id**                         | | Agent-Remote-Id (string).                                |
+---------------------------------------------+------------------------------------------------------------+
| **access-aggregation-circuit-id**           | | Access-Aggregation-Circuit-ID-ASCII (string).            |
+---------------------------------------------+------------------------------------------------------------+
| **rate-up**                                 | | Actual Data Rate Upstream.                               |
|                                             | | Default: 0 Range: 0 - 4294967295                         |
+---------------------------------------------+------------------------------------------------------------+
| **rate-down**                               | | Actual Data Rate Downstream.                             |
|                                             | | Default: 0 Range: 0 - 4294967295                         |
+---------------------------------------------+------------------------------------------------------------+
| **dsl-type**                                | | DSL-Type.                                                |
|                                             | | Default: 0 Range: 0 - 4294967295                         |
+---------------------------------------------+------------------------------------------------------------+

Attributes with values set to zero will be automatically excluded, 
making it impossible to send attributes with a zero value. In other words, 
any attribute that has a value of zero will not be included in the corresponding
packets.

In the context of DHCPv6, access line attributes, as well as Agent-Remote-Id or Agent-Circuit-Id, 
are exclusively permitted in DHCPv6 relay-forward messages as dictated by RFC. By default, BNG Blaster 
includes these attributes in other DHCPv6 messages, even if this deviates from RFC guidelines. 
Therefore, the DHCPv6 configuration section provides the option to either disable access-line attributes or, 
as an alternative, enable LDRA (Lightweight DHCPv6 Relay Agent). 