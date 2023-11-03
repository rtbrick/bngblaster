.. code-block:: json

    { "ldp": {} }

+----------------------------------+------------------------------------------------------------+
| Attribute                        | Description                                                |
+==================================+============================================================+
| **instance-id**                  | | LDP instance identifier.                                 |
+----------------------------------+------------------------------------------------------------+
| **keepalive-time**               | | LDP session keepalive time in seconds.                   |
|                                  | | The **keepalive-time** defines the local LDP session     |
|                                  | | keepalive timeout. Each LDP peer must calculate the      |
|                                  | | effective keepalive timeout by using the smaller of its  |
|                                  | | locally defined and received timeout in the PDU. The     |
|                                  | | value chosen indicates the maximum number of seconds     |
|                                  | | that may elapse between the receipt of successive PDUs   |
|                                  | | from the LDP peer on the session TCP connection. The     |
|                                  | | keepalive timeout is reset each time a PDU arrives. The  |
|                                  | | BNG Blaster will send keepalive messages at an interval  |
|                                  | | calculated by using the effective keepalive time divided |
|                                  | | by 3. Assuming an effective keepalive time of of 15      |
|                                  | | seconds results in a keepalive interval of 5 seconds.    |
|                                  | | Default: 15 Range: 0 - 65535                             |
+----------------------------------+------------------------------------------------------------+
| **hold-time**                    | | LDP hello hold time in seconds.                          |
|                                  | | Default: 15 Range: 0 - 65535                             |
+----------------------------------+------------------------------------------------------------+
| **teardown-time**                | | LDP teardown time in seconds.                            |
|                                  | | Default: 5 Range: 0 - 65535                              |
+----------------------------------+------------------------------------------------------------+
| **hostname**                     | | LDP hostname.                                            |
|                                  | | Default: bngblaster                                      |
+----------------------------------+------------------------------------------------------------+
| **lsr-id**                       | | LDP LSR identifier.                                      |
|                                  | | Default: 10.10.10.10                                     |
+----------------------------------+------------------------------------------------------------+
| **ipv6-transport-address**       | | LDP transport IPv6 address.                              |
|                                  | | Setting a valid IPv6 address here enables LDP IPv6       |
|                                  | | hello and transport.                                     |
+----------------------------------+------------------------------------------------------------+
| **ipv4-transport-address**       | | LDP transport IPv4 address.                              |
|                                  | | Default: `lsr-id`                                        |
+----------------------------------+------------------------------------------------------------+
| **no-ipv4-transport**            | | Disable/discard IPv4 LDP hello messages.                 |
+----------------------------------+------------------------------------------------------------+
| **prefer-ipv4-transport**        | | According to RFC7552, IPv6 is preferred over IPv4 which  |
|                                  | | can be changed with this option to prefer IPv4 transport |
|                                  | | even if IPv6 is enabled.                                 |
|                                  | | Default: false                                           |
+----------------------------------+------------------------------------------------------------+
| **raw-update-file**              | | LDP RAW update file.                                     |
+----------------------------------+------------------------------------------------------------+