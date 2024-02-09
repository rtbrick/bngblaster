.. code-block:: json

    { "interfaces": {} }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **io-mode**                       | | IO mode.                                                           |
|                                   | | The supported IO modes are listed with ``bngblaster -v``           |
|                                   | | but except ``packet_mmap_raw`` all other modes are currently       |
|                                   | | considered experimental. In the default mode (``packet_mmap_raw``) |
|                                   | | all packets are received in a Packet MMAP ring buffer and sent     |
|                                   | | directly through RAW packet sockets.                               |
|                                   | | Default: packet_mmap_raw                                           |
+-----------------------------------+----------------------------------------------------------------------+
| **io-slots**                      | | IO slots (ring size).                                              |
|                                   | | It might be also needed to increase the **io-slots** to            |
|                                   | | reach the desired throughput. The actual meaning of IO slots       |
|                                   | | depends on the selected IO mode. For Packet MMAP, it defines the   |
|                                   | | maximum number of packets in the ring buffer.                      |
|                                   | | Default: 4096                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **io-burst**                      | | IO burst (ring size).                                              |
|                                   | | Default: 256                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **qdisc-bypass**                  | | Bypass the kernel's qdisc layer.                                   |
|                                   | | It's currently not recommended to change the default (issue #206)! |
|                                   | | Default: true                                                      |
+-----------------------------------+----------------------------------------------------------------------+
| **tx-interval**                   | | TX polling interval in milliseconds.                               |
|                                   | | Default: 0.1 Range: 0.0001 to 1000                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **rx-interval**                   | | RX polling interval in milliseconds.                               |
|                                   | | Default: 0.1 Range: 0.0001 to 1000                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **tx-threads**                    | | Number of TX threads per interface link.                           |
|                                   | | Default: 0 (main thread)                                           |
+-----------------------------------+----------------------------------------------------------------------+
| **rx-threads**                    | | Number of RX threads per interface link.                           |
|                                   | | Default: 0 (main thread)                                           |
+-----------------------------------+----------------------------------------------------------------------+
| **capture-include-streams**       | | Include traffic streams in the capture.                            |
|                                   | | Default: false                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **mac-modifier**                  | | Third byte of access session MAC address (0-255). This option      |
|                                   | | allows to run multiple BNG Blaster instances with disjoint session |
|                                   | | MAC addresses.                                                     |
|                                   | | Default: 0                                                         |
+-----------------------------------+----------------------------------------------------------------------+