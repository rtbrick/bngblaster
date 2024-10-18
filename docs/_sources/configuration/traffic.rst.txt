.. code-block:: json

    { "traffic": {} }

+---------------------------------+--------------------------------------------------------+
| Attribute                       | Description                                            |
+=================================+========================================================+
| **autostart**                   | | Automatically start traffic globally.                |
|                                 | | This option control the initial state of the global  |
|                                 | | signal to control transmission of traffic streams.   |
|                                 | | Default: true                                        |
+---------------------------------+--------------------------------------------------------+
| **stop-verified**               | | Automatically stop traffic streams if verified.      |
|                                 | | Default: false                                       |
+---------------------------------+--------------------------------------------------------+
| **stream-autostart**            | | Enable stream autostart.                             |
|                                 | | Default: true                                        |
+---------------------------------+--------------------------------------------------------+
| **stream-rate-calculation**     | | Enable stream rate calculation.                      |
|                                 | | This option should be set to false if massive        |
|                                 | | streams (e.g. more than 1M) are defined but          |
|                                 | | per-stream live rate statistics are not required.    |
|                                 | | Default: true                                        |
+---------------------------------+--------------------------------------------------------+
| **stream-delay-calculation**    | | Enable stream delay calculation.                     |
|                                 | | This option should be set to false if massive        |
|                                 | | streams (e.g. more than 1M) are defined but          |
|                                 | | per-stream delay measurements are not required.      |
|                                 | | Default: true                                        |
+---------------------------------+--------------------------------------------------------+
| **stream-burst-ms**             | | This option controls the maximum burst size per      |
|                                 | | stream, measured in milliseconds. It regulates       |
|                                 | | how data is sent in bursts over a stream within the  |
|                                 | | specified time interval. Setting this option         |
|                                 | | determines the balance between throughput consistency|
|                                 | | and burst behavior. The value directly influences the|
|                                 | | distribution of traffic bursts within a stream,      |
|                                 | | affecting how closely the stream rate adheres to the |
|                                 | | desired target. A smaller burst size can lead to     |
|                                 | | smoother traffic, reducing the risk of micro-bursts, |
|                                 | | but may result in the stream rate falling below the  |
|                                 | | intended target. A larger burst size increases the   |
|                                 | | risk of micro-bursts. This value should be based     |
|                                 | | on the tolerance for traffic bursts and the required |
|                                 | | stream rate. Testing different values is recommended |
|                                 | | to find the optimal balance between maintaining the  |
|                                 | | target rate and preventing large bursts.             |
|                                 | | Default: 100 Range: 1 - 1000                         |
+---------------------------------+--------------------------------------------------------+
| **multicast-traffic-autostart** | | Automatically start multicast traffic.               |
|                                 | | Default: true                                        |
+---------------------------------+--------------------------------------------------------+
| **udp-checksum**                | | Enable UDP checksums.                                |
|                                 | | Default: false                                       |
+---------------------------------+--------------------------------------------------------+