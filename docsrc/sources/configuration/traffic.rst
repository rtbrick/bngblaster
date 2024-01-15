.. code-block:: json

    { "traffic": {} }

+------------------------------+--------------------------------------------------------+
| Attribute                    | Description                                            |
+==============================+========================================================+
| **autostart**                | | Automatically start traffic.                         |
|                              | | Default: true                                        |
+------------------------------+--------------------------------------------------------+
| **stop-verified**            | | Automatically stop traffic streams if verified.      |
|                              | | Default: false                                       |
+------------------------------+--------------------------------------------------------+
| **max-burst**                | | Stream flow burst size in packets.                   |
|                              | | Default: 16                                          |
+------------------------------+--------------------------------------------------------+
| **stream-rate-calculation**  | | Enable stream rate calculation.                      |
|                              | | This option should be set to false if massive        |
|                              | | streams (e.g. more than 1M) are defined but          |
|                              | | per-stream live rate statistics are not required.    |
|                              | | Default: true                                        |
+------------------------------+--------------------------------------------------------+
| **stream-delay-calculation** | | Enable stream delay calculation.                     |
|                              | | This option should be set to false if massive        |
|                              | | streams (e.g. more than 1M) are defined but          |
|                              | | per-stream delay measurements are not required.      |
|                              | | Default: true                                        |
+------------------------------+--------------------------------------------------------+