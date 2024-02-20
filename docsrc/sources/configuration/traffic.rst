.. code-block:: json

    { "traffic": {} }

+------------------------------+--------------------------------------------------------+
| Attribute                    | Description                                            |
+==============================+========================================================+
| **autostart**                | | Automatically start traffic globally.                |
|                              | | This option control the initial state of the global  |
|                              | | signal to control transmission of traffic streams.   |
|                              | | Default: true                                        |
+------------------------------+--------------------------------------------------------+
| **stop-verified**            | | Automatically stop traffic streams if verified.      |
|                              | | Default: false                                       |
+------------------------------+--------------------------------------------------------+
| **max-burst**                | | Stream flow burst size in packets.                   |
|                              | | Default: 16                                          |
+------------------------------+--------------------------------------------------------+
| **stream-autostart**         | | Enable stream autostart.                             |
|                              | | Default: true                                        |
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