.. code-block:: json

    { "sessions": {} }

+--------------------------+------------------------------------------------------------------+
| Attribute                | Description                                                      |
+==========================+==================================================================+
| **count**                | | Sessions (PPPoE + IPoE).                                       |
|                          | | Default: 1                                                     |
+--------------------------+------------------------------------------------------------------+
| **max-outstanding**      | | Max outstanding sessions.                                      |
|                          | | Default: 800                                                   |
+--------------------------+------------------------------------------------------------------+
| **start-rate**           | | Setup request rate in sessions per second.                     |
|                          | | Default: 400                                                   |
+--------------------------+------------------------------------------------------------------+
| **stop-rate**            | | Teardown request rate in sessions per second.                  |
|                          | | Default: 400                                                   |
+--------------------------+------------------------------------------------------------------+
| **start-delay**          | | Wait N seconds after all interfaces are resolved               |
|                          | | before starting sessions.                                      |
|                          | | Default: 0                                                     |
+--------------------------+------------------------------------------------------------------+
| **reconnect**            | | Automatically reconnect sessions (PPPoE and IPoE).             |
|                          | | Default: false                                                 |
+--------------------------+------------------------------------------------------------------+
| **autostart**            | | Start sessions automatically.                                  |
|                          | | Default: true                                                  |
+--------------------------+------------------------------------------------------------------+
| **monkey-autostart**     | | Start monkey testing automatically if enabled.                 |
|                          | | Default: true                                                  |
+--------------------------+------------------------------------------------------------------+
| **iterate-vlan-outer**   | | Iterate on outer VLAN first.                                   |
|                          | | Per default, sessions are created by iteration over the        |
|                          | | inner VLAN range first and outer VLAN second. Which can be     |
|                          | | changed with this option to iterate on the outer VLAN first    |
|                          | | and inner VLAN second.                                         |
|                          | |                                                                |
|                          | | Assuming the following configuration:                          |
|                          | | "outer-vlan-min": 1                                            |
|                          | | "outer-vlan-max": 2                                            |
|                          | | "inner-vlan-min": 3                                            |
|                          | | "inner-vlan-max": 4                                            |
|                          | | This generates the sessions on VLAN (outer:inner)              |
|                          | | 1:3, 1:4, 2:3, 2:4 per default or alternative                  |
|                          | | 1:3, 2:3, 1:4, 2:4 with this option enabled.                   |
|                          | |                                                                |
|                          | | Default: false                                                 |
+--------------------------+------------------------------------------------------------------+
