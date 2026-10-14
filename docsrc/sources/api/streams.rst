+-----------------------------------+------------------------------------------------------------------------+
| Command                           | Description                                                            |
+===================================+========================================================================+
| **stream-stats**                  | | Display stream traffic statistics.                                   |
+-----------------------------------+------------------------------------------------------------------------+
| **stream-info**                   | | Display stream/flow information.                                     |
|                                   | |                                                                      |
|                                   | | **Arguments:**                                                       |
|                                   | | ``flow-id`` Mandatory                                                |
|                                   | | ``debug``                                                            |
+-----------------------------------+------------------------------------------------------------------------+
| **stream-summary**                | | Display stream/flow summary information.                             |
|                                   | |                                                                      |
|                                   | | **Arguments:**                                                       |
|                                   | | ``flow-id``                                                          |
|                                   | | ``flow-id-min`` flow range                                           |
|                                   | | ``flow-id-max``                                                      |
|                                   | | ``flows`` list of flows (e.g. ``[1,2,3]``)                           |
|                                   | | ``session-id``                                                       |
|                                   | | ``session-group-id``                                                 |
|                                   | | ``name`` stream name                                                 |
|                                   | | ``interface`` TX interface name                                      |
|                                   | | ``direction`` [both(default), upstream, downstream]                  |
|                                   | | ``verified-only`` streams verified                                   |
|                                   | | ``bidirectional-verified-only`` streams verified in both directions  |
|                                   | | ``pending-only`` streams not verified                                |
+-----------------------------------+------------------------------------------------------------------------+
| **stream-reset**                  | | Reset all traffic streams except session-traffic.                    |
+-----------------------------------+------------------------------------------------------------------------+
| **stream-start**                  | | This command can be used to start or stop traffic stream flows.      |
|                                   | | This command applies to all flows except session-traffic and         |
| **stream-stop**                   | | multicast. If you provide a specific ``flow-id`` or a list of        |
|                                   | | ``flows`` as an argument, all other arguments are ignored.           |
| **stream-stop-verified**          | | Use **session-traffic-start/stop** for session-traffic.              |
|                                   | |                                                                      |
|                                   | | The command **stream-stop-verified** works similarly to              |
|                                   | | **stream-stop** but only verified streams will be stopped.           |
|                                   | | This filter is not applied with ``flow-id`` or ``flows``.            |
|                                   | |                                                                      |
|                                   | | **Arguments:**                                                       |
|                                   | | ``flow-id``                                                          |
|                                   | | ``flow-id-min`` flow range                                           |
|                                   | | ``flow-id-max``                                                      |
|                                   | | ``flows`` list of flows (e.g. ``[1,2,3]``)                           |
|                                   | | ``session-id``                                                       |
|                                   | | ``session-group-id``                                                 |
|                                   | | ``name`` stream name                                                 |
|                                   | | ``interface`` TX interface name                                      |
|                                   | | ``direction`` [both(default), upstream, downstream]                  |
|                                   | | ``verified-only`` streams verified                                   |
|                                   | | ``bidirectional-verified-only`` streams verified in both directions  |
|                                   | | ``pending-only`` streams not verified                                |
+-----------------------------------+------------------------------------------------------------------------+
| **streams-pending**               | | List flow-id of all pending (not verified) traffic streams.          |
+-----------------------------------+------------------------------------------------------------------------+
| **stream-update**                 | | Update stream/flow configuration.                                    |
|                                   | |                                                                      |
|                                   | | **Arguments:**                                                       |
|                                   | | ``flow-id``                                                          |
|                                   | | ``flow-id-min`` flow range                                           |
|                                   | | ``flow-id-max``                                                      |
|                                   | | ``flows`` list of flows (e.g. ``[1,2,3]``)                           |
|                                   | | ``session-id``                                                       |
|                                   | | ``session-group-id``                                                 |
|                                   | | ``name`` stream name                                                 |
|                                   | | ``interface`` TX interface name                                      |
|                                   | | ``direction`` [both(default), upstream, downstream]                  |
|                                   | | ``verified-only`` streams verified                                   |
|                                   | | ``bidirectional-verified-only`` streams verified in both directions  |
|                                   | | ``pending-only`` streams not verified                                |
|                                   | | ``tcp-flags`` [ack, fin, fin-ack, syn, syn-ack, rst, push, push-ack] |
|                                   | | ``pps`` Update the stream rate in packets per second.                |
+-----------------------------------+------------------------------------------------------------------------+
