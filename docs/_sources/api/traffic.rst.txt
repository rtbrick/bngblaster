+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **traffic-start**                 | | This command can be used to start or stop all traffic globally.    |
|                                   | | This command does not alter the current state of a traffic stream. |
| **traffic-stop**                  | | In example, if a stream has not been started or has been stopped,  |
|                                   | | it can't be started with this command. Instead, this command acts  |
|                                   | | as a global block to control the transmission of traffic streams.  |
+-----------------------------------+----------------------------------------------------------------------+
| **multicast-traffic-start**       | | This command can be used to start or stop all multicast traffic.   |
|                                   | | This includes auto generated multicast traffic and RAW streams     |
| **multicast-traffic-stop**        | | with multicast destination address.                                |
+-----------------------------------+----------------------------------------------------------------------+