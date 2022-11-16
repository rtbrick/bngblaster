.. code-block:: json

    { "l2tp-server": [] }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `name`
     - Mandatory L2TP LNS server hostname (AVP 7)
     - 
   * - `address`
     - Mandatory L2TP server address
     - 
   * - `secret`
     - Tunnel secret
     - 
   * - `receive-window-size`
     - Control messages receive window size
     - 16
   * - `max-retry`
     - Control messages max retry
     - 5
   * - `congestion-mode`
     - Control messages congestion mode
     - default
   * - `hello-interval`
     - Set hello interval
     - 30
   * - `data-control-priority`
     - Set the priority bit in the L2TP header for all non-IP data packets (LCP, IPCP, ...)
     - false
   * - `data-length`
     - Set length bit for all data packets
     - false
   * - `data-offset`
     - Set offset bit with offset zero for all data packets
     - false
   * - `control-tos`
     - L2TP control traffic (SCCRQ, ICRQ, ...) TOS priority
     - 0
   * - `data-control-tos`
     - Set the L2TP tunnel TOS priority (outer IPv4 header) for all non-IP data packets (LCP, IPCP, ...)
     - 0
   * - `lcp-padding`
     - Add fixed padding to LCP packets send from LNS
     - 0 

The BNG Blaster supports different congestion modes for the
reliable delivery of control messages. The ``default`` mode
is described in RFC2661 appendix A (Control Channel Slow Start and
Congestion Avoidance). The mode ``slow`` uses a fixed control window
size of 1 where ``aggressive`` sticks to max permitted based on peer
received window size.

