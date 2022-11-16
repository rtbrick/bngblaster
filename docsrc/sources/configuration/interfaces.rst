The following configuration allows to overwrite the global default interface link settings. 

.. code-block:: json

    { "interfaces": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `io-mode`
     - IO mode
     - packet_mmap_raw
   * - `io-slots`
     - IO slots (ring size)
     - 4096
   * - `qdisc-bypass`
     - Bypass the kernel's qdisc layer
     - true
   * - `tx-interval`
     - TX polling interval in milliseconds
     - 1.0
   * - `rx-interval`
     - RX polling interval in milliseconds
     - 1.0
   * - `tx-threads`
     - Number of TX threads per interface link
     - 0 (main thread)
   * - `rx-threads`
     - Number of RX threads per interface link
     - 0 (main thread)
   * - `capture-include-streams`
     - Include traffic streams in the capture
     - false
   * - `mac-modifier`
     - Third byte of access session MAC address (0-255)
     - 0

The supported IO modes are listed with ``bngblaster -v`` but except
``packet_mmap_raw`` all other modes are currently considered experimental. In
the default mode (``packet_mmap_raw``) all packets are received in a Packet MMAP
ring buffer and sent directly through RAW packet sockets.

The default ``tx-interval`` and ``rx-interval`` of ``1.0`` (1ms) allows precise timestamps 
and high throughput. Those values can be further increased (e.g. ``0.1``) for higher throughput 
or decreased (e.g. ``5.0``) for lower system load.

It might be also needed to increase the ``io-slots`` from the default value of ``4096`` to 
reach the desired throughput. The actual meaning of IO slots depends on the selected IO mode. 
For Packet MMAP, it defines the maximum number of packets in the ring buffer.