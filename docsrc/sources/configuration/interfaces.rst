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
     - Include traffic streams in capture
     - true
   * - `mac-modifier`
     - Third byte of access session MAC address (0-255)
     - 0
