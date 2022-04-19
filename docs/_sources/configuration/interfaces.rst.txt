.. code-block:: json

    { "interfaces": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `tx-interval`
     - TX ring polling interval in milliseconds
     - 1.0
   * - `rx-interval`
     - RX ring polling interval in milliseconds
     - 1.0
   * - `qdisc-bypass`
     - Bypass the kernel's qdisc layer
     - true
   * - `io-mode`
     - IO mode
     - packet_mmap_raw
   * - `io-slots`
     - IO slots (ring size)
     - 4096
   * - `io-stream-max-ppi`
     - IO traffic stream max packets per interval
     - 32
   * - `capture-include-streams`
     - Include traffic streams in capture
     - true
   * - `mac-modifier`
     - Third byte of access session MAC address (0-255)
     - 0