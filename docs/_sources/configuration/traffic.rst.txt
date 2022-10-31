.. code-block:: json

    { "traffic": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `autostart`
     - Automatically start traffic
     - true
   * - `stop-verified`
     - Automatically stop traffic streams if verified
     - false
   * - `max-burst`
     - Stream flow burst size in packets
     - 16
   * - `stream-rate-calculation`
     - Enable stream rate calculation
     - true

The option ``stream-rate-calculation`` should be set to 
false if massive streams (> 1M) are defined but per-stream
live rate statistics are not required.