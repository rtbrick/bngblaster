.. code-block:: json

    { "access-line-profiles": [] }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `access-line-profile-id`
     - Mandatory access-line-profile identifier
     - 
   * - `act-up`
     - Actual Data Rate Upstream
     - 0
   * - `act-down`
     - Actual Data Rate Downstream
     - 0
   * - `min-up`
     - Minimum Data Rate Upstream
     - 0
   * - `min-down`
     - Minimum Data Rate Downstream
     - 0
   * - `att-up`
     - Attainable DataRate Upstream
     - 0
   * - `att-down`
     - Attainable DataRate Downstream
     - 0
   * - `max-up`
     - Maximum Data Rate Upstream
     - 0
   * - `max-down`
     - Maximum Data Rate Downstream
     - 0
   * - `min-up-low`
     - Min Data Rate Upstream in low power state
     - 0
   * - `min-down-low`
     - Min Data Rate Downstream in low power state
     - 0
   * - `max-interl-delay-up`
     - Max Interleaving Delay Upstream
     - 0
   * - `act-interl-delay-up`
     - Actual Interleaving Delay Upstream
     - 0
   * - `max-interl-delay-down`
     - Max Interleaving Delay Downstream
     - 0
   * - `act-interl-delay-down`
     - Actual Interleaving Delay Downstream
     - 0
   * - `data-link-encaps`
     - Data Link Encapsulation
     - 0
   * - `dsl-type`
     - DSL Type
     - 0
   * - `pon-type`
     - PON Access Type
     - 0
   * - `etr-up`
     - Expected Throughput (ETR) Upstream
     - 0
   * - `etr-down`
     - Expected Throughput (ETR) Downstream
     - 0
   * - `attetr-up`
     - Attainable Expected Throughput (ATTETR) Upstream
     - 0
   * - `attetr-down`
     - Attainable Expected Throughput (ATTETR) Downstream
     - 0
   * - `gdr-up`
     - Gamma Data Rate (GDR) Upstream
     - 0
   * - `gdr-down`
     - Gamma Data Rate (GDR) Downstream
     - 0
   * - `attgdr-up`
     - Attainable Gamma Data Rate (ATTGDR) Upstream
     - 0
   * - `attgdr-down`
     - Attainable Gamma Data Rate (ATTGDR) Downstream
     - 0
   * - `ont-onu-avg-down`
     - ONT/ONU Average Data Rate Downstream
     - 0
   * - `ont-onu-peak-down`
     - ONT/ONUPeak Data Rate Downstream
     - 0
   * - `ont-onu-max-up`
     - ONT/ONU Maximum Data Rate Upstream
     - 0
   * - `ont-onu-ass-up`
     - ONT/ONU Assured Data Rate Upstream
     - 0
   * - `pon-max-up`
     - PON Tree Maximum Data Rate Upstream
     - 0
   * - `pon-max-down`
     - PON Tree Maximum Data Rate Downstream
     - 0

Attributes with value set to 0 will not be send.

The values for ``rate-up``, ``rate-down`` and ``dsl-type`` defined in the
access-line or interface section have priority over those defined here.
