Attributes within the **access-line-profiles** are treated analogous to those within the 
**access-line** section but they provide the capability to apply different profiles to 
each access interface.

.. code-block:: json

    { "access-line-profiles": [] }

+-----------------------------------+----------------------------------------------------------------------+
| Attribute                         | Description                                                          |
+===================================+======================================================================+
| **access-line-profile-id**        | | Mandatory access-line-profile identifier.                          |
|                                   | | Range: 1 - 65535                                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **act-up**                        | | Actual Data Rate Upstream.                                         |
|                                   | | This value is overwritten by **rate-up**.                          |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **act-down**                      | | Actual Data Rate Downstream.                                       |
|                                   | | This value is overwritten by **rate-down**                         |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **min-up**                        | | Minimum Data Rate Upstream.                                        |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **min-down**                      | | Minimum Data Rate Downstream.                                      |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **att-up**                        | | Attainable DataRate Upstream.                                      |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **att-down**                      | | Attainable DataRate Downstream.                                    |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **max-up**                        | | Maximum Data Rate Upstream.                                        |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **max-down**                      | | Maximum Data Rate Downstream.                                      |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **min-up-low**                    | | Min Data Rate Upstream.in low power state                          |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **min-down-low**                  | | Min Data Rate Downstream.in low power state                        |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **max-interl-delay-up**           | | Max Interleaving Delay Upstream.                                   |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **act-interl-delay-up**           | | Actual Interleaving Delay Upstream.                                |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **max-interl-delay-down**         | | Max Interleaving Delay Downstream.                                 |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **act-interl-delay-down**         | | Actual Interleaving Delay Downstream.                              |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **data-link-encaps**              | | Data Link Encapsulation                                            |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **dsl-type**                      | | DSL Type.                                                          |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **pon-type**                      | | PON Access Type.                                                   |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **etr-up**                        | | Expected Throughput (ETR) Upstream.                                |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **etr-down**                      | | Expected Throughput (ETR) Downstream.                              |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **attetr-up**                     | | Attainable Expected Throughput (ATTETR) Upstream.                  |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **attetr-down**                   | | Attainable Expected Throughput (ATTETR) Downstream.                |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **gdr-up**                        | | Gamma Data Rate (GDR) Upstream.                                    |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **gdr-down**                      | | Gamma Data Rate (GDR) Downstream.                                  |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **attgdr-up**                     | | Attainable Gamma Data Rate (ATTGDR) Upstream.                      |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **attgdr-down**                   | | Attainable Gamma Data Rate (ATTGDR) Downstream.                    |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **ont-onu-avg-down**              | | ONT/ONU Average Data Rate Downstream.                              |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **ont-onu-peak-down**             | | ONT/ONU Peak Data Rate Downstream.                                 |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **ont-onu-max-up**                | | ONT/ONU Maximum Data Rate Upstream.                                |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **ont-onu-ass-up**                | | ONT/ONU Assured Data Rate Upstream.                                |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **pon-max-up**                    | | PON Tree Maximum Data Rate Upstream.                               |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **pon-max-down**                  | | PON Tree Maximum Data Rate Downstream.                             |
|                                   | | Default: 0 Range: 0 - 4294967295                                   |
+-----------------------------------+----------------------------------------------------------------------+
| **pon-access-line-version**       | | This option allows to switch between the versions                  |
|                                   | | 00 (DRAFT-LIHAWI-00) and 04 (DRAFT-LIHAWI-04) of the RFC           |
|                                   | | `draft-lihawi-ancp-protocol-access-extension`.                     |
|                                   | | Default: DRAFT-LIHAWI-04                                           |
+-----------------------------------+----------------------------------------------------------------------+
+-----------------------------------+----------------------------------------------------------------------+

The values specified for **rate-up**, **rate-down** and **dsl-type** defined in the
**access-line** or **interface** section section take precedence over the definitions 
provided here.
