.. code-block:: json

    { "isis": {} }

+----------------------------------+-------------------------------------------------------------------+
| Attribute                        | Description                                                       |
+==================================+===================================================================+
| **instance-id**                  | | Mandatory ISIS instance identifier.                             |
| **instance-id**                  | | Range: 0 - 65535                                                |
+----------------------------------+-------------------------------------------------------------------+
| **level**                        | | Level.                                                          |
|                                  | | Default: 3 Range: 1 - 3                                         |
+----------------------------------+-------------------------------------------------------------------+
| **overload**                     | | Set the overload bit in the self originated LSP to prevent      |
|                                  | | transit traffic through the BNG Blaster.                        |
|                                  | | Default: false                                                  |
+----------------------------------+-------------------------------------------------------------------+
| **protocol-ipv4**                | | Enable/disable IPv4 routing.                                    |
|                                  | | Default: true                                                   |
+----------------------------------+-------------------------------------------------------------------+
| **protocol-ipv6**                | | Enable/disable IPv6 routing.                                    |
|                                  | | Default: true                                                   |
+----------------------------------+-------------------------------------------------------------------+
| **level1-auth-key**              | | Level 1 authentication key.                                     |
+----------------------------------+-------------------------------------------------------------------+
| **level1-auth-type**             | | Level 1 authentication type (simple or md5).                    |
| **level1-auth-type**             | | Required to enable authentication with **level1-auth-key**.     |
+----------------------------------+-------------------------------------------------------------------+
| **level1-auth-hello**            | | Level 1 hello authentication.                                   |
| **level1-auth-hello**            | | Default: true                                                   |
+----------------------------------+-------------------------------------------------------------------+
| **level1-auth-csnp**             | | Level 1 CSNP authentication.                                    |
| **level1-auth-csnp**             | | Default: true                                                   |
+----------------------------------+-------------------------------------------------------------------+
| **level1-auth-psnp**             | | Level 1 PSNP authentication.                                    |
| **level1-auth-psnp**             | | Default: true                                                   |
+----------------------------------+-------------------------------------------------------------------+
| **level2-auth-key**              | | Level 2 authentication key.                                     |
+----------------------------------+-------------------------------------------------------------------+
| **level2-auth-type**             | | Level 2 authentication type (simple or md5).                    |
| **level2-auth-type**             | | Required to enable authentication with **level2-auth-key**.     |
+----------------------------------+-------------------------------------------------------------------+
| **level2-auth-hello**            | | Level 2 hello authentication.                                   |
| **level2-auth-hello**            | | Default: true                                                   |
+----------------------------------+-------------------------------------------------------------------+
| **level2-auth-csnp**             | | Level 2 CSNP authentication.                                    |
| **level2-auth-csnp**             | | Default: true                                                   |
+----------------------------------+-------------------------------------------------------------------+
| **level2-auth-psnp**             | | Level 2 PSNP authentication.                                    |
| **level2-auth-psnp**             | | Default: true                                                   |
+----------------------------------+-------------------------------------------------------------------+
| **hello-interval**               | | Hello interval in seconds.                                      |
|                                  | | Default: 10 Range: 1 - 65535                                    |
+----------------------------------+-------------------------------------------------------------------+
| **hello-padding**                | | Enable/disable hello padding.                                   |
|                                  | | Default: false                                                  |
+----------------------------------+-------------------------------------------------------------------+
| **hold-time**                    | | ISIS hold time in seconds.                                      |
|                                  | | Default: 30 Range: 1 - 65535                                    |
+----------------------------------+-------------------------------------------------------------------+
| **lsp-buffer-size**              | | ISIS LSPBufferSize in bytes.                                    |
|                                  | | Default: 1492 Range: 128 - 9192                                 |
+----------------------------------+-------------------------------------------------------------------+
| **lsp-lifetime**                 | | ISIS LSP lifetime in seconds.                                   |
|                                  | | Default: 65535 Range: 330 - 65535                               |
+----------------------------------+-------------------------------------------------------------------+
| **lsp-refresh-interval**         | | ISIS LSP refresh interval in seconds.                           |
|                                  | | Default: 300 Range: 1 - 65535                                   |
+----------------------------------+-------------------------------------------------------------------+
| **lsp-retry-interval**           | | ISIS LSP retry interval in seconds.                             |
|                                  | | Default: 5 Range: 1 - 65535                                     |
+----------------------------------+-------------------------------------------------------------------+
| **lsp-tx-interval**              | | ISIS LSP TX interval in ms (time between LSP send windows).     |
|                                  | | Default: 10 Range: 1 - 65535                                    |
+----------------------------------+-------------------------------------------------------------------+
| **lsp-tx-window-size**           | | ISIS LSP TX window size (LSP send per window).                  |
|                                  | | Default: 1 Range: 1 - 65535                                     |
+----------------------------------+-------------------------------------------------------------------+
| **csnp-interval**                | | ISIS CSNP interval in seconds.                                  |
|                                  | | Default: 30 Range: 1 - 65535                                    |
+----------------------------------+-------------------------------------------------------------------+
| **hostname**                     | | ISIS hostname.                                                  |
|                                  | | Default: bngblaster                                             |
+----------------------------------+-------------------------------------------------------------------+
| **router-id**                    | | ISIS router identifier.                                         |
|                                  | | Default: 10.10.10.10                                            |
+----------------------------------+-------------------------------------------------------------------+
| **system-id**                    | | ISIS system identifier.                                         |
|                                  | | Default: 0100.1001.0010                                         |
+----------------------------------+-------------------------------------------------------------------+
| **area**                         | | ISIS area(s).                                                   |
|                                  | | Default: 49.0001/24                                             |
+----------------------------------+-------------------------------------------------------------------+
| **sr-algo**                      | | ISIS SR algorithm(s), multiple possible.                        |
|                                  | | Default: disabled Range: 0 - 255                                |
+----------------------------------+-------------------------------------------------------------------+
| **sr-base**                      | | ISIS SR base.                                                   |
|                                  | | Default: 0 Range: 0 - 1048575                                   |
+----------------------------------+-------------------------------------------------------------------+
| **sr-range**                     | | ISIS SR range.                                                  |
|                                  | | Default: 0 Range: 0 - 1048575                                   |
+----------------------------------+-------------------------------------------------------------------+
| **sr-node-sid**                  | | ISIS SR node SID.                                               |
|                                  | | Default: 0 Range: 0 - 1048575                                   |
+----------------------------------+-------------------------------------------------------------------+
| **sr-node-sids**                 | | ISIS SR node SIDs, one per SR algorithm, as list                |
|                                  | | of ``index`` (0 - 1048575) and ``algo`` (default 0), e.g.       |
|                                  | | ``[{"algo": 0, "index": 1}, {"algo": 128, "index": 101}]``.     |
|                                  | | Mutually exclusive with **sr-node-sid**.                        |
+----------------------------------+-------------------------------------------------------------------+
| **node-msd**                     | | ISIS node maximum SID depth (BMI-MSD, RFC 8491).                |
|                                  | | Advertised together with **sr-base** and **sr-range**.          |
|                                  | | Default: 0 (disabled) Range: 0 - 255                            |
+----------------------------------+-------------------------------------------------------------------+
| **flex-algo**                    | | ISIS Flex-Algo definitions (RFC 9350), up to 4                  |
|                                  | | advertised in dedicated router capability TLVs, as list of      |
|                                  | | ``algo`` (mandatory, 128 - 255), ``metric-type``                |
|                                  | | (``igp`` (default), ``min-delay`` or ``te``), ``priority``      |
|                                  | | (default 128), ``m-flag`` (default false) and the               |
|                                  | | admin group masks ``exclude-any``, ``include-any`` and          |
|                                  | | ``include-all``. The algorithms must be added to                |
|                                  | | **sr-algo** as well.                                            |
+----------------------------------+-------------------------------------------------------------------+
| **adjacency-sid-base**           | | Enable Adjacency SID generation.                                |
|                                  | | Default: disabled Range: 256 - 4096                             |
+----------------------------------+-------------------------------------------------------------------+
| **teardown-time**                | | ISIS teardown time in seconds.                                  |
|                                  | | Default: 5 Range: 0 - 65535                                     |
+----------------------------------+-------------------------------------------------------------------+
