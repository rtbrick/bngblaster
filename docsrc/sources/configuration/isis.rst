.. code-block:: json

    { "isis": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `instance-id`
     - ISIS instance identifier
     - 
   * - `level`
     - ISIS level
     - 3
   * - `overload`
     - ISIS overload
     - false
   * - `protocol-ipv4`
     - Enable/disable IPv4
     - true
   * - `protocol-ipv6`
     - Enable/disable IPv6
     - true
   * - `level1-auth-key`
     - ISIS level 1 authentication key
     - 
   * - `level1-auth-type`
     - ISIS level 1 authentication type (simple or md5)
     - disabled
   * - `level1-auth-hello`
     - ISIS level 1 hello authentication 
     - true
   * - `level1-auth-csnp`
     - ISIS level 1 CSNP authentication 
     - true
   * - `level1-auth-psnp`
     - ISIS level 1 PSNP authentication 
     - true
   * - `level2-auth-key`
     - ISIS level 2 authentication key
     - 
   * - `level2-auth-type`
     - ISIS level 2 authentication type (simple or md5)
     - disabled
   * - `level2-auth-hello`
     - ISIS level 2 hello authentication 
     - true
   * - `level2-auth-csnp`
     - ISIS level 2 CSNP authentication 
     - true
   * - `level2-auth-psnp`
     - ISIS level 2 PSNP authentication 
     - true
   * - `hello-interval`
     - ISIS hello interval in seconds
     - 10
   * - `hello-padding`
     - ISIS hello padding
     - false
   * - `hold-time`
     - ISIS hold time in seconds
     - 30
   * - `lsp-lifetime`
     - ISIS LSP lifetime in seconds
     - 65535
   * - `lsp-refresh-interval`
     - ISIS LSP refresh interval in seconds
     - 300
   * - `lsp-retry-interval`
     - ISIS LSP retry interval in seconds
     - 5
   * - `lsp-tx-interval`
     - ISIS LSP TX interval in ms (time between LSP send windows)
     - 10
   * - `lsp-tx-window-size`
     - ISIS LSP TX window size (LSP send per window)
     - 1
   * - `csnp-interval`
     - ISIS CSNP interval in seconds
     - 30
   * - `hostname`
     - ISIS hostname
     - bngblaster
   * - `router-id`
     - ISIS router identifier
     - 10.10.10.10
   * - `system-id`
     - ISIS system identifier
     - 0100.1001.0010
   * - `area`
     - ISIS area(s)
     - 49.0001/24
   * - `sr-base`
     - ISIS SR base
     - 
   * - `sr-range`
     - ISIS SR range
     - 
   * - `sr-node-sid`
     - ISIS SR node SID
     - 
   * - `teardown-time`
     - ISIS teardown time in seconds
     - 5