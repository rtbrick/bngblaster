.. list-table::
   :header-rows: 1

   * - Attribute
     - Description
     - Mandatory Arguments
     - Optional Arguments
   * - `isis-adjacencies`
     - Display ISIS adjacencies
     - 
     - 
   * - `isis-database`
     - Display ISIS database (LSDB)
     - `instance`, `level`
     - 
   * - `isis-load-mrt`
     - Load ISIS MRT file
     - `instance`, `file`
     - 
   * - `isis-lsp-update`
     - Update ISIS LSP
     - `instance`, `pdu`
     - 
   * - `isis-lsp-purge`
     - Purge ISIS LSP based on LSP identifier
     - `instance`, `level`, `id`
     - 
   * - `isis-lsp-flap`
     - Flap ISIS LSP based on LSP identifier
     - `instance`, `level`, `id`
     - `timer`
   * - `isis-teardown`
     - Teardown ISIS
     - 
     - 