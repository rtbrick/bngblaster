.. list-table::
   :header-rows: 1

   * - Attribute
     - Description
     - Mandatory Arguments
     - Optional Arguments
   * - `ldp-sessions`
     - Display all matching LDP sessions
     - 
     - `ldp-instance-id`, `local-ipv4-address`, `peer-ipv4-address`
   * - `ldp-disconnect`
     - Disconnect all matching LDP sessions
     - 
     - `ldp-instance-id`, `local-ipv4-address`, `peer-ipv4-address`
   * - `ldp-teardown`
     - Teardown LDP
     - 
     - 
   * - `ldp-raw-update-list`
     - List all loaded LDP RAW update files
     - 
     - 
   * - `ldp-raw-update`
     - Update all matching LDP session
     - `file`
     - `ldp-instance-id`, `local-ipv4-address`, `peer-ipv4-address`
