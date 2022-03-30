.. list-table::
   :header-rows: 1

   * - Attribute
     - Description
     - Mandatory Arguments
     - Optional Arguments
   * - `bgp-sessions`
     - Display all matching BGP sessions
     - 
     - `local-ipv4-address`, `peer-ipv4-address`
   * - `bgp-disconnect`
     - Disconnect all matching BGP sessions
     - 
     - `local-ipv4-address`, `peer-ipv4-address`
   * - `bgp-teardown`
     - Teardown BGP
     - 
     - 
   * - `bgp-raw-update-list`
     - List all loaded BGP RAW update files
     - 
     - 
   * - `bgp-raw-update`
     - Update all matching BGP session
     - `file`
     - `local-ipv4-address`, `peer-ipv4-address`
