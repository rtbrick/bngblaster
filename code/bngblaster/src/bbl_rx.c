/*
 * BNG Blaster (BBL) - RX
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

void
bbl_rx_handler(bbl_interface_s *interface, bbl_ethernet_header_t *eth) {
    bbl_network_interface_s *network_interface = interface->network;
    while(network_interface) {
        if(network_interface->vlan == eth->vlan_outer) {
            return bbl_network_rx_handler(network_interface, eth);
        } 
    }
    if(interface->access) {
        return bbl_access_rx_handler(interface->access, eth);
    } else if(interface->a10nsp) {
        return bbl_a10nsp_rx_handler(interface->a10nsp, eth);
    }
    interface->stats.unknown++;
    return;
}