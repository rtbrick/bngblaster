/*
 * BNG Blaster (BBL) - LDP Interface
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

/**
 * ldp_interface_init
 * 
 * This function inits the LDP interface. 
 *
 * @param interface network interface
 * @param config network interface configuration
 * @param instance LDP instance
 */
bool 
ldp_interface_init(bbl_network_interface_s *interface,
                   bbl_network_config_s *interface_config,
                   ldp_instance_s *instance)
{
    ldp_config_s *config = instance->config;
    ldp_adjacency_s *adjacency;

    LOG(LDP, "Add network interface %s to LDP instance %u\n", 
        interface->name, interface_config->ldp_instance_id);

    adjacency = calloc(1, sizeof(ldp_adjacency_s));
    adjacency->next = instance->adjacencies;
    instance->adjacencies = adjacency;
    adjacency->instance = instance;
    adjacency->interface = interface;
    adjacency->hold_time = config->hold_time;
    interface->ldp_adjacency = adjacency;

    if(!config->no_ipv4_transport) {
        adjacency->hello_ipv4 = true;
        adjacency->prefer_ipv4_transport = config->prefer_ipv4_transport;
    }
    if(ipv6_addr_not_zero(&config->ipv6_transport_address)) {
        adjacency->hello_ipv6 = true;
    }

    ldp_hello_start(adjacency);
    return true;
}