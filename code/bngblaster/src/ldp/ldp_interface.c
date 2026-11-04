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
/**
 * ldp_targeted_peer_address
 *
 * @param adjacency targeted LDP adjacency
 * @return peer address string
 */
char *
ldp_targeted_peer_address(ldp_adjacency_s *adjacency)
{
    if(adjacency->hello_ipv6) {
        return format_ipv6_address(&adjacency->peer_ipv6_address);
    }
    return format_ipv4_address(&adjacency->peer_ipv4_address);
}

/**
 * ldp_targeted_local_address
 *
 * @param adjacency targeted LDP adjacency
 * @return local (hello source) address string
 */
char *
ldp_targeted_local_address(ldp_adjacency_s *adjacency)
{
    if(adjacency->hello_ipv6) {
        return format_ipv6_address(&adjacency->local_ipv6_address);
    }
    return format_ipv4_address(&adjacency->local_ipv4_address);
}

/**
 * ldp_targeted_adjacency_add
 *
 * @param instance LDP instance
 * @param interface network interface used for the targeted hellos
 * @param neighbor targeted neighbor addresses, the source address
 *        defaults to the transport address of the address family
 * @param configured true for configured targeted neighbors which send
 *        hellos and request targeted hellos from the peer
 * @return new targeted adjacency
 */
ldp_adjacency_s *
ldp_targeted_adjacency_add(ldp_instance_s *instance,
                           bbl_network_interface_s *interface,
                           ldp_targeted_neighbor_config_s *neighbor,
                           bool configured)
{
    ldp_config_s *config = instance->config;
    ldp_adjacency_s *adjacency;

    adjacency = calloc(1, sizeof(ldp_adjacency_s));
    adjacency->next = instance->adjacencies;
    instance->adjacencies = adjacency;
    adjacency->instance = instance;
    adjacency->interface = interface;
    adjacency->hold_time = config->targeted_hold_time;
    adjacency->targeted = true;
    adjacency->targeted_configured = configured;
    if(neighbor->ipv6) {
        adjacency->hello_ipv6 = true;
        memcpy(&adjacency->peer_ipv6_address, &neighbor->ipv6_address, sizeof(ipv6addr_t));
        if(ipv6_addr_not_zero(&neighbor->ipv6_source_address)) {
            memcpy(&adjacency->local_ipv6_address, &neighbor->ipv6_source_address, sizeof(ipv6addr_t));
        } else {
            memcpy(&adjacency->local_ipv6_address, &config->ipv6_transport_address, sizeof(ipv6addr_t));
        }
    } else {
        adjacency->hello_ipv4 = true;
        adjacency->peer_ipv4_address = neighbor->ipv4_address;
        if(neighbor->ipv4_source_address) {
            adjacency->local_ipv4_address = neighbor->ipv4_source_address;
        } else {
            adjacency->local_ipv4_address = config->ipv4_transport_address;
        }
    }
    adjacency->prefer_ipv4_transport = config->prefer_ipv4_transport;

    LOG(LDP, "Add LDP targeted neighbor %s (source %s) on interface %s to LDP instance %u\n",
        ldp_targeted_peer_address(adjacency), ldp_targeted_local_address(adjacency),
        interface->name, config->id);
    return adjacency;
}

/**
 * ldp_targeted_init
 *
 * This function inits the configured targeted neighbors of all
 * LDP instances, after the network interfaces are initialised.
 */
bool
ldp_targeted_init()
{
    ldp_instance_s *instance = g_ctx->ldp_instances;
    ldp_targeted_neighbor_config_s *neighbor;
    bbl_network_interface_s *interface;

    while(instance) {
        neighbor = instance->config->targeted_neighbors;
        while(neighbor) {
            interface = bbl_network_interface_get(neighbor->network_interface);
            if(!interface) {
                LOG(ERROR, "Failed to init LDP targeted neighbor %s (network interface %s not found)\n",
                    neighbor->ipv6 ? format_ipv6_address(&neighbor->ipv6_address) :
                                     format_ipv4_address(&neighbor->ipv4_address),
                    neighbor->network_interface ? neighbor->network_interface : "");
                return false;
            }
            ldp_hello_start(ldp_targeted_adjacency_add(instance, interface, neighbor, true));
            neighbor = neighbor->next;
        }
        instance = instance->next;
    }
    return true;
}
