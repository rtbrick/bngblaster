/*
 * BNG Blaster (BBL) - OSPF Functions
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

/**
 * ospf_init
 * 
 * This function inits all OSPF instances. 
 */
bool
ospf_init() {
    ospf_config_s *config = g_ctx->config.ospf_config;
    ospf_instance_s *instance = NULL;

    while(config) {
        LOG(OSPF, "Init OSPFv%u instance %u\n", config->version, config->id);
        if(instance) {
            instance->next = calloc(1, sizeof(ospf_instance_s));
            instance = instance->next;
        } else {
            instance = calloc(1, sizeof(ospf_instance_s));
            g_ctx->ospf_instances = instance;
        }
        instance->config = config;
        // TODO: ...
        //for(int i=0; i<OSPF_LSA_TYPES; i++) {
        //    instance->lsdb[i].db = hb_tree_new((dict_compare_func)ospf_lsa_id_compare);
        //}
        //if(!ospf_lsa_self_update(instance, level)) {
        //    LOG(OSPF, "Failed to generate self originated LSA for OSPFv%u instance %u\n", config->version, config->id);
        //    return false;
        //}
        if(config->external_mrt_file) {
            if(!ospf_mrt_load(instance, config->external_mrt_file)) {
                LOG(OSPF, "Failed to load MRT file %s\n", config->external_mrt_file);
                return false;
            }
        }

        /* Start LSA garbage collection job. */
        timer_add_periodic(&g_ctx->timer_root, &instance->timer_lsa_gc, 
                           "OSPF LSA GC", OSPF_LSA_GC_INTERVAL, 0, instance,
                           &ospf_lsa_gc_job);

        config = config->next;
    }
    return true;
}

/**
 * ospf_handler_rx_ipv4
 *
 * This function handles IPv4 OSPF packets received on network interfaces.
 *
 * @param interface pointer to interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 * @param ipv4 pointer to IPv4 header structure of received packet
 */
void
ospf_handler_rx_ipv4(bbl_network_interface_s *interface, 
                     bbl_ethernet_header_s *eth, 
                     bbl_ipv4_s *ipv4) {
    UNUSED(interface);
    UNUSED(eth);
    UNUSED(ipv4);
}

/**
 * ospf_handler_rx_ipv6
 *
 * This function handles IPv6 OSPF packets received on network interfaces.
 *
 * @param interface pointer to interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 * @param ipv6 pointer to IPv6 header structure of received packet
 */
void
ospf_handler_rx_ipv6(bbl_network_interface_s *interface, 
                     bbl_ethernet_header_s *eth, 
                     bbl_ipv6_s *ipv6) {
    UNUSED(interface);
    UNUSED(eth);
    UNUSED(ipv6);
}

void
ospf_teardown_job(timer_s *timer) {
    ospf_instance_s *instance = timer->data;
    ospf_adjacency_s *adjacency = instance->adjacency;
    while(adjacency) {
        //ospf_adjacency_down(adjacency);
        adjacency = adjacency->next;
    }
}

/**
 * ospf_teardown
 * 
 * This function stops all OSPF instances. 
 */
void
ospf_teardown()
{
    ospf_instance_s *instance = g_ctx->ospf_instances;
    while(instance) {
        if(!instance->teardown) {
            LOG(ISIS, "Teardown OSPFv%u instance %u\n", instance->config->version, instance->config->id);
            instance->teardown = true;
            //if(instance->adjacency) {
            //    ospf_lsa_self_update(instance, i+1);
            //    ospf_lsa_purge_external(instance, i+1);
            //}
            timer_add(&g_ctx->timer_root, &instance->timer_teardown, 
                      "OSPF TEARDOWN", instance->config->teardown_time, 0, instance,
                      &ospf_teardown_job);
        }
        instance = instance->next;
    }
}