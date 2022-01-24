/*
 * BNG Blaster (BBL) - IS-IS Adjacency
 * 
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

/**
 * isis_adjacency_init
 * 
 * This function inits the IS-IS adjacency. 
 *
 * @param config network interface configuration
 * @param interface network interface
 */
bool 
isis_adjacency_init(bbl_network_config_s *interface_config,
                    bbl_interface_s *interface,
                    isis_instance_t *instance) {
    
    isis_config_t        *config = instance->config;
    isis_adjacency_t     *adjacency;
    isis_adjacency_p2p_t *adjacency_p2p;
    
    uint8_t level;

    LOG(ISIS, "Add network interface %s to IS-IS instance %u\n", 
        interface_config->interface, interface_config->isis_instance_id);

    /* Init P2P adjacency. */
    if(interface_config->isis_p2p) {
        adjacency_p2p = calloc(1, sizeof(isis_adjacency_p2p_t));
        if(!adjacency_p2p) return false;
        interface->isis_adjacency_p2p = adjacency_p2p;
        adjacency_p2p->interface = interface;
        adjacency_p2p->instance  = instance; 
        adjacency_p2p->peer = calloc(1, sizeof(isis_peer_t));
        if(!adjacency_p2p->peer) return false;
        adjacency_p2p->level = interface_config->isis_level;
        adjacency_p2p->state = ISIS_P2P_ADJACENCY_STATE_DOWN;
        interface->send_requests |= BBL_IF_SEND_ISIS_P2P_HELLO;
    }

    /* Init adjacency levels. */
    for(int i=0; i<ISIS_LEVELS; i++) {
        level = i+1;
        if(!(interface_config->isis_level & level)) {
            continue;
        }
        adjacency = calloc(1, sizeof(isis_adjacency_t));
        if(!adjacency) return false;
        interface->isis_adjacency[i] = adjacency;
        adjacency->interface = interface;
        adjacency->instance = instance;
        if(interface_config->isis_p2p) {
            adjacency->peer = adjacency_p2p->peer;
        } else {
            adjacency->peer = calloc(1, sizeof(isis_peer_t));
            if(!adjacency->peer) return false;
        }
        if(instance->level[i].adjacency) {
            adjacency->next = instance->level[i].adjacency;
        }
        instance->level[i].adjacency = adjacency;

        adjacency->flood_tree = hb_tree_new((dict_compare_func)isis_lsp_id_compare);
        adjacency->psnp_tree = hb_tree_new((dict_compare_func)isis_lsp_id_compare);
        adjacency->level = level;
        adjacency->window_size = config->lsp_tx_window_size;
        if(level == ISIS_LEVEL_1) {
            adjacency->metric = interface_config->isis_l1_metric;
        } else {
            adjacency->metric = interface_config->isis_l2_metric;
        }
    }
    return true;
}

void 
isis_adjacency_up(isis_adjacency_t *adjacency) {

    bbl_ctx_s *ctx = adjacency->interface->ctx;
    isis_config_t *config = adjacency->instance->config;

    LOG(ISIS, "ISIS %s adjacency UP on interface %s \n", 
        isis_level_string(adjacency->level), adjacency->interface->name);

    adjacency->state = ISIS_ADJACENCY_STATE_UP;

    timer_add_periodic(&ctx->timer_root, &adjacency->timer_tx, 
        "ISIS TX", 
        0, config->lsp_tx_interval, adjacency,
        &isis_lsp_tx_job);

    timer_add_periodic(&ctx->timer_root, &adjacency->timer_retry, 
        "ISIS RETRY", 
        config->lsp_retry_interval, 0, adjacency,
        &isis_lsp_retry_job);

    timer_add_periodic(&ctx->timer_root, &adjacency->timer_csnp, 
        "ISIS CSNP", 
        config->csnp_interval, 0, adjacency,
        &isis_csnp_job);

    timer_add(&ctx->timer_root, &adjacency->timer_csnp_next, 
        "ISIS CSNP", 
        0, 10*MSEC, adjacency,
        &isis_csnp_job);
}

void
isis_adjacency_down(isis_adjacency_t *adjacency) {

    LOG(ISIS, "ISIS %s adjacency DOWN on interface %s \n", 
        isis_level_string(adjacency->level), adjacency->interface->name);

    adjacency->state = ISIS_ADJACENCY_STATE_DOWN;

    timer_del(adjacency->timer_tx);
    timer_del(adjacency->timer_retry);
    timer_del(adjacency->timer_csnp);
    timer_del(adjacency->timer_csnp_next);
}