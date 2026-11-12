/*
 * BNG Blaster (BBL) - IS-IS Adjacency
 * 
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

/**
 * isis_adjacency_init
 * 
 * This function inits the IS-IS adjacency. 
 *
 * @param interface network interface
 * @param config network interface configuration
 * @param instance IS-IS instance
 */
bool 
isis_adjacency_init(bbl_network_interface_s *interface,
                    bbl_network_config_s *interface_config,
                    isis_instance_s *instance)
{
    isis_config_s *config = instance->config;
    isis_adjacency_s *adjacency = NULL;
    isis_adjacency_p2p_s *adjacency_p2p = NULL;
    
    uint8_t level;
    /* Levels of the interface supported by the instance. */
    uint8_t levels = interface_config->isis_level & config->level;

    LOG(ISIS, "Add network interface %s to IS-IS instance %u\n", 
        interface->name, interface_config->isis_instance_id);

    if(!levels) {
        LOG(ERROR, "IS-IS level %u of interface %s is not enabled in instance %u (level %u)\n",
            interface_config->isis_level, interface->name, config->id, config->level);
        return false;
    }

    if(config->max_pdu_size > ISIS_DEFAULT_MAX_PDU_SIZE) {
        if(interface->mtu < config->max_pdu_size + LLC_HDR_LEN) {
            LOG(ERROR, "IS-IS max-pdu-size %u exceeds MTU %u of interface %s (3 byte LLC header)\n",
                config->max_pdu_size, interface->mtu, interface->name);
            return false;
        }
        /* The DPDK buffers are limited to 2048 byte. */
        for(bbl_link_config_s *link = g_ctx->config.link_config; link; link = link->next) {
            if(link->io_mode == IO_MODE_DPDK) {
                LOG(ERROR, "IS-IS max-pdu-size %u is not supported with DPDK (interface %s)\n",
                    config->max_pdu_size, link->interface);
                return false;
            }
        }
    }
    interface->isis_max_pdu_len_rx = ISIS_MAX_PDU_LEN_RX(config->max_pdu_size);

    /* Init P2P adjacency. */
    if(interface_config->isis_p2p) {
        adjacency_p2p = calloc(1, sizeof(isis_adjacency_p2p_s));
        if(!adjacency_p2p) return false;
        interface->isis_adjacency_p2p = adjacency_p2p;
        adjacency_p2p->interface = interface;
        adjacency_p2p->instance  = instance; 
        adjacency_p2p->peer = calloc(1, sizeof(isis_peer_s));
        if(!adjacency_p2p->peer) return false;
        adjacency_p2p->peer->adjacency_p2p = adjacency_p2p;
        adjacency_p2p->level = levels;
        adjacency_p2p->state = ISIS_P2P_ADJACENCY_STATE_DOWN;
        interface->send_requests |= BBL_IF_SEND_ISIS_P2P_HELLO;
    } else {
        instance->next_pseudo_node_id++;
    }

    /* Init adjacency levels. */
    for(int i=0; i<ISIS_LEVELS; i++) {
        level = i+1;
        if(!(levels & level)) {
            continue;
        }
        adjacency = calloc(1, sizeof(isis_adjacency_s));
        if(!adjacency) return false;
        interface->isis_adjacency[i] = adjacency;
        adjacency->interface = interface;
        adjacency->instance = instance;
        if(interface_config->isis_p2p) {
            if(!adjacency_p2p) return false;
            adjacency->p2p = true;
            adjacency->peer = adjacency_p2p->peer;
        } else {
            adjacency->pseudo_node_id = instance->next_pseudo_node_id;
        }
        if(instance->level[i].adjacency) {
            adjacency->next = instance->level[i].adjacency;
        }
        instance->level[i].adjacency = adjacency;

        adjacency->flood_tree = hb_tree_new((dict_compare_func)isis_lsp_id_compare);
        adjacency->psnp_tree = hb_tree_new((dict_compare_func)isis_lsp_id_compare);
        adjacency->levels = levels;
        adjacency->level = level;
        adjacency->window_size = config->lsp_tx_window_size;
        if(level == ISIS_LEVEL_1) {
            adjacency->priority = interface_config->isis_l1_priority;
            adjacency->metric = interface_config->isis_l1_metric;
            if(!interface_config->isis_p2p) interface->send_requests |= BBL_IF_SEND_ISIS_L1_HELLO;
        } else {
            adjacency->priority = interface_config->isis_l2_priority;
            adjacency->metric = interface_config->isis_l2_metric;
            if(!interface_config->isis_p2p) interface->send_requests |= BBL_IF_SEND_ISIS_L2_HELLO;
        }
	if(interface_config->isis_adjacency_sid > 0) {
	    adjacency->adjacency_sid = interface_config->isis_adjacency_sid;
	}
        adjacency->link_attr = interface_config->isis_link_attr;
        adjacency->bfd_profile_id = interface_config->isis_bfd_profile_id;
    }
    return true;
}

static void
isis_adjacency_bfd_cb(void *client, bfd_session_s *session, bfd_event_t event)
{
    isis_adjacency_s *adjacency = client;
    isis_peer_s *peer;
    UNUSED(session);

    if(event != BFD_EVENT_DOWN || adjacency->state != ISIS_ADJACENCY_STATE_UP) {
        return;
    }
    if(adjacency->p2p) {
        isis_peer_down_p2p(adjacency->peer, "BFD down");
        return;
    }
    peer = adjacency->peer;
    while(peer) {
        if(peer->state == ISIS_PEER_STATE_UP) {
            isis_peer_down(peer, "BFD down");
        }
        peer = peer->next;
    }
}

/**
 * isis_adjacency_bfd_add
 *
 * One BFD session per address family of the adjacency (RFC 6213),
 * to the IPv4 interface address (TLV 132) and the IPv6 link-local
 * address (TLV 232) of the neighbor. Called for every hello of an
 * adjacency in state up, as the addresses may be advertised later.
 *
 * @param adjacency IS-IS adjacency
 */
void
isis_adjacency_bfd_add(isis_adjacency_s *adjacency)
{
    bbl_network_interface_s *interface = adjacency->interface;
    isis_peer_s *peer = adjacency->peer;

    if(!adjacency->bfd_profile_id || adjacency->state != ISIS_ADJACENCY_STATE_UP ||
       (adjacency->bfd && adjacency->bfd6)) {
        return;
    }
    while(peer && !adjacency->p2p && peer->state != ISIS_PEER_STATE_UP) {
        peer = peer->next;
    }
    if(!peer) {
        return;
    }
    if(!adjacency->bfd && interface->ip.address && peer->ipv4) {
        adjacency->bfd = bfd_session_client_add(interface, adjacency->bfd_profile_id, false,
                                                AF_INET, NULL, &peer->ipv4,
                                                BFD_CLIENT_ISIS, adjacency, isis_adjacency_bfd_cb);
    }
    if(!adjacency->bfd6 && ipv6_addr_not_zero(&peer->ipv6)) {
        adjacency->bfd6 = bfd_session_client_add(interface, adjacency->bfd_profile_id, false,
                                                 AF_INET6, NULL, &peer->ipv6,
                                                 BFD_CLIENT_ISIS, adjacency, isis_adjacency_bfd_cb);
    }
}

/**
 * isis_adjacency_up
 *
 * @param adjacency IS-IS adjacency
 */
void 
isis_adjacency_up(isis_adjacency_s *adjacency)
{
    isis_config_s *config = adjacency->instance->config;

    if(adjacency->state == ISIS_ADJACENCY_STATE_UP) {
        return;
    }
    if(adjacency->instance->teardown) {
        /* Hellos received after the teardown job set the adjacencies
         * down must not bring them up again, the instance would never
         * terminate (routing sessions). */
        return;
    }

    LOG(ISIS, "ISIS %s adjacency UP to %s on interface %s \n", 
        isis_level_string(adjacency->level), 
        isis_system_id_to_str(adjacency->peer->system_id),
        adjacency->interface->name);

    adjacency->state = ISIS_ADJACENCY_STATE_UP;

    timer_add_periodic(&g_ctx->timer_root, &adjacency->timer_csnp, 
        "ISIS CSNP", config->csnp_interval, 0, adjacency, &isis_csnp_job);

    timer_add(&g_ctx->timer_root, &adjacency->timer_csnp_next, 
        "ISIS CSNP", 0, 10 * MSEC, adjacency, &isis_csnp_job);

    if(adjacency->p2p) {
        timer_add_periodic(&g_ctx->timer_root, &adjacency->timer_tx, 
            "ISIS TX", 0, config->lsp_tx_interval * MSEC, adjacency, &isis_lsp_tx_p2p_job);

        timer_add_periodic(&g_ctx->timer_root, &adjacency->timer_retry, 
            "ISIS RETRY", 1, 0, adjacency, &isis_lsp_retry_job);
    } else {
        timer_add_periodic(&g_ctx->timer_root, &adjacency->timer_tx, 
            "ISIS TX", 0, config->lsp_tx_interval * MSEC, adjacency, &isis_lsp_tx_job);
    }

    g_ctx->routing_sessions++;
    isis_adjacency_bfd_add(adjacency);
}

/**
 * isis_adjacency_down
 *
 * @param adjacency IS-IS adjacency
 */
void
isis_adjacency_down(isis_adjacency_s *adjacency, const char *reason)
{
    if(adjacency->state == ISIS_ADJACENCY_STATE_DOWN) {
        return;
    }
    adjacency->state = ISIS_ADJACENCY_STATE_DOWN;

    LOG(ISIS, "ISIS %s adjacency DOWN to %s on interface %s (%s)\n", 
        isis_level_string(adjacency->level), 
        isis_system_id_to_str(adjacency->peer->system_id),
        adjacency->interface->name, reason);

    if(adjacency->bfd) {
        bfd_session_client_del(adjacency->bfd, adjacency);
        adjacency->bfd = NULL;
    }
    if(adjacency->bfd6) {
        bfd_session_client_del(adjacency->bfd6, adjacency);
        adjacency->bfd6 = NULL;
    }

    timer_del(adjacency->timer_tx);
    timer_del(adjacency->timer_retry);
    timer_del(adjacency->timer_csnp);
    timer_del(adjacency->timer_csnp_next);
    timer_del(adjacency->timer_psnp_next);
    adjacency->timer_psnp_started = false;
    adjacency->csnp_start = 0;

    /* Pending LSPs are sent again by the database
     * synchronization once the adjacency is up. */
    hb_tree_clear(adjacency->flood_tree, isis_flood_entry_free);
    hb_tree_clear(adjacency->psnp_tree, isis_psnp_free);

    if(g_ctx->routing_sessions) g_ctx->routing_sessions--;
}
