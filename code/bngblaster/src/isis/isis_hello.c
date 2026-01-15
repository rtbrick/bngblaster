/*
 * BNG Blaster (BBL) - IS-IS Hello
 *
 * Christian Giese, June 2024
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

void
isis_hello_timeout(timer_s *timer)
{
    isis_adjacency_s *adjacency = timer->data;
    bbl_network_interface_s *interface = adjacency->interface;
    if(adjacency->level == ISIS_LEVEL_1) {
        interface->send_requests |= BBL_IF_SEND_ISIS_L1_HELLO;
    } else {
        interface->send_requests |= BBL_IF_SEND_ISIS_L2_HELLO;
    }
}

/**
 * isis_hello_encode
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @param level ISIS level
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
isis_hello_encode(bbl_network_interface_s *interface,
                  uint8_t *buf, uint16_t *len, 
                  bbl_ethernet_header_s *eth,
                  uint8_t level)
{
    protocol_error_t result;
    isis_pdu_s pdu = {0};
    bbl_isis_s isis = {0};

    isis_adjacency_s    *adjacency = interface->isis_adjacency[level-1];
    isis_instance_s     *instance  = adjacency->instance;
    isis_config_s       *config    = instance->config;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    /* Start next timer ... */
    timer_add(&g_ctx->timer_root, &adjacency->timer_hello, 
              "ISIS Hello", config->hello_interval, 0, adjacency, 
              &isis_hello_timeout);

    /* Build PDU */
    if(adjacency->level & ISIS_LEVEL_1) {
        if(config->level1_auth_hello) {
            auth = config->level1_auth;
            key = config->level1_key;
        }
        eth->dst = g_isis_mac_all_l1;
        isis_pdu_init(&pdu, ISIS_PDU_L1_HELLO);
    } else {
        if(config->level2_auth_hello) {
            auth = config->level2_auth;
            key = config->level2_key;
        }
        eth->dst = g_isis_mac_all_l2;
        isis_pdu_init(&pdu, ISIS_PDU_L2_HELLO);
    } 
    /* PDU header */
    isis_pdu_add_u8(&pdu, adjacency->levels);
    isis_pdu_add_bytes(&pdu, config->system_id, ISIS_SYSTEM_ID_LEN);
    isis_pdu_add_u16(&pdu, config->hold_time);
    isis_pdu_add_u16(&pdu, 0);
    isis_pdu_add_u8(&pdu, adjacency->priority);
    if(adjacency->dis) {
        isis_pdu_add_bytes(&pdu, adjacency->dis->system_id, ISIS_SYSTEM_ID_LEN);
        isis_pdu_add_u8(&pdu, adjacency->dis->pseudo_node_id);
    } else {
        /* Advertise myself as DIS */
        isis_pdu_add_bytes(&pdu, config->system_id, ISIS_SYSTEM_ID_LEN);
        isis_pdu_add_u8(&pdu, adjacency->pseudo_node_id);
    }
    /* TLV section */
    isis_pdu_add_tlv_auth(&pdu, auth, key);
    isis_pdu_add_tlv_area(&pdu, config->area, config->area_count);
    isis_pdu_add_tlv_protocols(&pdu, config->protocol_ipv4, config->protocol_ipv6);
    if(config->protocol_ipv4) {
        isis_pdu_add_tlv_ipv4_int_address(&pdu, interface->ip.address);
    }
    if(config->protocol_ipv6) {
        isis_pdu_add_tlv_ipv6_int_address(&pdu, &interface->ip6_ll);
    }
    isis_pdu_add_tlv_is_neighbor(&pdu, adjacency);
    if(config->hello_padding) {
        isis_pdu_padding(&pdu);
    }
    isis_pdu_update_len(&pdu);
    isis_pdu_update_auth(&pdu, key);
    /* Build packet ... */
    eth->type = ISIS_PROTOCOL_IDENTIFIER;
    eth->next = &isis;
    isis.type = pdu.pdu_type;
    isis.pdu = pdu.pdu;
    isis.pdu_len = pdu.pdu_len;
    result = encode_ethernet(buf, len, eth);
    if(result == PROTOCOL_SUCCESS) {
        LOG(PACKET, "ISIS TX %s on interface %s\n",
            isis_pdu_type_string(isis.type), interface->name);
        adjacency->stats.hello_tx++;
        adjacency->interface->stats.isis_tx++;
    }
    return result;
}

/**
 * Return true if MAC is listed in IS neighbor list.
 */
static bool
is_neighbor(isis_tlv_s *tlv, uint8_t *mac)
{
    uint8_t *cur = tlv->value; 
    uint8_t len = tlv->len;
    while(len >= ETH_ADDR_LEN) {
        if(memcmp(cur, mac, ETH_ADDR_LEN) == 0) {
            return true;
        }
        cur += ETH_ADDR_LEN; len -= ETH_ADDR_LEN;
    }
    return false;
}

/**
 * isis_hello_handler_rx
 *
 * @param interface receive interface
 * @param eth receive ethernet packet
 * @param pdu received ISIS PDU
 * @param level ISIS level
 */
void
isis_hello_handler_rx(bbl_network_interface_s *interface, 
                      bbl_ethernet_header_s *eth, 
                      isis_pdu_s *pdu, uint8_t level)
{
    isis_adjacency_s *adjacency = interface->isis_adjacency[level-1];
    isis_instance_s  *instance  = NULL;
    isis_config_s    *config    = NULL;

    isis_peer_s *peer;
    isis_tlv_s *tlv;

    uint8_t new_state = ISIS_PEER_STATE_INIT;
    uint8_t dis_pseudo_node_id = 0;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;
    bool self_update = false;
    bool adjacency_up = false;

    if(interface->isis_adjacency_p2p) {
        LOG(ISIS, "ISIS RX %s-Hello on P2P interface %s\n",
            isis_level_string(level), interface->name);
        return;
    }
    if(!adjacency) {
        LOG(ISIS, "ISIS RX %s-Hello on %s disabled interface %s\n",
            isis_level_string(level), isis_level_string(level), interface->name);
        return;
    }
    instance = adjacency->instance;
    config = instance->config;

    adjacency->stats.hello_rx++;

    if((adjacency->level & ISIS_LEVEL_1) && config->level1_auth_hello) {
        auth = config->level1_auth;
        key = config->level1_key;
    } else if((adjacency->level & ISIS_LEVEL_2) && config->level2_auth_hello) {
        auth = config->level2_auth;
        key = config->level2_key;
    }

    if(!isis_pdu_validate_auth(pdu, auth, key)) {
        LOG(ISIS, "ISIS RX %s-Hello authentication failed on interface %s\n",
            isis_level_string(level), interface->name);
        return;
    }


    if(adjacency->dis) dis_pseudo_node_id = adjacency->dis->pseudo_node_id;

    peer = isis_peer(adjacency, eth->src);
    isis_peer_update(peer, pdu);

    if(adjacency->dis && adjacency->dis->pseudo_node_id != dis_pseudo_node_id) {
        /* This check is required to handle the case where DIS remains 
         * but pseudo-node-id of DIS has changed. */
        self_update = true;
    }

    tlv = isis_pdu_first_tlv(pdu);
    while(tlv) {
        switch(tlv->type) {
            case ISIS_TLV_IS_NEIGHBOR:
                if(is_neighbor(tlv, interface->mac)) {
                    new_state = ISIS_PEER_STATE_UP;
                }
                break;
            default:
                break;
        }
        tlv = isis_pdu_next_tlv(pdu);
    }

    if(peer->state != new_state) {
        peer->state = new_state;
        self_update = true;
        if(adjacency->level & ISIS_LEVEL_1) {
            interface->send_requests |= BBL_IF_SEND_ISIS_L1_HELLO;
        } else {
            interface->send_requests |= BBL_IF_SEND_ISIS_L2_HELLO;
        }

        /* Update adjacency state */
        peer = adjacency->peer;
        while(peer) {
            if(peer->state == ISIS_PEER_STATE_UP) {
                adjacency_up = true;
                break;
            }
            peer = peer->next;
        }
        if(adjacency_up) {
            isis_adjacency_up(adjacency);
        } else {
            isis_adjacency_down(adjacency, "hello goodby");
        }
    }

    if(isis_peer_dis_elect(adjacency)) {
        self_update = true;
    }

    /* Update self originated LSP's if required! */
    if(self_update) isis_lsp_self_update(instance, adjacency->level);
}