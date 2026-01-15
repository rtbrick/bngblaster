/*
 * BNG Blaster (BBL) - IS-IS P2P Hello
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

void
isis_p2p_hello_timeout(timer_s *timer)
{
    bbl_network_interface_s *interface = timer->data;
    interface->send_requests |= BBL_IF_SEND_ISIS_P2P_HELLO;
}

/**
 * isis_p2p_hello_encode
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
isis_p2p_hello_encode(bbl_network_interface_s *interface, 
                      uint8_t *buf, uint16_t *len, 
                      bbl_ethernet_header_s *eth)
{
    protocol_error_t result;
    isis_pdu_s pdu = {0};
    bbl_isis_s isis = {0};

    isis_adjacency_p2p_s *adjacency = interface->isis_adjacency_p2p;
    isis_instance_s      *instance  = adjacency->instance;
    isis_config_s        *config    = instance->config;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    /* Start next timer ... */
    timer_add(&g_ctx->timer_root, &adjacency->timer_hello, 
              "ISIS Hello", config->hello_interval, 0, interface, 
              &isis_p2p_hello_timeout);

    if((interface->isis_adjacency[ISIS_LEVEL_1_IDX]) && config->level1_auth_hello) {
        auth = config->level1_auth;
        key = config->level1_key;
    } else if((interface->isis_adjacency[ISIS_LEVEL_2_IDX]) && config->level2_auth_hello) {
        auth = config->level2_auth;
        key = config->level2_key;
    }

    /* Build PDU */
    isis_pdu_init(&pdu, ISIS_PDU_P2P_HELLO);
    /* PDU header */
    isis_pdu_add_u8(&pdu, adjacency->level);
    isis_pdu_add_bytes(&pdu, config->system_id, ISIS_SYSTEM_ID_LEN);
    isis_pdu_add_u16(&pdu, config->hold_time);
    isis_pdu_add_u16(&pdu, 0);
    isis_pdu_add_u8(&pdu, 0x1);
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
    isis_pdu_add_tlv_p2p_adjacency_state(&pdu, adjacency->state, interface->vlindex);
    if(config->hello_padding) {
        isis_pdu_padding(&pdu);
    }
    isis_pdu_update_len(&pdu);
    isis_pdu_update_auth(&pdu, key);
    /* Build packet ... */
    eth->type = ISIS_PROTOCOL_IDENTIFIER;
    eth->next = &isis;
    eth->dst = g_isis_mac_p2p_hello;
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
 * isis_p2p_hello_handler_rx
 *
 * @param interface receive interface
 * @param pdu received ISIS PDU
 */
void
isis_p2p_hello_handler_rx(bbl_network_interface_s *interface, isis_pdu_s *pdu)
{
    isis_adjacency_p2p_s *adjacency_p2p = interface->isis_adjacency_p2p;
    isis_adjacency_s *adjacency;
    isis_instance_s *instance;
    isis_config_s *config;
    isis_peer_s *peer;
    isis_tlv_s *tlv;
    
    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    uint8_t peer_state = ISIS_PEER_STATE_UP;

    if(!adjacency_p2p) {
        LOG(ISIS, "ISIS RX P2P-Hello on broadcast interface %s\n", interface->name);
        return;
    }
    peer = adjacency_p2p->peer;
    instance = adjacency_p2p->instance;
    config = instance->config;

    adjacency_p2p->stats.hello_rx++;

    if((interface->isis_adjacency[ISIS_LEVEL_1_IDX]) && config->level1_auth_hello) {
        auth = config->level1_auth;
        key = config->level1_key;
    } else if((interface->isis_adjacency[ISIS_LEVEL_2_IDX]) && config->level2_auth_hello) {
        auth = config->level2_auth;
        key = config->level2_key;
    }

    if(!isis_pdu_validate_auth(pdu, auth, key)) {
        LOG(ISIS, "ISIS RX P2P-Hello authentication failed on interface %s\n",
            interface->name);
        return;
    }
    
    isis_peer_update(peer, pdu);

    tlv = isis_pdu_first_tlv(pdu);
    while(tlv) {
        switch(tlv->type) {
            case ISIS_TLV_P2P_ADJACENCY_STATE:
                switch(*tlv->value) {
                    case ISIS_P2P_ADJACENCY_STATE_UP:
                    case ISIS_P2P_ADJACENCY_STATE_INIT:
                        peer_state = ISIS_PEER_STATE_UP;
                        break;
                    case ISIS_P2P_ADJACENCY_STATE_DOWN:
                        peer_state = ISIS_PEER_STATE_INIT;
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
        tlv = isis_pdu_next_tlv(pdu);
    }

    if(peer->state != peer_state) {
        peer->state = peer_state;
        if(peer_state == ISIS_PEER_STATE_UP) {
            adjacency_p2p->state = ISIS_P2P_ADJACENCY_STATE_UP;
        } else {
            adjacency_p2p->state = ISIS_P2P_ADJACENCY_STATE_INIT;
        } 
        for(int i=0; i<ISIS_LEVELS; i++) {
            adjacency = interface->isis_adjacency[i];
            if(adjacency) {
                if(peer_state == ISIS_PEER_STATE_UP) {
                    isis_adjacency_up(adjacency);
                } else {
                    isis_adjacency_down(adjacency, "hello goodby");
                }
                isis_lsp_self_update(instance, adjacency->level);
            }
        }
        interface->send_requests |= BBL_IF_SEND_ISIS_P2P_HELLO;
    }
}
