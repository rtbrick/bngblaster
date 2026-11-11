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
    uint8_t pdu_buf[ISIS_PDU_BUF_LEN];
    isis_pdu_s pdu = {.pdu = pdu_buf};
    bbl_isis_s isis = {0};

    isis_adjacency_p2p_s *adjacency = interface->isis_adjacency_p2p;
    isis_instance_s      *instance  = adjacency->instance;
    isis_config_s        *config    = instance->config;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    pdu.size = ISIS_MAX_PDU_LEN_TX(config, interface);

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
    isis_pdu_add_tlv_p2p_adjacency_state(&pdu, adjacency->state, interface->vlindex, adjacency->peer);
    if(config->hello_padding) {
        isis_pdu_padding(&pdu);
    }
    isis_pdu_update_len(&pdu);
    isis_pdu_update_auth(&pdu, key);

    /* Hellos are not fragmented. */
    if(pdu.pdu_len + LLC_HDR_LEN > interface->mtu) {
        return ENCODE_ERROR;
    }
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
 * Set the IS-IS adjacencies of a P2P interface up or down. A level is
 * only up if the neighbor supports it, level 1 requires a common area.
 */
static void
isis_p2p_adjacency_update(bbl_network_interface_s *interface, isis_pdu_s *pdu, bool up)
{
    isis_adjacency_p2p_s *adjacency_p2p = interface->isis_adjacency_p2p;
    isis_adjacency_s *adjacency;
    bool level_up;

    for(int i=0; i<ISIS_LEVELS; i++) {
        adjacency = interface->isis_adjacency[i];
        if(!adjacency) {
            continue;
        }
        level_up = up && pdu && isis_peer_hello_valid(adjacency_p2p->instance, pdu, adjacency->level);
        if(level_up == (adjacency->state == ISIS_ADJACENCY_STATE_UP)) {
            continue;
        }
        if(level_up) {
            isis_adjacency_up(adjacency);
        } else {
            isis_adjacency_down(adjacency, "hello goodbye");
        }
        isis_lsp_self_update(adjacency->instance, adjacency->level);
    }
}

/**
 * isis_p2p_hello_handler_rx
 *
 * The three-way handshake follows RFC 5303, P2P hellos
 * without adjacency state TLV are accepted (RFC 1195).
 *
 * @param interface receive interface
 * @param pdu received ISIS PDU
 */
void
isis_p2p_hello_handler_rx(bbl_network_interface_s *interface, isis_pdu_s *pdu)
{
    isis_adjacency_p2p_s *adjacency_p2p = interface->isis_adjacency_p2p;
    isis_instance_s *instance;
    isis_config_s *config;
    isis_peer_s *peer;
    isis_tlv_s *tlv;
    
    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    uint8_t received_state = ISIS_P2P_ADJACENCY_STATE_UP;
    uint8_t state;
    bool three_way = false;
    uint8_t *system_id;

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

    system_id = ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_SYSTEM_ID);
    if(memcmp(system_id, config->system_id, ISIS_SYSTEM_ID_LEN) == 0) {
        LOG(ISIS, "ISIS RX P2P-Hello with own system-id on interface %s\n", interface->name);
        return;
    }
    if(peer->state != ISIS_PEER_STATE_DOWN &&
       memcmp(peer->system_id, system_id, ISIS_SYSTEM_ID_LEN) != 0) {
        /* The system-id of the neighbor has changed, so the
         * adjacency is initialized again. */
        LOG(ISIS, "ISIS P2P neighbor %s changed system-id on interface %s\n",
            isis_system_id_to_str(peer->system_id), interface->name);
        adjacency_p2p->state = ISIS_P2P_ADJACENCY_STATE_DOWN;
        peer->ext_circuit_id_valid = false;
        isis_p2p_adjacency_update(interface, NULL, false);
    }

    isis_peer_update(peer, pdu);

    tlv = isis_pdu_first_tlv(pdu);
    while(tlv) {
        if(tlv->type == ISIS_TLV_P2P_ADJACENCY_STATE && tlv->len >= 1) {
            three_way = true;
            received_state = tlv->value[0];
            if(tlv->len >= 5) {
                peer->ext_circuit_id = be32toh(*(uint32_t*)&tlv->value[1]);
                peer->ext_circuit_id_valid = true;
            }
            /* The neighbor reports another system or circuit (RFC 5303 section 3.3). */
            if(tlv->len >= 11 && memcmp(&tlv->value[5], config->system_id, ISIS_SYSTEM_ID_LEN) != 0) {
                received_state = ISIS_P2P_ADJACENCY_STATE_DOWN;
            }
            if(tlv->len >= 15 && be32toh(*(uint32_t*)&tlv->value[11]) != interface->vlindex) {
                received_state = ISIS_P2P_ADJACENCY_STATE_DOWN;
            }
            break;
        }
        tlv = isis_pdu_next_tlv(pdu);
    }

    if(!three_way) {
        /* Hellos without adjacency state TLV are handled
         * by the two-way handshake of ISO 10589 (RFC 5303
         * section 3.1), the adjacency is up immediately. */
        state = ISIS_P2P_ADJACENCY_STATE_UP;
    } else {
        /* State transition table (RFC 5303 section 3.2) */
        switch(received_state) {
            case ISIS_P2P_ADJACENCY_STATE_DOWN:
                state = ISIS_P2P_ADJACENCY_STATE_INIT;
                break;
            case ISIS_P2P_ADJACENCY_STATE_INIT:
                state = ISIS_P2P_ADJACENCY_STATE_UP;
                break;
            case ISIS_P2P_ADJACENCY_STATE_UP:
                if(adjacency_p2p->state == ISIS_P2P_ADJACENCY_STATE_DOWN) {
                    state = ISIS_P2P_ADJACENCY_STATE_DOWN;
                } else {
                    state = ISIS_P2P_ADJACENCY_STATE_UP;
                }
                break;
            default:
                return;
        }
    }
    peer->state = state == ISIS_P2P_ADJACENCY_STATE_UP ? ISIS_PEER_STATE_UP : ISIS_PEER_STATE_INIT;

    if(adjacency_p2p->state != state) {
        adjacency_p2p->state = state;
        interface->send_requests |= BBL_IF_SEND_ISIS_P2P_HELLO;
    }
    isis_p2p_adjacency_update(interface, pdu, state == ISIS_P2P_ADJACENCY_STATE_UP);
}
