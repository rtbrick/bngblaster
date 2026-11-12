/*
 * BNG Blaster (BBL) - IS-IS Peer/Neighbor
 *
 * Christian Giese, June 2024
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

/**
 * Select DIS and return true if DIS has changed. 
 */
bool
isis_peer_dis_elect(isis_adjacency_s *adjacency)
{
    uint8_t priority = adjacency->priority;
    uint8_t *mac = adjacency->interface->mac;
    isis_peer_s *dis = NULL;
    isis_peer_s *peer = adjacency->peer;
    while(peer) {
        if(peer->pseudo_node_id && peer->state == ISIS_PEER_STATE_UP && 
           (peer->priority > priority ||
           (peer->priority == priority && 
            compare_mac_addresses(peer->mac, mac) > 0))) {
            priority = peer->priority;
            dis = peer;
            mac = peer->mac;
        }
        peer = peer->next;
    }
    if(dis != adjacency->dis) {
        LOG(ISIS, "ISIS %s DIS changed from %s to %s on interface %s\n",
            isis_level_string(adjacency->level), 
            adjacency->dis ? isis_pseudo_node_id_to_str(adjacency->dis->system_id, adjacency->dis->pseudo_node_id) : "self",
            dis ? isis_pseudo_node_id_to_str(dis->system_id, dis->pseudo_node_id) : "self",
            adjacency->interface->name);
        adjacency->dis = dis;
        return true;
    }
    return false;
}

/**
 * isis_peer_down_p2p
 *
 * @param peer P2P peer
 * @param reason reason for logging
 */
void
isis_peer_down_p2p(isis_peer_s *peer, const char *reason)
{
    isis_adjacency_s *adjacency;
    isis_adjacency_p2p_s *adjacency_p2p = peer->adjacency_p2p;
    bbl_network_interface_s *interface = adjacency_p2p->interface;
    
    if(peer->state == ISIS_PEER_STATE_DOWN) {
        return;
    }
    peer->state = ISIS_PEER_STATE_DOWN;
    adjacency_p2p->state = ISIS_P2P_ADJACENCY_STATE_DOWN;

    LOG(ISIS, "ISIS P2P %s to %s on interface %s\n",
        reason, isis_system_id_to_str(peer->system_id), interface->name);

    for(int i=0; i<ISIS_LEVELS; i++) {
        adjacency = interface->isis_adjacency[i];
        if(adjacency) {
            isis_adjacency_down(adjacency, reason);
            isis_lsp_self_update(adjacency->instance, adjacency->level);
        }
    }
}

void
isis_peer_hold_timeout_p2p(timer_s *timer)
{
    isis_peer_down_p2p(timer->data, "hold timeout");
}

/**
 * isis_peer_down
 *
 * @param peer broadcast peer
 * @param reason reason for logging
 */
void
isis_peer_down(isis_peer_s *peer, const char *reason)
{
    isis_adjacency_s *adjacency = peer->adjacency;

    if(peer->state == ISIS_PEER_STATE_DOWN) {
        return;
    }
    peer->state = ISIS_PEER_STATE_DOWN;

    LOG(ISIS, "ISIS %s %s to %s on interface %s\n",
        isis_level_string(adjacency->level), reason,
        isis_system_id_to_str(peer->system_id),
        adjacency->interface->name);

    if(adjacency->level == ISIS_LEVEL_1) {
        adjacency->interface->send_requests |= BBL_IF_SEND_ISIS_L1_HELLO;
    } else {
        adjacency->interface->send_requests |= BBL_IF_SEND_ISIS_L2_HELLO;
    }

    peer = adjacency->peer;
    while(peer) {
        if(peer->state == ISIS_PEER_STATE_UP) {
            isis_peer_dis_elect(adjacency);
            isis_lsp_self_update(adjacency->instance, adjacency->level);
            return;
        }
        peer = peer->next;
    }    
    isis_adjacency_down(adjacency, reason);
    isis_peer_dis_elect(adjacency);
    isis_lsp_self_update(adjacency->instance, adjacency->level);
}

void
isis_peer_hold_timeout(timer_s *timer)
{
    isis_peer_down(timer->data, "hold timeout");
}

/* Interface addresses of the neighbor used for BFD, which
 * are IPv4 or link-local IPv6 addresses in hellos. */
static void
isis_peer_update_addresses(isis_peer_s *peer, isis_pdu_s *pdu)
{
    isis_tlv_s *tlv = isis_pdu_first_tlv(pdu);
    while(tlv) {
        if(tlv->type == ISIS_TLV_IPV4_INT_ADDRESS && tlv->len >= IPV4_ADDR_LEN) {
            memcpy(&peer->ipv4, tlv->value, IPV4_ADDR_LEN);
        } else if(tlv->type == ISIS_TLV_IPV6_INT_ADDRESS && tlv->len >= IPV6_ADDR_LEN) {
            memcpy(&peer->ipv6, tlv->value, IPV6_ADDR_LEN);
        }
        tlv = isis_pdu_next_tlv(pdu);
    }
}

void
isis_peer_update(isis_peer_s *peer, isis_pdu_s *pdu)
{
    bbl_network_interface_s *interface;

    isis_peer_update_addresses(peer, pdu);
    /* BFD sessions of adjacencies which are already up. */
    if(peer->adjacency_p2p) {
        interface = peer->adjacency_p2p->interface;
        for(int i=0; i<ISIS_LEVELS; i++) {
            if(interface->isis_adjacency[i]) isis_adjacency_bfd_add(interface->isis_adjacency[i]);
        }
    } else if(peer->adjacency && peer->state == ISIS_PEER_STATE_UP) {
        isis_adjacency_bfd_add(peer->adjacency);
    }
    peer->level = *ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_LEVEL) & 0x03;
    memcpy(peer->system_id, ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_SYSTEM_ID), ISIS_SYSTEM_ID_LEN);
    peer->hold_time = be16toh(*(uint16_t*)ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_HOLD_TIME));
    if(peer->adjacency_p2p) {
        timer_add(&g_ctx->timer_root, &peer->timer_hold, 
                "ISIS Hold", peer->hold_time, 0, peer, 
                &isis_peer_hold_timeout_p2p);
    } else {
        peer->priority = *ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_PRIORITY);
        if(memcmp(peer->system_id, ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_DIS), ISIS_SYSTEM_ID_LEN) == 0) {
            peer->pseudo_node_id = *ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_DIS_PSEUDO);
        } else {
            /* The peer no longer claims to be DIS. */
            peer->pseudo_node_id = 0;
        }
        timer_add(&g_ctx->timer_root, &peer->timer_hold, 
                  "ISIS Hold", peer->hold_time, 0, peer, 
                  &isis_peer_hold_timeout);
    }
}

/**
 * Return true if one of the areas of a received hello matches
 * one of the areas of the instance (ISO 10589 8.2.4 and 8.4.2).
 */
static bool
isis_peer_area_match(isis_config_s *config, isis_pdu_s *pdu)
{
    isis_tlv_s *tlv;
    uint8_t offset, len;

    tlv = isis_pdu_first_tlv(pdu);
    while(tlv) {
        if(tlv->type == ISIS_TLV_AREA_ADDRESSES) {
            offset = 0;
            while(offset < tlv->len) {
                len = tlv->value[offset++];
                if(offset + len > tlv->len) {
                    break;
                }
                for(int i = 0; i < config->area_count; i++) {
                    if(config->area[i].len == len &&
                       memcmp(config->area[i].value, tlv->value+offset, len) == 0) {
                        return true;
                    }
                }
                offset += len;
            }
        }
        tlv = isis_pdu_next_tlv(pdu);
    }
    return false;
}

/**
 * Check a received hello for the given level: the system-id must not
 * be the own one, the circuit type must include the level and level 1
 * requires a common area (ISO 10589 8.2 and 8.4).
 */
bool
isis_peer_hello_valid(isis_instance_s *instance, isis_pdu_s *pdu, uint8_t level)
{
    isis_config_s *config = instance->config;
    uint8_t circuit_type = *ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_LEVEL) & 0x03;

    if(memcmp(ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_HELLO_SYSTEM_ID), config->system_id, ISIS_SYSTEM_ID_LEN) == 0) {
        return false;
    }
    if(!(circuit_type & level)) {
        return false;
    }
    if(level == ISIS_LEVEL_1 && !isis_peer_area_match(config, pdu)) {
        return false;
    }
    return true;
}

isis_peer_s*
isis_peer(isis_adjacency_s *adjacency, uint8_t *mac)
{
    isis_peer_s *peer = adjacency->peer;
    while(peer) {
        if(memcmp(peer->mac, mac, ETH_ADDR_LEN) == 0) {
            return peer;
        }
        peer = peer->next;
    }
    peer = calloc(1, sizeof(isis_peer_s));
    peer->next = adjacency->peer;
    peer->adjacency = adjacency;
    adjacency->peer = peer;
    if(mac) {
        memcpy(peer->mac, mac, ETH_ADDR_LEN);
    }
    return peer;
}
