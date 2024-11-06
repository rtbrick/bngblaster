/*
 * BNG Blaster (BBL) - IS-IS Peer/Neighbor
 *
 * Christian Giese, June 2024
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
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
            compare_mac_addresses(peer->mac, mac)))) {
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

void
isis_peer_hold_timeout_p2p(timer_s *timer)
{
    isis_peer_s *peer = timer->data;
    isis_adjacency_s *adjacency;
    isis_adjacency_p2p_s *adjacency_p2p = peer->adjacency_p2p;
    bbl_network_interface_s *interface = adjacency_p2p->interface;
    
    if(peer->state == ISIS_PEER_STATE_DOWN) {
        return;
    }
    peer->state = ISIS_PEER_STATE_DOWN;
    adjacency_p2p->state = ISIS_P2P_ADJACENCY_STATE_DOWN;

    LOG(ISIS, "ISIS P2P hold timeout to %s on interface %s\n",
        isis_system_id_to_str(peer->system_id), interface->name);

    for(int i=0; i<ISIS_LEVELS; i++) {
        adjacency = interface->isis_adjacency[i];
        if(adjacency) {
            isis_adjacency_down(adjacency, "timeout");
            isis_lsp_self_update(adjacency->instance, adjacency->level);
        }
    }
}

void
isis_peer_hold_timeout(timer_s *timer)
{
    isis_peer_s *peer = timer->data;
    isis_adjacency_s *adjacency = peer->adjacency;

    if(peer->state == ISIS_PEER_STATE_DOWN) {
        return;
    }
    peer->state = ISIS_PEER_STATE_DOWN;

    LOG(ISIS, "ISIS %s hold timeout to %s on interface %s\n",
        isis_level_string(adjacency->level), 
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
    isis_adjacency_down(adjacency, "timeout");
    isis_peer_dis_elect(adjacency);
    isis_lsp_self_update(adjacency->instance, adjacency->level);
}

void
isis_peer_update(isis_peer_s *peer, isis_pdu_s *pdu)
{
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
        }
        timer_add(&g_ctx->timer_root, &peer->timer_hold, 
                  "ISIS Hold", peer->hold_time, 0, peer, 
                  &isis_peer_hold_timeout);
    }
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
