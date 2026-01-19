/*
 * BNG Blaster (BBL) - ARP Client
 *
* Christian Giese, March 2025
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

extern volatile bool g_teardown;
extern bool g_init_phase;

static bbl_txq_result_t
bbl_arp_client_tx(bbl_arp_client_s *client)
{
    bbl_session_s *session = client->session;
    bbl_ethernet_header_s eth = {0};
    bbl_arp_s arp = {0};

    eth.dst = (uint8_t*)broadcast_mac;
    eth.type = ETH_TYPE_ARP;
    eth.vlan_inner_priority = client->vlan_priority;
    eth.vlan_outer_priority = client->vlan_priority;
    eth.next = &arp;
    arp.code = ARP_REQUEST;
    arp.target_ip = client->target_ip;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    arp.sender = session->client_mac;
    arp.sender_ip = session->ip_address;    
    return bbl_txq_to_buffer(session->access_interface->txq, &eth);
}

void
bbl_arp_client_job(timer_s *timer)
{
    bbl_arp_client_s *client = timer->data;
    bbl_session_s *session = client->session;

    if(g_init_phase || g_teardown || session->endpoint.ipv4 != ENDPOINT_ACTIVE) {
        return;
    }

    if(bbl_arp_client_tx(client) == BBL_TXQ_OK) {
        client->tx++;
    }
}

static bool
bbl_arp_client_add(bbl_arp_client_config_s *config, bbl_session_s *session)
{
    bbl_arp_client_s *client = calloc(1, sizeof(bbl_arp_client_s));
    client->target_ip = config->target_ip;
    client->session = session;

    /* Add to session ARP client list */
    client->next = session->arp_client;
    session->arp_client = client;

    timer_add_periodic(&g_ctx->timer_root, &client->timer, 
                       "ARP", config->interval, 0, client,
                       &bbl_arp_client_job);
    return true;
}

/**
 * Init ARP clients on IPoE session. 
 */
bool
bbl_arp_client_session_init(bbl_session_s *session)
{
    bbl_arp_client_config_s *config;
    uint16_t arp_client_group_id = session->access_config->arp_client_group_id;

    if(session->access_type != ACCESS_TYPE_IPOE) return true;

    /** Add clients of corresponding arp-client-group-id */
    if(arp_client_group_id) {
        config = g_ctx->config.arp_client_config;
        while(config) {
            if(config->arp_client_group_id == arp_client_group_id) {
                if(!bbl_arp_client_add(config, session)) {
                    return false;
                }
            }
            config = config->next;
        }
    }
    return true;
}

void
bbl_arp_client_rx(bbl_session_s *session, bbl_arp_s *arp)
{
    bbl_arp_client_s *client = session->arp_client;
    while(client) {
        if(client->target_ip == arp->sender_ip) {
            memcpy(client->target_mac, arp->sender, ETH_ADDR_LEN);
            client->rx++;
        }
        client = client->next;
    }
}

void
bbl_arp_client_reset(bbl_session_s *session)
{
    bbl_arp_client_s *client = session->arp_client;
    while(client) {
        memset(client->target_mac, 0x0, ETH_ADDR_LEN);
        client->tx = 0;
        client->rx = 0;
        client = client->next;
    }
    return;
}

static json_t *
bbl_arp_client_json(bbl_arp_client_s *client)
{
    if(!client) return NULL;  
    return json_pack("{sI ss* ss* ss* ss* sI sI}",
        "session-id", client->session->session_id,
        "sender-ip", format_ipv4_address(&client->session->ip_address),
        "sender-mac", format_mac_address(client->session->client_mac),
        "target-ip", format_ipv4_address(&client->target_ip),
        "target-mac", format_mac_address(client->target_mac),
        "tx", client->tx,
        "rx", client->rx);
}

int
bbl_arp_client_ctrl(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    int result = 0;
    uint32_t i;

    json_t *root;
    json_t *json_clients = json_array();;

    bbl_session_s *session;
    bbl_arp_client_s *client;

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            client = session->arp_client;
            while(client) {
                json_array_append_new(json_clients, bbl_arp_client_json(client));
                client = client->next;
            }
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                client = session->arp_client;
                while(client) {
                    json_array_append_new(json_clients, bbl_arp_client_json(client));
                    client = client->next;
                }
            }
        }
    }

    root = json_pack("{ss si so*}",
                     "status", "ok",
                     "code", 200,
                     "arp-clients", json_clients);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(json_clients);
    }
    return result;
}

int
bbl_arp_client_ctrl_reset(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    bbl_session_s *session;
    uint32_t i;

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            bbl_arp_client_reset(session);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                bbl_arp_client_reset(session);
            }
        }
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}