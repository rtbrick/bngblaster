/*
 * BNG Blaster (BBL) - ICMP Client
 *
 * Christian Giese, December 2024
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

extern volatile bool g_teardown;
extern bool g_init_phase;

const char *
bbl_icmp_client_state_string(icmp_state_t state)
{
    switch(state) {
        case ICMP_DOWN: return "down";
        case ICMP_WAIT: return "wait";
        case ICMP_STARTED: return "started";
        case ICMP_STOPPED: return "stopped";
        default: return "unknown";
    }
}

const char *
bbl_icmp_client_result_string(icmp_result_t result)
{
    switch(result) {
        case ICMP_RESULT_NONE: return "none";
        case ICMP_RESULT_WAIT: return "wait";
        case ICMP_RESULT_OKAY: return "okay";
        case ICMP_RESULT_UNREACHABLE: return "unreachable";
        case ICMP_RESULT_REDIRECTED: return "redirected";
        case ICMP_RESULT_FRAGMENTATION_NEEDED: return "fragmentation-needed";
        case ICMP_RESULT_TTL_EXCEEDED: return "ttl-exceeded";
        default: return "unknown";
    }
}

static bbl_txq_result_t
bbl_icmp_client_tx(bbl_icmp_client_s *client, bbl_icmp_s *icmp)
{
    bbl_icmp_client_config_s *config = client->config;
    bbl_session_s *session = client->session;
    bbl_network_interface_s *network_interface = client->network_interface;
    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_ipv4_s ipv4 = {0};

    if(session) {
        eth.dst = session->server_mac;
        eth.src = session->client_mac;
        eth.qinq = session->access_config->qinq;
        eth.vlan_outer = session->vlan_key.outer_vlan_id;
        eth.vlan_inner = session->vlan_key.inner_vlan_id;
        eth.vlan_three = session->access_third_vlan;
        if(config->src) {
            ipv4.src = client->src;
        } else {
            ipv4.src = session->ip_address;
            client->src = ipv4.src;
        }
    } else {
        eth.dst = network_interface->gateway_mac;
        eth.src = network_interface->mac;
        eth.vlan_outer = network_interface->vlan;
        eth.vlan_inner = 0;
        ipv4.src = client->src;
    }

    if(session && session->access_type == ACCESS_TYPE_PPPOE) {
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV4;
        pppoe.next = &ipv4;
    } else {
        eth.type = ETH_TYPE_IPV4;
        eth.next = &ipv4;
    }
    ipv4.dst = client->dst;
    ipv4.ttl = config->ttl;
    ipv4.tos = config->tos;
    ipv4.protocol = PROTOCOL_IPV4_ICMP;
    ipv4.next = icmp;
    if(config->df) {
        ipv4.offset = IPV4_DF;
    }

    if(session) {
        return bbl_txq_to_buffer(session->access_interface->txq, &eth);
    } else {
        return bbl_txq_to_buffer(network_interface->txq, &eth);
    }
}

void
bbl_icmp_client_send_job_ping(timer_s *timer)
{
    bbl_icmp_client_s *client = timer->data;
    bbl_icmp_client_config_s *config = client->config;
    bbl_icmp_client_result_ping_s *result;
    bbl_icmp_s icmp = {0};

    bbl_session_s *session = client->session;
    bbl_network_interface_s *network_interface = client->network_interface;

    uint16_t slot = client->seq % config->results;

    if(session && session->endpoint.ipv4 != ENDPOINT_ACTIVE) {
        return;
    }
    if(client->state != ICMP_STARTED) {
        return;
    }

    result = &((bbl_icmp_client_result_ping_s*)client->result)[slot];
    memset(result, 0x0, sizeof(bbl_icmp_client_result_ping_s));
    *(uint16_t*)(client->data+2) = client->seq;

    icmp.type = ICMP_TYPE_ECHO_REQUEST;
    icmp.data = client->data;
    icmp.data_len = client->data_len;

    if(bbl_icmp_client_tx(client, &icmp) == BBL_TXQ_OK) {
        result->seq = client->seq;
        result->state = ICMP_RESULT_WAIT;
        result->timestamp_tx.tv_sec = timer->timestamp->tv_sec;
        result->timestamp_tx.tv_nsec = timer->timestamp->tv_nsec;
        client->seq++;
        client->send++;
        if(!client->last_result) client->last_result = ICMP_RESULT_WAIT;
        if(session) {
            session->stats.icmp_tx++;
            session->access_interface->stats.icmp_tx++;
            LOG(ICMP, "ICMP (ID: %u) send echo-request addr=%s id=%u seq=%u\n",
                session->session_id, format_ipv4_address(&client->dst), client->id, result->seq);
        } else {
            network_interface->stats.icmp_tx++;
            LOG(ICMP, "ICMP (%s) send echo-request addr=%s id=%u seq=%u\n",
                network_interface->name, format_ipv4_address(&client->dst), client->id, result->seq);
        }

        if(config->count && client->send >= config->count) {
            client->state = ICMP_STOPPED;
        }
    }
}

static void
bbl_icmp_client_start(bbl_icmp_client_s *client)
{
    bbl_icmp_client_config_s *config = client->config;
    bbl_session_s *session = client->session;

    if(session && session->endpoint.ipv4 != ENDPOINT_ACTIVE) return;

    if(client->state != ICMP_STARTED) {
        client->state = ICMP_STARTED;
        client->seq = 0;
        client->send = 0;
        client->received = 0;
        client->errors = 0;
        client->last_result = ICMP_RESULT_NONE;
        switch(config->mode) {
            case ICMP_MODE_PING:
                memset(client->result, 0x0, sizeof(bbl_icmp_client_result_ping_s) * client->results);
                timer_add_periodic(&g_ctx->timer_root, &client->send_timer, 
                                   "ICMP SEND", config->interval_sec, config->interval_nsec, client,
                                   &bbl_icmp_client_send_job_ping);
                break;    
            default:
                break;
        }
    }
}

static void
bbl_icmp_client_stop(bbl_icmp_client_s *client)
{
    bbl_session_s *session = client->session;

    client->state = ICMP_STOPPED;
    if(session && session->endpoint.ipv4 != ENDPOINT_ACTIVE) {
        client->state = ICMP_DOWN;
    } 
    timer_del(client->send_timer);
}

void
bbl_icmp_client_state_job(timer_s *timer)
{
    bbl_icmp_client_s *client = timer->data;

    if(g_init_phase || g_teardown) {
        client->state = ICMP_DOWN;
        timer_del(client->send_timer);
        return;
    }
    if(client->session && client->session->endpoint.ipv4 != ENDPOINT_ACTIVE) {
        client->state = ICMP_DOWN;
        timer_del(client->send_timer);
        return;
    }
    if(client->state == ICMP_DOWN) {
        if(client->config->autostart) {
            client->start_delay_countdown = client->config->start_delay;
            client->state = ICMP_WAIT;
        } else {
            client->state = ICMP_STOPPED;
        }
    }
    if(client->state == ICMP_WAIT) {
        if(client->start_delay_countdown) {
            client->start_delay_countdown--;
        } else {
            bbl_icmp_client_start(client);
        }
    }
    if(client->state != ICMP_STARTED) {
        timer_del(client->send_timer);
    }
}

static bool
bbl_icmp_client_add(bbl_icmp_client_config_s *config, 
                    bbl_network_interface_s *network_interface,
                    bbl_session_s *session)
{
    bbl_icmp_client_s *client = calloc(1, sizeof(bbl_icmp_client_s));
    uint16_t id = 1;

    if(session) {
        if(session->icmp_client) id = session->icmp_client->id+1;
        client->next = session->icmp_client;
        session->icmp_client = client;
        client->session = session;
    } else if (network_interface) {
        if(network_interface->icmp_client) id = network_interface->icmp_client->id+1;
        client->next = network_interface->icmp_client;
        network_interface->icmp_client = client;
        client->network_interface = network_interface;
        client->src = network_interface->ip.address;
    } else {
        return false;
    }

    client->id = id;
    client->config = config;
    client->results = config->results;
    client->dst = config->dst;
    if(config->src) client->src = config->src;

    switch(client->config->mode) {
        case ICMP_MODE_PING:
            client->result = calloc(client->results, sizeof(bbl_icmp_client_result_ping_s));
            client->data_len = client->config->size+2;
            client->data = calloc(1, client->data_len);
            *(uint16_t*)client->data = id;
            break;
        default:
            return false;
    }

    timer_add_periodic(&g_ctx->timer_root, &client->state_timer, 
                       "ICMP", 1, 0, client,
                       &bbl_icmp_client_state_job);

    /* Add to global ICMP client list */
    client->global_next = g_ctx->icmp_clients;
    g_ctx->icmp_clients = client;

    return true;
}

static bool
bbl_icmp_client_rx_echo_reply(bbl_session_s *session,
                              bbl_network_interface_s *network_interface,
                              bbl_ethernet_header_s *eth,
                              bbl_ipv4_s *ipv4,
                              bbl_icmp_s *icmp)
{
    bbl_icmp_client_s *client;
    bbl_icmp_client_config_s *config;
    bbl_icmp_client_result_ping_s *result;

    uint16_t slot = 0;
    uint16_t id = *(uint16_t*)icmp->data;
    uint16_t seq = *(uint16_t*)(icmp->data+2);
    uint16_t size = icmp->data_len+6;

    struct timespec time_diff;
    uint32_t ms = 0;
    uint32_t rtt = 0;

    if(session) {
        client = session->icmp_client;
    } else {
        client = network_interface->icmp_client;
    }

    while(client) {
        if(ipv4->src == client->dst && id == client->id) {
            break;
        }
        client = client->next;
    }
    if(!client) return false;

    config = client->config;
    slot = seq % config->results;
    result = &((bbl_icmp_client_result_ping_s*)client->result)[slot];

    if(result->seq == seq) {
        result->size = icmp->data_len >= 8 ? icmp->data_len - 8 : 0;
        result->ttl = ipv4->ttl;
        result->state = ICMP_RESULT_OKAY;
        result->timestamp_rx.tv_sec = eth->timestamp.tv_sec;
        result->timestamp_rx.tv_nsec = eth->timestamp.tv_nsec;
        
        timespec_sub(&time_diff, &result->timestamp_rx, &result->timestamp_tx);
        ms = time_diff.tv_nsec / 1000000; /* convert nanoseconds to milliseconds */
        if(time_diff.tv_nsec % 1000000) ms++; /* simple roundup function */
        rtt = (time_diff.tv_sec * 1000) + ms;
        result->rtt = rtt;
    }
    client->last_result = ICMP_RESULT_OKAY;
    client->received++;

    if(session) {
        LOG(ICMP, "ICMP (ID: %u) received echo-reply addr=%s id=%u seq=%u size=%u ttl=%u rtt=%ums\n",
            session->session_id, format_ipv4_address(&ipv4->src), id, seq, size, ipv4->ttl, result->rtt);
    } else {
        LOG(ICMP, "ICMP (%s) received echo-reply addr=%s id=%u seq=%u size=%u ttl=%u rtt=%ums\n",
            network_interface->name, format_ipv4_address(&ipv4->src), id, seq, size, ipv4->ttl, result->rtt);
    }

    return true;
}

static bool
bbl_icmp_client_rx_unreachable(bbl_session_s *session,
                               bbl_network_interface_s *network_interface,
                               bbl_ipv4_s *ipv4,
                               bbl_icmp_s *icmp)
{
    bbl_icmp_client_s *client;
    bbl_icmp_client_config_s *config;
    bbl_icmp_client_result_ping_s *result;

    ipv4addr_t dst;
    uint16_t slot, id, seq, mtu;
    uint8_t state = ICMP_RESULT_UNREACHABLE;

    if(icmp->data_len < 32) {
        LOG(ICMP, "ICMP failed to decode unreachable message from %s\n", format_ipv4_address(&ipv4->src));
        return false;
    }

    mtu = be16toh(*(uint16_t*)(icmp->data+2));
    dst = *(ipv4addr_t*)(icmp->data+20);
    id = *(uint16_t*)(icmp->data+28);
    seq = *(uint16_t*)(icmp->data+30);

    if(icmp->code == ICMP_CODE_FRAGMENTATION_NEEDED) {
        state = ICMP_RESULT_FRAGMENTATION_NEEDED;
        if(session) {
            LOG(ICMP, "ICMP (ID: %u) fragmentation needed addr=%s id=%u seq=%u mtu=%u\n",
                session->session_id, format_ipv4_address(&dst), id, seq, mtu);
        } else {
            LOG(ICMP, "ICMP (%s) fragmentation needed addr=%s id=%u seq=%u mtu=%u\n",
                network_interface->name, format_ipv4_address(&dst), id, seq, mtu);
        }
    }  else {
        if(session) {
            LOG(ICMP, "ICMP (ID: %u) unreachable (%u) addr=%s id=%u seq=%u\n",
                session->session_id, icmp->code, format_ipv4_address(&dst), id, seq);
        } else {
            LOG(ICMP, "ICMP (%s) unreachable (%u) addr=%s id=%u seq=%u\n",
                network_interface->name, icmp->code, format_ipv4_address(&dst), id, seq);
        }
    }

    if(session) {
        client = session->icmp_client;
    } else {
        client = network_interface->icmp_client;
    }

    while(client) {
        if(dst == client->dst && id == client->id) {
            break;
        }
        client = client->next;
    }
    if(!client) return false;

    config = client->config;
    slot = seq % config->results;
    result = &((bbl_icmp_client_result_ping_s*)client->result)[slot];

    if(result->seq == seq) {
        result->size = mtu;
        result->state = state;
    }

    client->last_result = state;
    client->errors++;
    return true;
}

static bool
bbl_icmp_client_rx_time_exceeded(bbl_session_s *session,
                                 bbl_network_interface_s *network_interface,
                                 bbl_ipv4_s *ipv4,
                                 bbl_icmp_s *icmp)
{
    bbl_icmp_client_s *client;
    bbl_icmp_client_config_s *config;
    bbl_icmp_client_result_ping_s *result;

    ipv4addr_t dst;
    uint16_t slot, id, seq;

    if(icmp->data_len < 32) {
        LOG(ICMP, "ICMP failed to decode TTL exceeded message from %s\n", format_ipv4_address(&ipv4->src));
        return false;
    }

    dst = *(ipv4addr_t*)(icmp->data+20);
    id = *(uint16_t*)(icmp->data+28);
    seq = *(uint16_t*)(icmp->data+30);

    if(session) {
        client = session->icmp_client;
        LOG(ICMP, "ICMP (ID: %u) TTL exceeded addr=%s id=%u seq=%u\n",
            session->session_id, format_ipv4_address(&dst), id, seq);
    } else {
        client = network_interface->icmp_client;
        LOG(ICMP, "ICMP (%s) TTL exceeded addr=%s id=%u seq=%u\n",
            network_interface->name, format_ipv4_address(&dst), id, seq);
    }

    while(client) {
        if(dst == client->dst && id == client->id) {
            break;
        }
        client = client->next;
    }
    if(!client) return false;

    config = client->config;
    slot = seq % config->results;
    result = &((bbl_icmp_client_result_ping_s*)client->result)[slot];

    if(result->seq == seq) {
        result->state = ICMP_RESULT_TTL_EXCEEDED;
    }

    client->last_result = ICMP_RESULT_TTL_EXCEEDED;
    client->errors++;
    return true;
}


bool
bbl_icmp_client_rx(bbl_session_s *session,
                   bbl_network_interface_s *network_interface,
                   bbl_ethernet_header_s *eth,
                   bbl_ipv4_s *ipv4,
                   bbl_icmp_s *icmp)
{
    if(icmp->data_len < 4) return false;

    switch(icmp->type) {
        case ICMP_TYPE_ECHO_REPLY:
            return bbl_icmp_client_rx_echo_reply(session, network_interface, eth, ipv4, icmp);
        case ICMP_TYPE_UNREACHABLE:
            return bbl_icmp_client_rx_unreachable(session, network_interface, ipv4, icmp);
        case ICMP_TYPE_TIME_EXCEEDED:
            return bbl_icmp_client_rx_time_exceeded(session, network_interface, ipv4, icmp);
        default:
            return false;
    }
}

/**
 * Init ICMP clients on session. 
 */
bool
bbl_icmp_client_session_init(bbl_session_s *session)
{
    bbl_icmp_client_config_s *config;
    uint16_t icmp_client_group_id = session->access_config->icmp_client_group_id;

    /** Add clients of corresponding icmp-client-group-id */
    if(icmp_client_group_id) {
        config = g_ctx->config.icmp_client_config;
        while(config) {
            if(config->icmp_client_group_id == icmp_client_group_id) {
                if(!bbl_icmp_client_add(config, NULL, session)) {
                    return false;
                }
            }
            config = config->next;
        }
    }
    return true;
}

/**
 * Init ICMP clients on network interface. 
 */
bool
bbl_icmp_client_network_interface_init(bbl_network_interface_s *network_interface)
{
    bbl_icmp_client_config_s *config = g_ctx->config.icmp_client_config;

    while(config) {
        if(config->network_interface && 
           strcmp(config->network_interface, network_interface->name) == 0) {
            if(!bbl_icmp_client_add(config, network_interface, NULL)) {
                return false;
            }
        }
        config = config->next;
    }
    return true;
}

static json_t *
bbl_icmp_client_ping_result_json(bbl_icmp_client_result_ping_s *result)
{
    json_t *root = NULL;

    switch(result->state) {
        case ICMP_RESULT_OKAY:
            root = json_pack("{sI sI sI sI ss*}",
                "seq", result->seq,
                "size", result->size,
                "ttl", result->ttl,
                "rtt-ms", result->rtt,
                "state", bbl_icmp_client_result_string(result->state));
            break;
        case ICMP_RESULT_FRAGMENTATION_NEEDED:
            root = json_pack("{sI sI ss*}",
                "seq", result->seq,
                "mtu", result->size,
                "state", bbl_icmp_client_result_string(result->state));
            break;
        default:
            root = json_pack("{sI ss*}",
                "seq", result->seq,
                "state", bbl_icmp_client_result_string(result->state));
            break;
    }
    return root;
}

static json_t *
bbl_icmp_client_json(bbl_icmp_client_s *client, bool detail)
{
    json_t *root = NULL;
    json_t *results = NULL;
    uint16_t slot;

    bbl_icmp_client_config_s *config;
    bbl_icmp_client_result_ping_s *result;

    if(!client) {
        return NULL;
    }

    config = client->config;

    if(detail) {
        results = json_array();
        for(slot = 0; slot < client->results; slot++) {
            switch(config->mode) {
                case ICMP_MODE_PING:
                    result = &((bbl_icmp_client_result_ping_s*)client->result)[slot];
                    if(result->state) {
                        json_array_append_new(results, bbl_icmp_client_ping_result_json(result));
                    }
                    break;
                default:
                    break;
            }
        }
    }

    if(client->session) {
        root = json_pack("{sI sI ss* ss* ss* sI sI sI ss* so*}",
            "session-id", client->session->session_id,
            "icmp-client-group-id", config->icmp_client_group_id,
            "source-address", format_ipv4_address(&client->src),
            "destination-address", format_ipv4_address(&client->dst),
            "state", bbl_icmp_client_state_string(client->state),
            "send", client->send,
            "received", client->received,
            "errors", client->errors,
            "result", bbl_icmp_client_result_string(client->last_result),
            "results", results);
    } else {
        root = json_pack("{ss* ss* ss* ss* sI sI sI ss* so*}",
            "network-interface", config->network_interface,
            "source-address", format_ipv4_address(&client->src),
            "destination-address", format_ipv4_address(&client->dst),
            "state", bbl_icmp_client_state_string(client->state),
            "send", client->send,
            "received", client->received,
            "errors", client->errors,
            "result", bbl_icmp_client_result_string(client->last_result),
            "results", results);
    }
    return root;
}

int
bbl_icmp_client_ctrl(int fd, uint32_t session_id, json_t *arguments)
{
    int result = 0;
    int detail = 0;

    json_t *root;
    json_t *json_clients = json_array();;

    bbl_session_s *session;
    bbl_icmp_client_s *client;

    /* Unpack further arguments */
    json_unpack(arguments, "{s:b}", "detail", &detail);


    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            client = session->icmp_client;
            while(client) {
                json_array_append_new(json_clients, bbl_icmp_client_json(client, detail));
                client = client->next;
            }
        }
    } else {
        client = g_ctx->icmp_clients;
        while(client) {
            json_array_append_new(json_clients, bbl_icmp_client_json(client, detail));
            client = client->global_next;
        }
    }

    root = json_pack("{ss si so*}",
                     "status", "ok",
                     "code", 200,
                     "icmp-clients", json_clients);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(json_clients);
    }
    return result;
}

static int
bbl_icmp_client_ctrl_start_stop(int fd, uint32_t session_id, bool start)
{
    bbl_session_s *session;
    bbl_icmp_client_s *client;

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            client = session->icmp_client;
            while(client) {
                if(start) {
                    bbl_icmp_client_start(client);
                } else {
                    bbl_icmp_client_stop(client);
                }
                client = client->next;
            }
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        client = g_ctx->icmp_clients;
        while(client) {
            if(start) {
                bbl_icmp_client_start(client);
            } else {
                bbl_icmp_client_stop(client);
            }
            client = client->global_next;
        }
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_icmp_client_ctrl_start(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    return bbl_icmp_client_ctrl_start_stop(fd, session_id, true);
}

int
bbl_icmp_client_ctrl_stop(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    return bbl_icmp_client_ctrl_start_stop(fd, session_id, false);
}