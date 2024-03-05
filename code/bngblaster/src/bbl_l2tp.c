/*
 * BNG Blaster (BBL) - L2TPv2 Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_l2tp_avp.h"
#include "bbl_stream.h"
#include "bbl_session.h"
#include <openssl/md5.h>
#include <openssl/rand.h>

void
bbl_l2tp_send(bbl_l2tp_tunnel_s *l2tp_tunnel, bbl_l2tp_session_s *l2tp_session, l2tp_message_t l2tp_type);

const char*
l2tp_message_string(l2tp_message_t type)
{
    switch(type) {
        case L2TP_MESSAGE_DATA: return "DATA";
        case L2TP_MESSAGE_SCCRQ: return "SCCRQ";
        case L2TP_MESSAGE_SCCRP: return "SCCRP";
        case L2TP_MESSAGE_SCCCN: return "SCCCN";
        case L2TP_MESSAGE_STOPCCN: return "StopCCN";
        case L2TP_MESSAGE_HELLO: return "HELLO";
        case L2TP_MESSAGE_OCRQ: return "OCRQ";
        case L2TP_MESSAGE_OCRP: return "OCRP";
        case L2TP_MESSAGE_OCCN: return "OCCN";
        case L2TP_MESSAGE_ICRQ: return "ICRQ";
        case L2TP_MESSAGE_ICRP: return "ICRP";
        case L2TP_MESSAGE_ICCN: return "ICCN";
        case L2TP_MESSAGE_CDN: return "CDN";
        case L2TP_MESSAGE_WEN: return "WEN";
        case L2TP_MESSAGE_CSUN: return "CSUN";
        case L2TP_MESSAGE_CSURQ: return "CSURQ";
        case L2TP_MESSAGE_ZLB: return "ZLB";
        default: return "UNKNOWN";
    }
}

const char*
l2tp_tunnel_state_string(l2tp_tunnel_state_t state)
{
    switch(state) {
        case BBL_L2TP_TUNNEL_IDLE: return "Idle";
        case BBL_L2TP_TUNNEL_WAIT_CTR_CONN: return "Wait-Control-Connection";
        case BBL_L2TP_TUNNEL_ESTABLISHED: return "Established";
        case BBL_L2TP_TUNNEL_SEND_STOPCCN: return "Send-StopCCN";
        case BBL_L2TP_TUNNEL_RCVD_STOPCCN: return "Received-StopCCN";
        case BBL_L2TP_TUNNEL_TERMINATED: return "Terminated";
        default: return "UNKNOWN";
    }
}

const char*
l2tp_session_state_string(l2tp_session_state_t state)
{
    switch(state) {
        case BBL_L2TP_SESSION_IDLE: return "Idle";
        case BBL_L2TP_SESSION_WAIT_CONN: return "Wait-Control-Connection";
        case BBL_L2TP_SESSION_ESTABLISHED: return "Established";
        case BBL_L2TP_SESSION_TERMINATED: return "Terminated";
        default: return "UNKNOWN";
    }
}

/**
 * bbl_l2tp_force_stop
 */
static void
bbl_l2tp_force_stop(bbl_l2tp_tunnel_s *l2tp_tunnel)
{
    bbl_l2tp_queue_s *q = NULL;
    bbl_l2tp_queue_s *q_del = NULL;

    uint16_t ns = l2tp_tunnel->ns;

    /* Remove all packets from TX queue never 
     * send out and reset Ns. number. */
    q = CIRCLEQ_FIRST(&l2tp_tunnel->txq_qhead);
    while (q != (const void *)(&l2tp_tunnel->txq_qhead)) {
        if(!q->retries) {
            /* Packet was never send out! */
            if(q->ns < ns) {
                ns = q->ns;
            }
            q_del = q;
            q = CIRCLEQ_NEXT(q, txq_qnode);
            CIRCLEQ_REMOVE(&l2tp_tunnel->txq_qhead, q_del, txq_qnode);
            if(CIRCLEQ_NEXT(q_del, tx_qnode)) {
                CIRCLEQ_REMOVE(&l2tp_tunnel->interface->l2tp_tx_qhead, q_del, tx_qnode);
            }
            free(q_del);
        } else {
            q = CIRCLEQ_NEXT(q, txq_qnode);
        }
    }
    /* Reset Ns. number. */
    l2tp_tunnel->ns = ns;
    /* Increase window size to ensure that StopCCN is send out. */
    l2tp_tunnel->cwnd++;
    bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
}

/**
 * bbl_l2tp_session_delete
 *
 * This function will free all dynamic memory for the given
 * l2tp session instance.
 *
 * @param l2tp_session L2TP session structure to be deleted.
 */
void
bbl_l2tp_session_delete(bbl_l2tp_session_s *l2tp_session)
{
    if(l2tp_session) {
        if(l2tp_session->key.session_id) {
            /* Here we skip the session with ID zero which is the tunnel session. */
            LOG(DEBUG, "L2TP Debug (%s) Tunnel %u Session %u deleted\n",
                       l2tp_session->tunnel->server->host_name, l2tp_session->tunnel->tunnel_id, l2tp_session->key.session_id);

            if(g_ctx->l2tp_sessions) g_ctx->l2tp_sessions--;
        }
        /* Remove session from tunnel object */
        if(CIRCLEQ_NEXT(l2tp_session, session_qnode) != NULL) {
            CIRCLEQ_REMOVE(&l2tp_session->tunnel->session_qhead, l2tp_session, session_qnode);
            CIRCLEQ_NEXT(l2tp_session, session_qnode) = NULL;
        }
        /* Remove session from dict */
        dict_remove(g_ctx->l2tp_session_dict, &l2tp_session->key);

        /* Remove session from PPPoE session */
        if(l2tp_session->pppoe_session) {
            l2tp_session->pppoe_session->l2tp_session = NULL;
        }

        /* Free tunnel memory */
        if(l2tp_session->proxy_auth_name) free(l2tp_session->proxy_auth_name);
        if(l2tp_session->proxy_auth_challenge) free(l2tp_session->proxy_auth_challenge);
        if(l2tp_session->proxy_auth_response) free(l2tp_session->proxy_auth_response);
        if(l2tp_session->peer_called_number) free(l2tp_session->peer_called_number);
        if(l2tp_session->peer_calling_number) free(l2tp_session->peer_calling_number);
        if(l2tp_session->peer_sub_address) free(l2tp_session->peer_sub_address);
        free(l2tp_session);
    }
}

/**
 * bbl_l2tp_tunnel_delete
 *
 * This function will free all dynamic memory for the given
 * l2tp tunnel instance including corresponding send queues.
 *
 * @param l2tp_tunnel L2TP tunnel structure to be deleted.
 */
static void
bbl_l2tp_tunnel_delete(bbl_l2tp_tunnel_s *l2tp_tunnel)
{
    bbl_l2tp_queue_s *q;
    if(l2tp_tunnel) {
        if(l2tp_tunnel->tunnel_id) {
            LOG(DEBUG, "L2TP Debug (%s) Tunnel %u deleted\n",
                    l2tp_tunnel->server->host_name, l2tp_tunnel->tunnel_id);
        }
        if(g_ctx->l2tp_tunnels) g_ctx->l2tp_tunnels--;

        /* Delete timer */
        timer_del(l2tp_tunnel->timer_tx);

        /* Delete all remaining sessions */
        while (!CIRCLEQ_EMPTY(&l2tp_tunnel->session_qhead)) {
            bbl_l2tp_session_delete(CIRCLEQ_FIRST(&l2tp_tunnel->session_qhead));
        }
        /* Remove tunnel from server object */
        if(CIRCLEQ_NEXT(l2tp_tunnel, tunnel_qnode) != NULL) {
            CIRCLEQ_REMOVE(&l2tp_tunnel->server->tunnel_qhead, l2tp_tunnel, tunnel_qnode);
            CIRCLEQ_NEXT(l2tp_tunnel, tunnel_qnode) = NULL;
        }
        /* Cleanup send queues */
        while (!CIRCLEQ_EMPTY(&l2tp_tunnel->txq_qhead)) {
            q = CIRCLEQ_FIRST(&l2tp_tunnel->txq_qhead);
            CIRCLEQ_REMOVE(&l2tp_tunnel->txq_qhead, q, txq_qnode);
            CIRCLEQ_NEXT(q, txq_qnode) = NULL;
            if(CIRCLEQ_NEXT(q, tx_qnode) != NULL) {
                CIRCLEQ_REMOVE(&l2tp_tunnel->interface->l2tp_tx_qhead, q, tx_qnode);
                CIRCLEQ_NEXT(q, tx_qnode) = NULL;
            }
            free(q);
        }
        if(l2tp_tunnel->zlb_qnode) {
            free(l2tp_tunnel->zlb_qnode);
        }
        /* Free tunnel memory */
        if(l2tp_tunnel->challenge) free(l2tp_tunnel->challenge);
        if(l2tp_tunnel->peer_challenge) free(l2tp_tunnel->peer_challenge);
        if(l2tp_tunnel->challenge_response) free(l2tp_tunnel->challenge_response);
        if(l2tp_tunnel->peer_challenge_response) free(l2tp_tunnel->peer_challenge_response);
        if(l2tp_tunnel->peer_name) free(l2tp_tunnel->peer_name);
        if(l2tp_tunnel->peer_vendor) free(l2tp_tunnel->peer_vendor);
        free(l2tp_tunnel);
    }
}

/**
 * bbl_l2tp_tunnel_update_state
 *
 * @param l2tp_tunnel L2TP tunnel structure.
 * @param state New L2TP tunnel state.
 */
void
bbl_l2tp_tunnel_update_state(bbl_l2tp_tunnel_s *l2tp_tunnel, l2tp_tunnel_state_t state) {
    if(l2tp_tunnel->state != state) {
        /* State has changed */
        LOG(DEBUG, "L2TP Debug (%s) Tunnel %u state changed from %s to %s\n",
                    l2tp_tunnel->server->host_name, l2tp_tunnel->tunnel_id,
                    l2tp_tunnel_state_string(l2tp_tunnel->state),
                    l2tp_tunnel_state_string(state));

        if(state == BBL_L2TP_TUNNEL_ESTABLISHED) {
            /* New state established */
            g_ctx->l2tp_tunnels_established++;
            if(g_ctx->l2tp_tunnels_established > g_ctx->l2tp_tunnels_established_max) {
                g_ctx->l2tp_tunnels_established_max = g_ctx->l2tp_tunnels_established;
            }
            LOG(L2TP, "L2TP Info (%s) Tunnel (%u) with %s (%s) established\n",
                      l2tp_tunnel->server->host_name, l2tp_tunnel->tunnel_id,
                      l2tp_tunnel->peer_name,
                      format_ipv4_address(&l2tp_tunnel->peer_ip));
        } else if(l2tp_tunnel->state == BBL_L2TP_TUNNEL_ESTABLISHED) {
            if(g_ctx->l2tp_tunnels_established) {
                g_ctx->l2tp_tunnels_established--;
            }
        }
        /* Set new state and reset state seconds */
        l2tp_tunnel->state = state;
        l2tp_tunnel->state_seconds = 0;
    }
}

/**
 * bbl_l2tp_tunnel_tx_job
 */
void
bbl_l2tp_tunnel_tx_job(timer_s *timer)
{
    bbl_l2tp_tunnel_s *l2tp_tunnel = timer->data;
    bbl_network_interface_s *interface = l2tp_tunnel->interface;
    bbl_l2tp_queue_s *q = NULL;
    bbl_l2tp_queue_s *q_del = NULL;

    struct timespec now;
    struct timespec time_diff;
    int backoff;

    uint16_t max_ns = l2tp_tunnel->peer_nr + l2tp_tunnel->cwnd;

    l2tp_tunnel->timer_tx_active = false;
    if(l2tp_tunnel->state == BBL_L2TP_TUNNEL_SEND_STOPCCN) {
        if(CIRCLEQ_EMPTY(&l2tp_tunnel->txq_qhead)) {
            bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_TERMINATED);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &now);

    q = CIRCLEQ_FIRST(&l2tp_tunnel->txq_qhead);
    while (q != (const void *)(&l2tp_tunnel->txq_qhead)) {
        if(L2TP_SEQ_LT(q->ns, l2tp_tunnel->peer_nr)) {
            /* Delete acknowledged messages from queue. */
            q_del = q;
            q = CIRCLEQ_NEXT(q, txq_qnode);
            CIRCLEQ_REMOVE(&l2tp_tunnel->txq_qhead, q_del, txq_qnode);
            if(CIRCLEQ_NEXT(q_del, tx_qnode)) {
                CIRCLEQ_REMOVE(&interface->l2tp_tx_qhead, q_del, tx_qnode);
            }
            free(q_del);
            continue;
        }
        if(L2TP_SEQ_LT(q->ns, max_ns)) {
            if(q->last_tx_time.tv_sec) {
                timespec_sub(&time_diff, &now, &q->last_tx_time);
                backoff = 1 << (q->retries - 1);
                if(time_diff.tv_sec < backoff) {
                    q = CIRCLEQ_NEXT(q, txq_qnode);
                    continue;
                }
            }
            CIRCLEQ_INSERT_TAIL(&interface->l2tp_tx_qhead, q, tx_qnode);
            l2tp_tunnel->stats.control_tx++;
            interface->stats.l2tp_control_tx++;
            l2tp_tunnel->zlb = false;
            q->last_tx_time.tv_sec = now.tv_sec;
            q->last_tx_time.tv_nsec = now.tv_nsec;
            /* Update Nr. ... */
            *(uint16_t*)(q->packet + q->nr_offset) = htobe16(l2tp_tunnel->nr);
            if(q->retries) {
                l2tp_tunnel->stats.control_retry++;
                interface->stats.l2tp_control_retry++;
                if(q->retries > l2tp_tunnel->server->max_retry) {
                    l2tp_tunnel->result_code = 2;
                    l2tp_tunnel->error_code = 6;
                    l2tp_tunnel->error_message = "max retry";
                    bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_SEND_STOPCCN);
                    bbl_l2tp_force_stop(l2tp_tunnel);
                }
                /* When congestion occurs (indicated by the triggering of a
                 * retransmission) one half of the congestion window (CWND)
                 * is saved in SSTHRESH, and CWND is set to one. The sender
                 * then reenters the slow start phase. */
                l2tp_tunnel->ssthresh = l2tp_tunnel->cwnd/2;
                if(!l2tp_tunnel->ssthresh) l2tp_tunnel->ssthresh = 1;
                l2tp_tunnel->cwnd = 1;
                l2tp_tunnel->cwcount = 0;
            }
            q->retries++;
            q = CIRCLEQ_NEXT(q, txq_qnode);
        } else {
            break;
        }
    }
    if(l2tp_tunnel->zlb) {
        l2tp_tunnel->zlb = false;
        /* Update Ns. ... */
        *(uint16_t*)(q->packet + q->nr_offset) = htobe16(l2tp_tunnel->ns);
        /* Update Nr. ... */
        *(uint16_t*)(q->packet + q->nr_offset) = htobe16(l2tp_tunnel->nr);
        CIRCLEQ_INSERT_TAIL(&interface->l2tp_tx_qhead, l2tp_tunnel->zlb_qnode, tx_qnode);
        l2tp_tunnel->stats.control_tx++;
        interface->stats.l2tp_control_tx++;
        *(uint16_t*)(l2tp_tunnel->zlb_qnode->packet + l2tp_tunnel->zlb_qnode->ns_offset) = htobe16(l2tp_tunnel->ns);
        *(uint16_t*)(l2tp_tunnel->zlb_qnode->packet + l2tp_tunnel->zlb_qnode->nr_offset) = htobe16(l2tp_tunnel->nr);
    }
}

/**
 * bbl_l2tp_tunnel_control_job
 */
void
bbl_l2tp_tunnel_control_job(timer_s *timer)
{
    bbl_l2tp_tunnel_s *l2tp_tunnel = timer->data;
    l2tp_tunnel->state_seconds++;
    switch(l2tp_tunnel->state) {
        case BBL_L2TP_TUNNEL_WAIT_CTR_CONN:
            if(l2tp_tunnel->state_seconds > 30) {
                l2tp_tunnel->result_code = 2;
                l2tp_tunnel->error_code = 6;
                l2tp_tunnel->error_message = "timeout";
                bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_SEND_STOPCCN);
                bbl_l2tp_force_stop(l2tp_tunnel);
            }
            break;
        case BBL_L2TP_TUNNEL_ESTABLISHED:
            if(l2tp_tunnel->server->hello_interval) {
                if(l2tp_tunnel->state_seconds % l2tp_tunnel->server->hello_interval == 0) {
                    bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_HELLO);
                }
            }
            break;
        case BBL_L2TP_TUNNEL_RCVD_STOPCCN:
            if(l2tp_tunnel->state_seconds > 5) {
                bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_TERMINATED);
            }
            break;
        case BBL_L2TP_TUNNEL_SEND_STOPCCN:
            if(l2tp_tunnel->state_seconds > 30) {
                bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_TERMINATED);
            }
            break;
        case BBL_L2TP_TUNNEL_TERMINATED:
            timer->periodic = false;
            bbl_l2tp_tunnel_delete(l2tp_tunnel);
            return;
        default:
            break;
    }
    if(!l2tp_tunnel->timer_tx_active) {
        timer_add(&g_ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 0, L2TP_TX_WAIT_MS * MSEC, l2tp_tunnel, &bbl_l2tp_tunnel_tx_job);
        l2tp_tunnel->timer_tx_active = true;
    }
}

/**
 * bbl_l2tp_send
 *
 * This function send control packets for a given L2TP tunnel.
 *
 * @param l2tp_tunnel L2TP tunnel structure.
 * @param l2tp_session Optional L2TP session structure.
 *        This parameter is only required of L2TP session packets.
 * @param l2tp_type L2TP message type (SCCRP, ICRP, ...).
 */
void
bbl_l2tp_send(bbl_l2tp_tunnel_s *l2tp_tunnel, bbl_l2tp_session_s *l2tp_session, l2tp_message_t l2tp_type) {

    bbl_network_interface_s *interface = l2tp_tunnel->interface;
    bbl_l2tp_queue_s *q = calloc(1, sizeof(bbl_l2tp_queue_s));

    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_udp_s udp = {0};
    bbl_l2tp_s l2tp = {0};

    uint8_t sp[L2TP_MAX_AVP_SIZE]; /* scratchpad memory to craft the AVP attributes */
    uint16_t sp_len = 0;
    uint16_t len = 0;

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &ipv4;
    ipv4.dst = l2tp_tunnel->peer_ip;
    ipv4.src = l2tp_tunnel->server->ip;
    ipv4.ttl = 64;
    ipv4.tos = l2tp_tunnel->server->control_tos;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = L2TP_UDP_PORT;
    udp.dst = L2TP_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_L2TP;
    udp.next = &l2tp;
    l2tp.type = l2tp_type;
    l2tp.tunnel_id = l2tp_tunnel->peer_tunnel_id;
    if(l2tp_session) {
        l2tp.session_id = l2tp_session->peer_session_id;
    }
    /* The Nr. will be set on the fly while sending
     * using the latest received Ns. from peer.
     * Therfore we need to remember offset to Nr. */
    l2tp.nr = 0;
    if(eth.vlan_outer) {
        q->ns_offset = 54;
        q->nr_offset = 56;

    } else {
        q->ns_offset = 50;
        q->nr_offset = 52;
    }
    if(l2tp_type != L2TP_MESSAGE_ZLB) {
        l2tp.ns = l2tp_tunnel->ns++;
        bbl_l2tp_avp_encode_attributes(l2tp_tunnel, l2tp_session, l2tp_type, sp, &sp_len);
        l2tp.payload = sp;
        l2tp.payload_len = sp_len;
    }
    q->ns = l2tp.ns;
    q->tunnel = l2tp_tunnel;
    if(encode_ethernet(q->packet, &len, &eth) == PROTOCOL_SUCCESS) {
        q->packet_len = len;
        if(l2tp_type == L2TP_MESSAGE_ZLB) {
            if(l2tp_tunnel->zlb_qnode) {
                free(q);
            } else {
                l2tp_tunnel->zlb_qnode = q;
            }
        } else {
            CIRCLEQ_INSERT_TAIL(&l2tp_tunnel->txq_qhead, q, txq_qnode);
            if(!l2tp_tunnel->timer_tx_active) {
                timer_add(&g_ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 0, L2TP_TX_WAIT_MS * MSEC, l2tp_tunnel, &bbl_l2tp_tunnel_tx_job);
                l2tp_tunnel->timer_tx_active = true;
            }
        }
    } else {
        /* Encode error.... */
        LOG_NOARG(ERROR, "L2TP Encode Error!\n");
        free(q);
    }
}

/**
 * bbl_l2tp_send_data
 *
 * This function send data packets for a given L2TP session.
 *
 * @param l2tp_tunnel L2TP tunnel structure.
 * @param l2tp_session L2TP session structure.
 * @param protocol Payload type (IPCP, IPv4, ...).
 * @param next Payload structure.
 */
static void
bbl_l2tp_send_data(bbl_l2tp_session_s *l2tp_session, uint16_t protocol, void *next) {

    bbl_l2tp_tunnel_s *l2tp_tunnel = l2tp_session->tunnel;
    bbl_l2tp_server_s *l2tp_server = l2tp_tunnel->server;
    bbl_network_interface_s *interface = l2tp_tunnel->interface;
    bbl_l2tp_queue_s *q = calloc(1, sizeof(bbl_l2tp_queue_s));
    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_udp_s udp = {0};
    bbl_l2tp_s l2tp = {0};
    uint16_t len = 0;
    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &ipv4;
    ipv4.dst = l2tp_tunnel->peer_ip;
    ipv4.src = l2tp_tunnel->server->ip;
    ipv4.ttl = 64;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = L2TP_UDP_PORT;
    udp.dst = L2TP_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_L2TP;
    udp.next = &l2tp;
    l2tp.type = L2TP_MESSAGE_DATA;
    l2tp.tunnel_id = l2tp_tunnel->peer_tunnel_id;
    l2tp.session_id = l2tp_session->peer_session_id;
    l2tp.protocol = protocol;
    l2tp.with_length = l2tp_server->data_length;
    l2tp.with_offset = l2tp_server->data_offset;
    if(protocol != PROTOCOL_IPV4 && protocol != PROTOCOL_IPV6) {
        if(l2tp_server->data_control_priority) {
            l2tp.with_priority = true;
        }
        ipv4.tos = l2tp_tunnel->server->data_control_tos;
    }
    l2tp.next = next;
    q->data = true;
    if(encode_ethernet(q->packet, &len, &eth) == PROTOCOL_SUCCESS) {
        q->packet_len = len;
        CIRCLEQ_INSERT_TAIL(&interface->l2tp_tx_qhead, q, tx_qnode);
        l2tp_tunnel->stats.data_tx++;
        l2tp_session->stats.data_tx++;
        interface->stats.l2tp_data_tx++;
        if(protocol == PROTOCOL_IPV4) {
            l2tp_session->stats.data_ipv4_tx++;
        }
    } else {
        LOG_NOARG(ERROR, "L2TP Data Encode Error!\n");
        free(q);
    }
}

static void
bbl_l2tp_sccrq_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth, bbl_l2tp_s *l2tp) {
    MD5_CTX md5_ctx;

    bbl_ipv4_s *ipv4 = (bbl_ipv4_s*)eth->next;

    bbl_l2tp_server_s *l2tp_server = g_ctx->config.l2tp_server;
    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_tunnel_s *l2tp_tunnel2;
    bbl_l2tp_session_s *l2tp_session;

    dict_insert_result result;
    void **search = NULL;

    uint8_t l2tp_type;

    /* Init tunnel ... */
    l2tp_tunnel = calloc(1, sizeof(bbl_l2tp_tunnel_s));
    g_ctx->l2tp_tunnels++;
    CIRCLEQ_INIT(&l2tp_tunnel->txq_qhead);
    CIRCLEQ_INIT(&l2tp_tunnel->session_qhead);
    l2tp_tunnel->interface = interface;
    l2tp_tunnel->peer_receive_window = 4;
    l2tp_tunnel->ssthresh = 4;
    l2tp_tunnel->cwnd = 1;
    l2tp_tunnel->peer_ip = ipv4->src;
    l2tp_tunnel->peer_ns = l2tp->ns;
    l2tp_tunnel->nr = (l2tp->ns + 1);
    l2tp_tunnel->state = BBL_L2TP_TUNNEL_WAIT_CTR_CONN;
    l2tp_tunnel->stats.control_rx++;
    interface->stats.l2tp_control_rx++;

    /* Decode received attributes and store in tunnel */
    if(!bbl_l2tp_avp_decode_tunnel(l2tp, l2tp_tunnel)) {
        bbl_l2tp_tunnel_delete(l2tp_tunnel);
        return;
    }
    if(!l2tp_tunnel->peer_tunnel_id ||
        !l2tp_tunnel->peer_name) {
        LOG(ERROR, "L2TP Error (%s) Invalid SCCRQ received from %s\n",
                    l2tp_server->host_name,
                    format_ipv4_address(&ipv4->src));
        bbl_l2tp_tunnel_delete(l2tp_tunnel);
        return;
    }

    /* Check for SCCRQ retry ... */
    CIRCLEQ_FOREACH(l2tp_tunnel2, &l2tp_server->tunnel_qhead, tunnel_qnode) {
        if(l2tp_tunnel2->peer_ip == l2tp_tunnel->peer_ip &&
            l2tp_tunnel2->peer_tunnel_id == l2tp_tunnel->peer_tunnel_id) {
                if(l2tp_tunnel2->state == BBL_L2TP_TUNNEL_RCVD_STOPCCN) {
                    bbl_l2tp_tunnel_update_state(l2tp_tunnel2, BBL_L2TP_TUNNEL_TERMINATED);
                }
                /* Seems to be an SCCRQ retry ... */
                bbl_l2tp_tunnel_delete(l2tp_tunnel);
                return;
        }
    }

    while(l2tp_server) {
        if(l2tp_server->ip == ipv4->dst && (l2tp_server->client_auth_id == NULL ||
            (strcmp(l2tp_server->client_auth_id, l2tp_tunnel->peer_name) == 0))) {

            l2tp_tunnel->server = l2tp_server;
            LOG(PACKET, "L2TP (%s) SCCRQ received from %s (%s)\n",
                l2tp_server->host_name, l2tp_tunnel->peer_name,
                format_ipv4_address(&ipv4->src));

            /* Add dummy tunnel session, this session is only used
             * to search for tunnel using the same dictionary. */
            l2tp_session = calloc(1, sizeof(bbl_l2tp_session_s));
            l2tp_session->state = BBL_L2TP_SESSION_MAX;
            l2tp_session->tunnel = l2tp_tunnel;
            l2tp_session->key.session_id = 0;

            /* Assign tunnel id ... */
            while(true) {
                l2tp_session->key.tunnel_id = g_ctx->next_tunnel_id++;
                if(l2tp_session->key.tunnel_id == 0) continue; /* skip tunnel 0 */
                search = dict_search(g_ctx->l2tp_session_dict, &l2tp_session->key);
                if(search) {
                    /* Used, try next ... */
                    continue;
                } else {
                    break;
                }
            }
            l2tp_tunnel->tunnel_id = l2tp_session->key.tunnel_id;
            result = dict_insert(g_ctx->l2tp_session_dict, &l2tp_session->key);
            if(!result.inserted) {
                LOG(ERROR, "L2TP Error (%s) Failed to add tunnel session\n",
                            l2tp_tunnel->server->host_name);
                free(l2tp_session);
                bbl_l2tp_tunnel_delete(l2tp_tunnel);
                return;
            }
            *result.datum_ptr = l2tp_session;
            CIRCLEQ_INSERT_TAIL(&l2tp_tunnel->session_qhead, l2tp_session, session_qnode);
            if(g_ctx->l2tp_tunnels > g_ctx->l2tp_tunnels_max) g_ctx->l2tp_tunnels_max = g_ctx->l2tp_tunnels;
            /* L2TP Challenge/Response */
            if(l2tp_server->secret) {
                l2tp_tunnel->challenge = malloc(L2TP_MD5_DIGEST_LEN);
                l2tp_tunnel->challenge_len = L2TP_MD5_DIGEST_LEN;
                RAND_bytes(l2tp_tunnel->challenge, l2tp_tunnel->challenge_len);
                if(l2tp_tunnel->peer_challenge_len) {
                    l2tp_tunnel->challenge_response = malloc(L2TP_MD5_DIGEST_LEN);
                    l2tp_tunnel->challenge_response_len = L2TP_MD5_DIGEST_LEN;
                    l2tp_type = L2TP_MESSAGE_SCCRP;
                    MD5_Init(&md5_ctx);
                    MD5_Update(&md5_ctx, &l2tp_type, 1);
                    MD5_Update(&md5_ctx, (unsigned char *) l2tp_server->secret, strlen(l2tp_server->secret));
                    MD5_Update(&md5_ctx, l2tp_tunnel->peer_challenge, l2tp_tunnel->peer_challenge_len);
                    MD5_Final(l2tp_tunnel->challenge_response, &md5_ctx);
                } else {
                    /* We are not able to setup a session if no challenge
                     * is received but there is a secret configured! */
                    LOG(ERROR, "L2TP Error (%s) Missing challenge in SCCRQ from %s\n",
                               l2tp_tunnel->server->host_name,
                               format_ipv4_address(&l2tp_tunnel->peer_ip));
                    l2tp_tunnel->result_code = 2;
                    l2tp_tunnel->error_code = 6;
                    l2tp_tunnel->error_message = "missing challenge";
                    l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                }
            } else {
                if(l2tp_tunnel->peer_challenge_len) {
                    /* We are not able to setup a session if challenge
                     * is received but not secret configured! */
                    LOG(ERROR, "L2TP Error (%s) No secret found but challenge received in SCCRQ from %s\n",
                               l2tp_tunnel->server->host_name,
                               format_ipv4_address(&l2tp_tunnel->peer_ip));
                    l2tp_tunnel->result_code = 2;
                    l2tp_tunnel->error_code = 6;
                    l2tp_tunnel->error_message = "no challenge expected";
                    l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                }
            }
            /* Add tunnel to server */
            CIRCLEQ_INSERT_TAIL(&l2tp_server->tunnel_qhead, l2tp_tunnel, tunnel_qnode);
            /* Start control job
             * WARNING: Do not change the interval! */
            timer_add_periodic(&g_ctx->timer_root, &l2tp_tunnel->timer_ctrl, "L2TP Control", 1, 0, l2tp_tunnel, &bbl_l2tp_tunnel_control_job);
            /* Prepare ZLB */
            bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_ZLB);
            /* Send response */
            if(l2tp_tunnel->state == BBL_L2TP_TUNNEL_SEND_STOPCCN) {
                bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
            } else {
                bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_SCCRP);
            }
            return;
        }
        l2tp_server = l2tp_server->next;
    }
    bbl_l2tp_tunnel_delete(l2tp_tunnel);
}

static void
bbl_l2tp_scccn_rx(bbl_network_interface_s *interface, 
                  bbl_l2tp_tunnel_s *l2tp_tunnel, 
                  bbl_ethernet_header_s *eth, bbl_l2tp_s *l2tp)
{
    uint8_t digest[L2TP_MD5_DIGEST_LEN];
    MD5_CTX md5_ctx;
    uint8_t l2tp_type = L2TP_MESSAGE_SCCCN;

    UNUSED(interface);
    UNUSED(eth);

    if(l2tp_tunnel->state == BBL_L2TP_TUNNEL_WAIT_CTR_CONN) {
        if(!bbl_l2tp_avp_decode_tunnel(l2tp, l2tp_tunnel)) {
            LOG(ERROR, "L2TP Error (%s) Invalid SCCCN received from %s\n",
                       l2tp_tunnel->server->host_name,
                       format_ipv4_address(&l2tp_tunnel->peer_ip));
            bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_SEND_STOPCCN);
            l2tp_tunnel->result_code = 2;
            l2tp_tunnel->error_code = 6;
            l2tp_tunnel->error_message = "decode error";
            bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
            return;
        }
        /* Check challenge response ... */
        if(l2tp_tunnel->server->secret) {
            if(l2tp_tunnel->peer_challenge_response_len) {
                MD5_Init(&md5_ctx);
                MD5_Update(&md5_ctx, &l2tp_type, 1);
                MD5_Update(&md5_ctx, (unsigned char *) l2tp_tunnel->server->secret, strlen(l2tp_tunnel->server->secret));
                MD5_Update(&md5_ctx, l2tp_tunnel->challenge, l2tp_tunnel->challenge_len);
                MD5_Final(digest, &md5_ctx);
                if(memcmp(digest, l2tp_tunnel->peer_challenge_response, L2TP_MD5_DIGEST_LEN) != 0) {
                    LOG(ERROR, "L2TP Error (%s) Wrong challenge response in SCCCN from %s\n",
                               l2tp_tunnel->server->host_name,
                               format_ipv4_address(&l2tp_tunnel->peer_ip));
                    bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_SEND_STOPCCN);
                    l2tp_tunnel->result_code = 2;
                    l2tp_tunnel->error_code = 6;
                    l2tp_tunnel->error_message = "challenge authentication failed";
                    bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
                    return;
                }
            } else {
                LOG(ERROR, "L2TP Error (%s) Missing challenge response in SCCCN from %s\n",
                           l2tp_tunnel->server->host_name,
                           format_ipv4_address(&l2tp_tunnel->peer_ip));
                bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_SEND_STOPCCN);
                l2tp_tunnel->result_code = 2;
                l2tp_tunnel->error_code = 6;
                l2tp_tunnel->error_message = "missing challenge response";
                bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
                return;
            }
        }
        bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_ESTABLISHED);
    }
}

static void
bbl_l2tp_stopccn_rx(bbl_network_interface_s *interface, 
                    bbl_l2tp_tunnel_s *l2tp_tunnel, 
                    bbl_ethernet_header_s *eth, bbl_l2tp_s *l2tp)
{
    UNUSED(interface);
    UNUSED(eth);
    UNUSED(l2tp);

    bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_RCVD_STOPCCN);
}

static void
bbl_l2tp_csun_rx(bbl_network_interface_s *interface, 
                 bbl_l2tp_tunnel_s *l2tp_tunnel, 
                 bbl_ethernet_header_s *eth, bbl_l2tp_s *l2tp)
{
    UNUSED(interface);
    UNUSED(eth);

    bbl_l2tp_avp_decode_csun(l2tp, l2tp_tunnel);
}

static void
bbl_l2tp_icrq_rx(bbl_network_interface_s *interface, 
                 bbl_l2tp_tunnel_s *l2tp_tunnel, 
                 bbl_ethernet_header_s *eth, bbl_l2tp_s *l2tp)
{
    dict_insert_result result;
    void **search;

    UNUSED(interface);
    UNUSED(eth);

    if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_ESTABLISHED) {
        return;
    }

    bbl_l2tp_session_s *l2tp_session = calloc(1, sizeof(bbl_l2tp_session_s));
    g_ctx->l2tp_sessions++;
    l2tp_session->tunnel = l2tp_tunnel;
    l2tp_session->state = BBL_L2TP_SESSION_WAIT_CONN;

    if(!bbl_l2tp_avp_decode_session(l2tp, l2tp_tunnel, l2tp_session)) {
        bbl_l2tp_session_delete(l2tp_session);
        return;
    }

    l2tp_session->key.tunnel_id = l2tp_tunnel->tunnel_id;

    /* Assign session id ... */
    while(true) {
        l2tp_session->key.session_id = l2tp_tunnel->next_session_id++;
        if(l2tp_session->key.session_id == 0) continue; /* skip tunnel 0 */
        search = dict_search(g_ctx->l2tp_session_dict, &l2tp_session->key);
        if(search) {
            /* Used, try next ... */
            continue;
        } else {
            break;
        }
    }
    result = dict_insert(g_ctx->l2tp_session_dict, &l2tp_session->key);
    if(!result.inserted) {
        LOG(ERROR, "L2TP Error (%s) Failed to add session\n",
                    l2tp_tunnel->server->host_name);
        free(l2tp_session);
        return;
    }
    *result.datum_ptr = l2tp_session;
    CIRCLEQ_INSERT_TAIL(&l2tp_tunnel->session_qhead, l2tp_session, session_qnode);
    if(g_ctx->l2tp_sessions > g_ctx->l2tp_sessions_max) {
        g_ctx->l2tp_sessions_max = g_ctx->l2tp_sessions;
    }
    bbl_l2tp_send(l2tp_tunnel, l2tp_session, L2TP_MESSAGE_ICRP);
}

static void
bbl_l2tp_iccn_rx(bbl_network_interface_s *interface, 
                 bbl_l2tp_session_s *l2tp_session,
                 bbl_ethernet_header_s *eth, bbl_l2tp_s *l2tp)
{
    bbl_l2tp_tunnel_s *l2tp_tunnel = l2tp_session->tunnel;

    UNUSED(interface);
    UNUSED(eth);
    UNUSED(l2tp);

    if(!l2tp_session) {
        return;
    }

    if(!bbl_l2tp_avp_decode_session(l2tp, l2tp_tunnel, l2tp_session)) {
        l2tp_session->result_code = 2;
        l2tp_session->error_code = 6;
        l2tp_session->error_message = "decode error";
        bbl_l2tp_send(l2tp_tunnel, l2tp_session, L2TP_MESSAGE_CDN);
        bbl_l2tp_session_delete(l2tp_session);
        return;
    }
    if(l2tp_session->state == BBL_L2TP_SESSION_WAIT_CONN) {
        l2tp_session->state = BBL_L2TP_SESSION_ESTABLISHED;
        LOG(L2TP, "L2TP Info (%s) Tunnel (%u) from %s (%s) session (%u) established\n",
                  l2tp_tunnel->server->host_name, l2tp_tunnel->tunnel_id,
                  l2tp_tunnel->peer_name,
                  format_ipv4_address(&l2tp_tunnel->peer_ip),
                  l2tp_session->key.session_id);
    }
}

static void
bbl_l2tp_cdn_rx(bbl_network_interface_s *interface, 
                bbl_l2tp_session_s *l2tp_session, 
                bbl_ethernet_header_s *eth, bbl_l2tp_s *l2tp)
{
    bbl_l2tp_tunnel_s *l2tp_tunnel = l2tp_session->tunnel;

    UNUSED(interface);
    UNUSED(eth);
    UNUSED(l2tp);

    if(!l2tp_session) {
        return;
    }

    bbl_l2tp_avp_decode_session(l2tp, l2tp_tunnel, l2tp_session);

    l2tp_session->state = BBL_L2TP_SESSION_TERMINATED;
    LOG(L2TP, "L2TP Info (%s) Tunnel (%u) from %s (%s) session (%u) terminated\n",
            l2tp_tunnel->server->host_name, l2tp_tunnel->tunnel_id,
            l2tp_tunnel->peer_name,
            format_ipv4_address(&l2tp_tunnel->peer_ip),
            l2tp_session->key.session_id);

    bbl_l2tp_session_delete(l2tp_session);
}

static void
bbl_l2tp_data_rx(bbl_network_interface_s *interface, 
                 bbl_l2tp_session_s *l2tp_session, 
                 bbl_ethernet_header_s *eth, bbl_l2tp_s *l2tp)
{
    bbl_lcp_s   *lcp_rx;
    bbl_pap_s   *pap_rx;
    bbl_pap_s    pap_tx;
    bbl_chap_s  *chap_rx;
    bbl_chap_s   chap_tx;
    bbl_ipcp_s  *ipcp_rx;
    bbl_ipcp_s   ipcp_tx;
    bbl_ip6cp_s *ip6cp_rx;
    bbl_ip6cp_s  ip6cp_tx;

    UNUSED(eth);
    UNUSED(interface);

    char reply_message[sizeof(L2TP_REPLY_MESSAGE)+16];

    if(l2tp_session->state != BBL_L2TP_SESSION_ESTABLISHED) {
        return;
    }

    l2tp_session->stats.data_rx++;
    switch(l2tp->protocol) {
        case PROTOCOL_LCP:
            lcp_rx = (bbl_lcp_s*)l2tp->next;
            lcp_rx->padding = l2tp_session->tunnel->server->lcp_padding;
            if(lcp_rx->code == PPP_CODE_ECHO_REQUEST) {
                lcp_rx->code = PPP_CODE_ECHO_REPLY;
                bbl_l2tp_send_data(l2tp_session, PROTOCOL_LCP, lcp_rx);
            } else if(lcp_rx->code == PPP_CODE_TERM_REQUEST) {
                l2tp_session->disconnect_code = 3;
                l2tp_session->disconnect_protocol = 0;
                l2tp_session->disconnect_direction = 1;
                bbl_l2tp_send(l2tp_session->tunnel, l2tp_session, L2TP_MESSAGE_CDN);
                bbl_l2tp_session_delete(l2tp_session);
            } 
            break;
        case PROTOCOL_PAP:
            memset(&pap_tx, 0x0, sizeof(bbl_pap_s));
            pap_rx = (bbl_pap_s*)l2tp->next;
            pap_tx.code = PAP_CODE_ACK;
            pap_tx.identifier = pap_rx->identifier;
            pap_tx.reply_message = reply_message;
            pap_tx.reply_message_len = snprintf(reply_message, sizeof(reply_message),
                L2TP_REPLY_MESSAGE, l2tp_session->key.tunnel_id, l2tp_session->key.session_id);
            bbl_l2tp_send_data(l2tp_session, PROTOCOL_PAP, &pap_tx);
            break;
        case PROTOCOL_CHAP:
            memset(&chap_tx, 0x0, sizeof(bbl_chap_s));
            chap_rx = (bbl_chap_s*)l2tp->next;
            chap_tx.code = CHAP_CODE_SUCCESS;
            chap_tx.identifier = chap_rx->identifier;
            chap_tx.reply_message = reply_message;
            chap_tx.reply_message_len = snprintf(reply_message, sizeof(reply_message),
                L2TP_REPLY_MESSAGE, l2tp_session->key.tunnel_id, l2tp_session->key.session_id);
            bbl_l2tp_send_data(l2tp_session, PROTOCOL_CHAP, &chap_tx);
            break;
        case PROTOCOL_IPCP:
            ipcp_rx = (bbl_ipcp_s*)l2tp->next;
            memset(&ipcp_tx, 0x0, sizeof(bbl_ipcp_s));
            if(ipcp_rx->code == PPP_CODE_CONF_REQUEST) {
                if(ipcp_rx->address == MOCK_IP_REMOTE) {
                    ipcp_rx->code = PPP_CODE_CONF_ACK;
                    if(l2tp_session->ipcp_state == BBL_PPP_LOCAL_ACK) {
                        l2tp_session->ipcp_state = BBL_PPP_OPENED;
                    } else {
                        l2tp_session->ipcp_state = BBL_PPP_PEER_ACK;
                        ipcp_tx.code = PPP_CODE_CONF_REQUEST;
                        ipcp_tx.identifier = 1;
                        ipcp_tx.address = MOCK_IP_LOCAL;
                        ipcp_tx.option_address = true;
                        bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, &ipcp_tx);
                    }
                } else {
                    ipcp_rx->options = NULL;
                    ipcp_rx->options_len = 0;
                    ipcp_rx->code = PPP_CODE_CONF_NAK;
                    ipcp_rx->address = MOCK_IP_REMOTE;
                    ipcp_rx->option_address = true;
                    if(ipcp_rx->option_dns1) {
                        ipcp_rx->dns1 = MOCK_DNS1;
                    }
                    if(ipcp_rx->option_dns2) {
                        ipcp_rx->dns2 = MOCK_DNS2;
                    }
                }
                bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, ipcp_rx);
            } else if(ipcp_rx->code == PPP_CODE_CONF_ACK) {
                if(l2tp_session->ipcp_state == BBL_PPP_PEER_ACK) {
                    l2tp_session->ipcp_state = BBL_PPP_OPENED;
                } else {
                    l2tp_session->ipcp_state = BBL_PPP_LOCAL_ACK;
                    ipcp_tx.code = PPP_CODE_CONF_REQUEST;
                    ipcp_tx.identifier = 1;
                    ipcp_tx.address = MOCK_IP_LOCAL;
                    ipcp_tx.option_address = true;
                    bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, &ipcp_tx);
                }
            }
            break;
        case PROTOCOL_IP6CP:
            ip6cp_rx = (bbl_ip6cp_s*)l2tp->next;
            memset(&ip6cp_tx, 0x0, sizeof(bbl_ip6cp_s));
            if(ip6cp_rx->code == PPP_CODE_CONF_REQUEST) {
                ip6cp_rx->code = PPP_CODE_CONF_ACK;
                if(l2tp_session->ip6cp_state == BBL_PPP_LOCAL_ACK) {
                    l2tp_session->ip6cp_state = BBL_PPP_OPENED;
                } else {
                    l2tp_session->ip6cp_state = BBL_PPP_PEER_ACK;
                    ip6cp_tx.code = PPP_CODE_CONF_REQUEST;
                    ip6cp_tx.identifier = 1;
                    ip6cp_tx.ipv6_identifier = 1;
                    bbl_l2tp_send_data(l2tp_session, PROTOCOL_IP6CP, &ip6cp_tx);
                }
                bbl_l2tp_send_data(l2tp_session, PROTOCOL_IP6CP, ip6cp_rx);
            } else if(ip6cp_rx->code == PPP_CODE_CONF_ACK) {
                if(l2tp_session->ip6cp_state == BBL_PPP_PEER_ACK) {
                    l2tp_session->ip6cp_state = BBL_PPP_OPENED;
                } else {
                    l2tp_session->ip6cp_state = BBL_PPP_LOCAL_ACK;
                    ip6cp_tx.code = PPP_CODE_CONF_REQUEST;
                    ip6cp_tx.identifier = 1;
                    ip6cp_tx.ipv6_identifier = 1;
                    bbl_l2tp_send_data(l2tp_session, PROTOCOL_IP6CP, &ip6cp_tx);
                }
            }
            break;
        case PROTOCOL_IPV4:
            l2tp_session->stats.data_ipv4_rx++;
            break;
        default:
            break;
    }
}

/**
 * bbl_l2tp_handler_rx
 *
 * This function handles all received L2TPv2 traffic.
 *
 * @param interface receiving interface
 * @param eth received ethernet header
 * @param l2tp L2TP header of received ethernet packet
 */
void
bbl_l2tp_handler_rx(bbl_network_interface_s *interface, 
                    bbl_ethernet_header_s *eth, 
                    bbl_l2tp_s *l2tp)
{
    bbl_ipv4_s *ipv4 = (bbl_ipv4_s*)eth->next;
    bbl_l2tp_session_s *l2tp_session;
    bbl_l2tp_tunnel_s *l2tp_tunnel;

    l2tp_key_t key = {0};
    void **search = NULL;

    if(l2tp->type == L2TP_MESSAGE_SCCRQ) {
        bbl_l2tp_sccrq_rx(interface, eth, l2tp);
        return;
    }

    key.tunnel_id = l2tp->tunnel_id;
    key.session_id = l2tp->session_id;
    search = dict_search(g_ctx->l2tp_session_dict, &key);
    if(!search && l2tp->type && key.session_id != 0) {
        /* Try with session zero (tunnel session) in case
         * the corresponding session was already deleted.
         * This is required for reliable delivery of control
         * messages. */
        key.session_id = 0;
        search = dict_search(g_ctx->l2tp_session_dict, &key);
    }
    if(search) {
        l2tp_session = *search;
        l2tp_tunnel = l2tp_session->tunnel;
        if(l2tp->type == L2TP_MESSAGE_DATA) {
            /* L2TP Data Packet */
            l2tp_tunnel->stats.data_rx++;
            interface->stats.l2tp_data_rx++;
            bbl_l2tp_data_rx(interface, l2tp_session, eth, l2tp);
            return;
        }
        /* L2TP Control Packet */
        l2tp_tunnel->stats.control_rx++;
        interface->stats.l2tp_control_rx++;
        if(L2TP_SEQ_GT(l2tp->nr, l2tp_tunnel->peer_nr)) {
            l2tp_tunnel->peer_nr = l2tp->nr;
        }
        if(l2tp_tunnel->nr == l2tp->ns) {
            /* In-Order packet received */
            LOG(PACKET, "L2TP (%s) %s received from %s\n",
                       l2tp_tunnel->server->host_name,
                       l2tp_message_string(l2tp->type),
                       format_ipv4_address(&ipv4->src));
            /* Update tunnel */
            l2tp_tunnel->peer_ns = l2tp->ns;
            if(l2tp->type != L2TP_MESSAGE_ZLB) {
                l2tp_tunnel->nr = (l2tp->ns + 1);
                l2tp_tunnel->zlb = true;
                /* Start tx timer */
                if(!l2tp_tunnel->timer_tx_active) {
                    timer_add(&g_ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 
                              0, L2TP_TX_WAIT_MS * MSEC, l2tp_tunnel, &bbl_l2tp_tunnel_tx_job);
                    l2tp_tunnel->timer_tx_active = true;
                }
            }
            /* Reliable Delivery of Control Messages */
            switch(l2tp_tunnel->server->congestion_mode) {
                case BBL_L2TP_CONGESTION_AGGRESSIVE:
                    l2tp_tunnel->cwnd = l2tp_tunnel->peer_receive_window;
                    break;
                case BBL_L2TP_CONGESTION_SLOW:
                    l2tp_tunnel->cwnd = 1;
                    break;
                default:
                    /* Adjust tunnel congestion window as defined
                    * in RFC 2661 Appendix A */
                    if(l2tp_tunnel->cwnd < l2tp_tunnel->peer_receive_window) {
                        if(l2tp_tunnel->cwnd < l2tp_tunnel->ssthresh) {
                            /* Slow Start Phase
                            *
                            * The congestion window (CWND) increases by 1
                            * for every new ACK received resulting in an
                            * exponential increase.
                            */
                            l2tp_tunnel->cwcount = 0;
                            l2tp_tunnel->cwnd++;
                        } else {
                            /* Congestion Avoidance Phase
                            *
                            * The congestion window (CWND) increases by 1/CWND
                            * for every new ACK received. resulting in an
                            * linear increase. The variable cwcount is used
                            * track when to increment the congestion window.
                            */
                            l2tp_tunnel->cwcount++;
                            if(l2tp_tunnel->cwcount >= l2tp_tunnel->cwnd) {
                                l2tp_tunnel->cwcount = 0;
                                l2tp_tunnel->cwnd++;
                            }
                        }
                    } else {
                        l2tp_tunnel->ssthresh = l2tp_tunnel->peer_receive_window;
                    }
                    break;
            }
            /* Handle received packet */
            if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_TERMINATED) {
                switch(l2tp->type) {
                    case L2TP_MESSAGE_SCCCN:
                        bbl_l2tp_scccn_rx(interface, l2tp_tunnel, eth, l2tp);
                        return;
                    case L2TP_MESSAGE_STOPCCN:
                        bbl_l2tp_stopccn_rx(interface, l2tp_tunnel, eth, l2tp);
                        return;
                    case L2TP_MESSAGE_ICRQ:
                        bbl_l2tp_icrq_rx(interface, l2tp_tunnel, eth, l2tp);
                        return;
                    case L2TP_MESSAGE_ICCN:
                        if(l2tp_session->key.session_id) {
                            bbl_l2tp_iccn_rx(interface, l2tp_session, eth, l2tp);
                            return;
                        }
                        break;
                    case L2TP_MESSAGE_CSUN:
                        bbl_l2tp_csun_rx(interface, l2tp_tunnel, eth, l2tp);
                        return;
                    case L2TP_MESSAGE_CDN:
                        if(l2tp_session->key.session_id) {
                            bbl_l2tp_cdn_rx(interface, l2tp_session, eth, l2tp);
                            return;
                        }
                        break;
                    default:
                        break;
                }
            }
        } else {
            if(L2TP_SEQ_LT(l2tp->ns, l2tp_tunnel->nr)) {
                /* Duplicate packet received */
                LOG(DEBUG, "L2TP Debug (%s) Duplicate %s received with Ns. %u (expected %u) from %s\n",
                           l2tp_tunnel->server->host_name,
                           l2tp_message_string(l2tp->type),
                           l2tp->ns, l2tp_tunnel->nr,
                           format_ipv4_address(&ipv4->src));

                l2tp_tunnel->zlb = true;
                l2tp_tunnel->stats.control_rx_dup++;
                interface->stats.l2tp_control_rx_dup++;
                if(!l2tp_tunnel->timer_tx_active) {
                    timer_add(&g_ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 
                              0, L2TP_TX_WAIT_MS * MSEC, l2tp_tunnel, &bbl_l2tp_tunnel_tx_job);
                    l2tp_tunnel->timer_tx_active = true;
                }
            } else {
                /* Out-of-Order packet received */
                LOG(DEBUG, "L2TP Debug (%s) Out-of-Order %s received with Ns. %u (expected %u) from %s\n",
                           l2tp_tunnel->server->host_name,
                           l2tp_message_string(l2tp->type),
                           l2tp->ns, l2tp_tunnel->nr,
                           format_ipv4_address(&ipv4->src));

                l2tp_tunnel->stats.control_rx_ooo++;
                interface->stats.l2tp_control_rx_ooo++;
            }
        }
    } else {
        /* Corresponding tunnel or session not found */
        interface->stats.l2tp_control_rx_nf++;
    }
}

/**
 * bbl_l2tp_stop_all_tunnel
 *
 * This function gracefully teardown all L2TP tunnels.
 */
void
bbl_l2tp_stop_all_tunnel()
{
    bbl_l2tp_server_s *l2tp_server = g_ctx->config.l2tp_server;
    bbl_l2tp_tunnel_s *l2tp_tunnel;
    while(l2tp_server) {
        CIRCLEQ_FOREACH(l2tp_tunnel, &l2tp_server->tunnel_qhead, tunnel_qnode) {
            if(l2tp_tunnel->state < BBL_L2TP_TUNNEL_SEND_STOPCCN) {
                bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_SEND_STOPCCN);
                l2tp_tunnel->result_code = 6;
                bbl_l2tp_force_stop(l2tp_tunnel);
            }
        }
        l2tp_server = l2tp_server->next;
    }
}

json_t *
l2tp_session_json(bbl_l2tp_session_s *l2tp_session)
{
    char *proxy_auth_response = NULL;

    if(l2tp_session->proxy_auth_response) {
        if(l2tp_session->proxy_auth_type == L2TP_PROXY_AUTH_TYPE_PAP) {
            proxy_auth_response = (char*)l2tp_session->proxy_auth_response;
        } else {
            proxy_auth_response = "0x...";
        }
    }

    return json_pack("{ss si si si si si ss ss ss ss ss si si ss ss sI sI sI sI}",
                     "state", l2tp_session_state_string(l2tp_session->state),
                     "tunnel-id", l2tp_session->key.tunnel_id,
                     "session-id", l2tp_session->key.session_id,
                     "peer-tunnel-id", l2tp_session->tunnel->peer_tunnel_id,
                     "peer-session-id", l2tp_session->peer_session_id,
                     "peer-proxy-auth-type", l2tp_session->proxy_auth_type,
                     "peer-proxy-auth-name", string_or_na(l2tp_session->proxy_auth_name),
                     "peer-proxy-auth-response", string_or_na(proxy_auth_response),
                     "peer-called-number", string_or_na(l2tp_session->peer_called_number),
                     "peer-calling-number", string_or_na(l2tp_session->peer_calling_number),
                     "peer-sub-address", string_or_na(l2tp_session->peer_sub_address),
                     "peer-tx-bps", l2tp_session->peer_tx_bps,
                     "peer-rx-bps", l2tp_session->peer_rx_bps,
                     "peer-ari", string_or_na(l2tp_session->peer_ari),
                     "peer-aci", string_or_na(l2tp_session->peer_aci),
                     "data-packets-rx", l2tp_session->stats.data_rx,
                     "data-packets-tx", l2tp_session->stats.data_tx,
                     "data-ipv4-packets-rx", l2tp_session->stats.data_ipv4_rx,
                     "data-ipv4-packets-tx", l2tp_session->stats.data_ipv4_tx);
}

/* Control Socket Commands */

int
bbl_l2tp_ctrl_sessions(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *sessions;

    bbl_l2tp_server_s *l2tp_server = g_ctx->config.l2tp_server;
    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_session_s *l2tp_session;
    l2tp_key_t l2tp_key = {0};
    void **search = NULL;

    int l2tp_tunnel_id = 0;
    int l2tp_session_id = 0;

    json_unpack(arguments, "{s:i}", "tunnel-id", &l2tp_tunnel_id);
    json_unpack(arguments, "{s:i}", "session-id", &l2tp_session_id);

    sessions = json_array();

    if(l2tp_tunnel_id && l2tp_session_id) {
        l2tp_key.tunnel_id = l2tp_tunnel_id;
        l2tp_key.session_id = l2tp_session_id;
        search = dict_search(g_ctx->l2tp_session_dict, &l2tp_key);
        if(search) {
            l2tp_session = *search;
            json_array_append(sessions, l2tp_session_json(l2tp_session));
        } else {
            result = bbl_ctrl_status(fd, "warning", 404, "session not found");
            json_decref(sessions);
            return result;
        }
    } else if(l2tp_tunnel_id) {
        l2tp_key.tunnel_id = l2tp_tunnel_id;
        search = dict_search(g_ctx->l2tp_session_dict, &l2tp_key);
        if(search) {
            l2tp_session = *search;
            l2tp_tunnel = l2tp_session->tunnel;
            CIRCLEQ_FOREACH(l2tp_session, &l2tp_tunnel->session_qhead, session_qnode) {
                if(!l2tp_session->key.session_id) continue; /* skip tunnel session */
                json_array_append(sessions, l2tp_session_json(l2tp_session));
            }
        } else {
            result = bbl_ctrl_status(fd, "warning", 404, "tunnel not found");
            json_decref(sessions);
            return result;
        }
    } else {
        while(l2tp_server) {
            CIRCLEQ_FOREACH(l2tp_tunnel, &l2tp_server->tunnel_qhead, tunnel_qnode) {
                CIRCLEQ_FOREACH(l2tp_session, &l2tp_tunnel->session_qhead, session_qnode) {
                    if(!l2tp_session->key.session_id) continue; /* skip tunnel session */
                    json_array_append(sessions, l2tp_session_json(l2tp_session));
                }
            }
            l2tp_server = l2tp_server->next;
        }
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "l2tp-sessions", sessions);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(sessions);
    }
    return result;
}

int
bbl_l2tp_ctrl_csurq(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    json_t *sessions, *number;

    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_session_s *l2tp_session;
    l2tp_key_t l2tp_key = {0};
    void **search = NULL;

    uint16_t l2tp_session_id = 0;
    int l2tp_tunnel_id = 0;
    int size, i;

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:i}", "tunnel-id", &l2tp_tunnel_id) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing tunnel-id");
    }
    l2tp_key.tunnel_id = l2tp_tunnel_id;
    search = dict_search(g_ctx->l2tp_session_dict, &l2tp_key);
    if(search) {
        l2tp_session = *search;
        l2tp_tunnel = l2tp_session->tunnel;
        if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_ESTABLISHED) {
            return bbl_ctrl_status(fd, "warning", 400, "tunnel not established");
        }
        sessions = json_object_get(arguments, "sessions");
        if(json_is_array(sessions)) {
            size = json_array_size(sessions);
            l2tp_tunnel->csurq_requests_len = size;
            l2tp_tunnel->csurq_requests = malloc(size * sizeof(uint16_t));
            for (i = 0; i < size; i++) {
                number = json_array_get(sessions, i);
                if(json_is_number(number)) {
                    l2tp_session_id = json_number_value(number);
                    l2tp_tunnel->csurq_requests[i] = l2tp_session_id;
                }
            }
            bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_CSURQ);
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "error", 400, "invalid request");
        }
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "tunnel not found");
    }
}

int
bbl_l2tp_ctrl_tunnel_terminate(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_session_s *l2tp_session;
    l2tp_key_t l2tp_key = {0};
    void **search = NULL;

    int l2tp_tunnel_id = 0;
    int result_code;
    int error_code;
    char *error_message;

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:i}", "tunnel-id", &l2tp_tunnel_id) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing tunnel-id");
    }
    l2tp_key.tunnel_id = l2tp_tunnel_id;
    search = dict_search(g_ctx->l2tp_session_dict, &l2tp_key);
    if(search) {
        l2tp_session = *search;
        l2tp_tunnel = l2tp_session->tunnel;
        if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_ESTABLISHED) {
            return bbl_ctrl_status(fd, "warning", 400, "tunnel not established");
        }
        bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_SEND_STOPCCN);
        if(json_unpack(arguments, "{s:i}", "result-code", &result_code) != 0) {
            result_code = 1;
        }
        l2tp_tunnel->result_code = result_code;
        if(json_unpack(arguments, "{s:i}", "error-code", &error_code) != 0) {
            error_code = 0;
        }
        l2tp_tunnel->error_code = error_code;
        if(json_unpack(arguments, "{s:s}", "error-message", &error_message) != 0) {
            error_message = NULL;
        }
        l2tp_tunnel->error_message = error_message;
        bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "tunnel not found");
    }
}

int
bbl_l2tp_ctrl_session_terminate(int fd, uint32_t session_id, json_t *arguments)
{
    bbl_session_s *session;
    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_session_s *l2tp_session;

    int result_code;
    int error_code;
    char *error_message;
    int disconnect_code;
    int disconnect_protocol;
    int disconnect_direction;
    char* disconnect_message;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }

    session = bbl_session_get(session_id);
    if(session) {
        l2tp_session = session->l2tp_session;
        if(!l2tp_session) {
            return bbl_ctrl_status(fd, "error", 400, "no L2TP session");
        }
        l2tp_tunnel = l2tp_session->tunnel;
        if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_ESTABLISHED) {
            return bbl_ctrl_status(fd, "warning", 400, "tunnel not established");
        }
        if(l2tp_session->state != BBL_L2TP_SESSION_ESTABLISHED) {
            return bbl_ctrl_status(fd, "warning", 400, "session not established");
        }
        if(json_unpack(arguments, "{s:i}", "result-code", &result_code) != 0) {
            result_code = 2;
        }
        l2tp_session->result_code = result_code;
        if(json_unpack(arguments, "{s:i}", "error-code", &error_code) != 0) {
            error_code = 0;
        }
        l2tp_session->error_code = error_code;
        if(json_unpack(arguments, "{s:s}", "error-message", &error_message) != 0) {
            error_message = NULL;
        }
        l2tp_session->error_message = error_message;
        if(json_unpack(arguments, "{s:i}", "disconnect-code", &disconnect_code) != 0) {
            disconnect_code = 0;
        }
        l2tp_session->disconnect_code = disconnect_code;
        if(json_unpack(arguments, "{s:i}", "disconnect-protocol", &disconnect_protocol) != 0) {
            disconnect_protocol = 0;
        }
        l2tp_session->disconnect_protocol = disconnect_protocol;
        if(json_unpack(arguments, "{s:i}", "disconnect-direction", &disconnect_direction) != 0) {
            disconnect_direction = 0;
        }
        l2tp_session->disconnect_direction = disconnect_direction;
        if(json_unpack(arguments, "{s:s}", "disconnect-message", &disconnect_message) != 0) {
            disconnect_message = NULL;
        }
        l2tp_session->disconnect_message = disconnect_message;
        bbl_l2tp_send(l2tp_tunnel, l2tp_session, L2TP_MESSAGE_CDN);
        bbl_l2tp_session_delete(l2tp_session);
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

int
bbl_l2tp_ctrl_tunnels(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *tunnels, *tunnel;

    bbl_l2tp_server_s *l2tp_server = g_ctx->config.l2tp_server;
    bbl_l2tp_tunnel_s *l2tp_tunnel;

    tunnels = json_array();

    while(l2tp_server) {
        CIRCLEQ_FOREACH(l2tp_tunnel, &l2tp_server->tunnel_qhead, tunnel_qnode) {

            tunnel = json_pack("{ss ss ss si si ss ss ss ss si si si si si sI sI}",
                                "state", l2tp_tunnel_state_string(l2tp_tunnel->state),
                                "server-name", l2tp_server->host_name,
                                "server-address", format_ipv4_address(&l2tp_server->ip),
                                "tunnel-id", l2tp_tunnel->tunnel_id,
                                "peer-tunnel-id", l2tp_tunnel->peer_tunnel_id,
                                "peer-name", string_or_na(l2tp_tunnel->peer_name),
                                "peer-address", format_ipv4_address(&l2tp_tunnel->peer_ip),
                                "peer-vendor", string_or_na(l2tp_tunnel->peer_vendor),
                                "secret", string_or_na(l2tp_server->secret),
                                "control-packets-rx", l2tp_tunnel->stats.control_rx,
                                "control-packets-rx-dup", l2tp_tunnel->stats.control_rx_dup,
                                "control-packets-rx-out-of-order", l2tp_tunnel->stats.control_rx_ooo,
                                "control-packets-tx", l2tp_tunnel->stats.control_tx,
                                "control-packets-tx-retry", l2tp_tunnel->stats.control_retry,
                                "data-packets-rx", l2tp_tunnel->stats.data_rx,
                                "data-packets-tx", l2tp_tunnel->stats.data_tx);
            json_array_append(tunnels, tunnel);
        }
        l2tp_server = l2tp_server->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "l2tp-tunnels", tunnels);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(tunnels);
    }
    return result;
}