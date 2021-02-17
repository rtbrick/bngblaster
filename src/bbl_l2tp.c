/*
 * BNG Blaster (BBL) - L2TPv2 Functions
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_logging.h"
#include <openssl/md5.h>
#include <openssl/rand.h>

const char*
l2tp_message_string(l2tp_message_type type)
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

/** 
 * bbl_l2tp_session_delete 
 *
 * This function will free all dynamic memory for the given 
 * l2tp session instance.
 * 
 * @param l2tp_session Pointer to L2TP session object to be deleted. 
 */
void
bbl_l2tp_session_delete(bbl_l2tp_session_t *l2tp_session) {
    if(l2tp_session) {
        /* Remove session from tunnel object */
        if(CIRCLEQ_NEXT(l2tp_session, session_qnode) != NULL) {
            CIRCLEQ_REMOVE(&l2tp_session->tunnel->session_qhead, l2tp_session, session_qnode);
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
 * @param l2tp_tunnel Pointer to L2TP tunnel object to be deleted. 
 */
void
bbl_l2tp_tunnel_delete(bbl_l2tp_tunnel_t *l2tp_tunnel) {
    bbl_l2tp_queue_t *q = NULL;
    bbl_interface_s *interface = l2tp_tunnel->server->interface;

    if(l2tp_tunnel) {
        /* Delete all remaining sessions */
        while (!CIRCLEQ_EMPTY(&l2tp_tunnel->session_qhead)) {
            bbl_l2tp_session_delete(CIRCLEQ_FIRST(&l2tp_tunnel->session_qhead));
        }
        /* Remove tunnel from server object */
        if(CIRCLEQ_NEXT(l2tp_tunnel, tunnel_qnode) != NULL) {
            CIRCLEQ_REMOVE(&l2tp_tunnel->server->tunnel_qhead, l2tp_tunnel, tunnel_qnode);
        }
        /* Cleanup send queues */
        while (!CIRCLEQ_EMPTY(&l2tp_tunnel->txq_qhead)) {
            q = CIRCLEQ_FIRST(&l2tp_tunnel->txq_qhead);
            if(CIRCLEQ_NEXT(q, tx_qnode) != NULL) {
                CIRCLEQ_REMOVE(&interface->l2tp_tx_qhead, q, tx_qnode);
            }
            free(q->packet);
            free(q);
        }

        if(l2tp_tunnel->zlb_qnode) {
            free(l2tp_tunnel->zlb_qnode->packet);
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
 * bbl_l2tp_tunnel_tx_job 
 *
 * This function ...
 */
void
bbl_l2tp_tunnel_tx_job (timer_s *timer) {
    bbl_l2tp_tunnel_t *l2tp_tunnel = timer->data;
    bbl_interface_s *interface = l2tp_tunnel->server->interface;
    bbl_l2tp_queue_t *q = NULL;
    bbl_l2tp_queue_t *q_del = NULL;

    struct timespec timestamp;
    struct timespec time_diff;
    double time_diff_ms;

    uint16_t max_ns = l2tp_tunnel->peer_nr + l2tp_tunnel->cwnd;

    l2tp_tunnel->timer_tx_active = false;
    if(!CIRCLEQ_EMPTY(&interface->l2tp_tx_qhead)) {
        return;
    }       

    clock_gettime(CLOCK_REALTIME, &timestamp);

    q = CIRCLEQ_FIRST(&l2tp_tunnel->txq_qhead);
    while (q != (const void *)(&l2tp_tunnel->txq_qhead)) {
        if (L2TP_SEQ_LT(q->ns, l2tp_tunnel->peer_nr)) {
            /* Delete acknowledged messages from queue. */
            q_del = q;
            q = CIRCLEQ_NEXT(q, txq_qnode);
            CIRCLEQ_REMOVE(&l2tp_tunnel->txq_qhead, q_del, txq_qnode);
            free(q_del->packet);
            free(q_del);
        }
        if (L2TP_SEQ_LT(q->ns, max_ns)) {
            if(q->last_tx_time.tv_sec) {
                timespec_sub(&time_diff, &timestamp, &q->last_tx_time);
                time_diff_ms = round(time_diff.tv_nsec / 1.0e6) * (time_diff.tv_sec * 1000);
                if(time_diff_ms < 1000) {
                    continue;
                }
            }
            CIRCLEQ_INSERT_TAIL(&interface->l2tp_tx_qhead, q, tx_qnode);
            l2tp_tunnel->zlb = false;
            q->last_tx_time.tv_sec = timestamp.tv_sec;
            q->last_tx_time.tv_nsec = timestamp.tv_nsec;
            /* Update Nr. ... */
            *(uint16_t*)(q->packet + q->nr_offset) = htobe16(l2tp_tunnel->nr);
            q->retries++;
        } else {
            break;
        }
    }
    if(l2tp_tunnel->zlb) {
        CIRCLEQ_INSERT_TAIL(&interface->l2tp_tx_qhead, l2tp_tunnel->zlb_qnode, tx_qnode);
        *(uint16_t*)(l2tp_tunnel->zlb_qnode->packet + l2tp_tunnel->zlb_qnode->ns_offset) = htobe16(l2tp_tunnel->ns);
        *(uint16_t*)(l2tp_tunnel->zlb_qnode->packet + l2tp_tunnel->zlb_qnode->nr_offset) = htobe16(l2tp_tunnel->nr);
    }
}

/** 
 * bbl_l2tp_tunnel_control_job 
 *
 * This function ...
 */
void
bbl_l2tp_tunnel_control_job (timer_s *timer) {
    bbl_l2tp_tunnel_t *l2tp_tunnel = timer->data;
    bbl_interface_s *interface = l2tp_tunnel->server->interface;
    bbl_ctx_s *ctx = interface->ctx;

    if(!l2tp_tunnel->timer_tx_active) {
        timer_add(&ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 0, 10 * MSEC, l2tp_tunnel, bbl_l2tp_tunnel_tx_job);
        l2tp_tunnel->timer_tx_active = true;
    }
}

/** 
 * bbl_l2tp_send 
 *
 * This function ...
 * 
 * @param l2tp_tunnel Mandatory pointer to L2TP tunnel object. 
 * @param l2tp_session Optional pointer to L2TP session object. 
 *        This parameter is only required of L2TP session packets.
 * @param l2tp_type L2TP message type (SCCRP, ICRP, ...)
 */
static void
bbl_l2tp_send(bbl_l2tp_tunnel_t *l2tp_tunnel, bbl_l2tp_session_t *l2tp_session, l2tp_message_type l2tp_type) {

    bbl_interface_s *interface = l2tp_tunnel->server->interface;
    bbl_ctx_s *ctx = interface->ctx;

    bbl_l2tp_queue_t *q = calloc(1, sizeof(bbl_l2tp_queue_t));

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_udp_t udp = {0};
    bbl_l2tp_t l2tp = {0};

    uint8_t sp[L2TP_MAX_AVP_SIZE]; /* scratchpad memory to craft the AVP attributes */
    uint16_t sp_len;
    uint len;

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->ctx->config.network_vlan;
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
    l2tp.type = l2tp_type;
    l2tp.ns = l2tp_tunnel->ns++;

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
    q->ns = l2tp.ns;
    q->tunnel = l2tp_tunnel;

    bbl_l2tp_avp_encode_attributes(l2tp_tunnel, l2tp_session, l2tp_type, sp, &sp_len);
    q->packet = malloc(L2TP_MAX_PACKET_SIZE);
    if(encode_ethernet(q->packet, &len, &eth) == PROTOCOL_SUCCESS) {
        q->packet_len = len;
        if(l2tp_type == L2TP_MESSAGE_ZLB) {
            if(l2tp_tunnel->zlb_qnode) {
                free(q->packet);
                free(q);
            } else {
                l2tp_tunnel->zlb_qnode = q;
            }
        } else {
            CIRCLEQ_INSERT_TAIL(&l2tp_tunnel->txq_qhead, q, txq_qnode);
            if(!l2tp_tunnel->timer_tx_active) {
                timer_add(&ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 0, 10 * MSEC, l2tp_tunnel, bbl_l2tp_tunnel_tx_job);
                l2tp_tunnel->timer_tx_active = true;
            }
        }
    } else {
        /* Encode error.... */
        LOG(ERROR, "L2TP Encode Error\n");
        free(q->packet);
        free(q);
    }
}

static void
bbl_l2tp_sccrq_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface) {
    MD5_CTX md5_ctx;

    bbl_ctx_s *ctx = interface->ctx;
    bbl_ipv4_t *ipv4 = (bbl_ipv4_t*)eth->next;

    bbl_l2tp_server_t *l2tp_server = ctx->config.l2tp_server;
    bbl_l2tp_tunnel_t *l2tp_tunnel;
    bbl_l2tp_tunnel_t *l2tp_tunnel2;
    bbl_l2tp_session_t *l2tp_session;

    l2tp_key_t key;
    dict_insert_result result;
    void **search;

    uint8_t l2tp_type;

    while(l2tp_server) {
        if(l2tp_server->ip == ipv4->dst) {
            LOG(L2TP, "L2TP Info (%s) SCCRQ received from %s\n",
                      l2tp_server->host_name, format_ipv4_address(&ipv4->src));

            l2tp_tunnel = calloc(1, sizeof(bbl_l2tp_tunnel_t));
            l2tp_tunnel->peer_ip = ipv4->src;
            l2tp_tunnel->server = l2tp_server;
            l2tp_tunnel->state = BBL_L2TP_TUNNEL_WAIT_CTR_CONN;
            if(!bbl_l2tp_avp_decode_tunnel(l2tp, l2tp_tunnel)) {
                return bbl_l2tp_tunnel_delete(l2tp_tunnel);
            }
            if(!l2tp_tunnel->peer_tunnel_id ||
               !l2tp_tunnel->peer_name) {
                LOG(L2TP, "L2TP Error (%s) Invalid SCCRQ received from %s\n",
                      l2tp_server->host_name, format_ipv4_address(&ipv4->src));
                return bbl_l2tp_tunnel_delete(l2tp_tunnel);
            }

            /* Check for SCCRQ retry ... */
            CIRCLEQ_FOREACH(l2tp_tunnel2, &l2tp_server->tunnel_qhead, tunnel_qnode) {
                if(l2tp_tunnel2->peer_ip == l2tp_tunnel->peer_ip &&
                   l2tp_tunnel2->peer_tunnel_id == l2tp_tunnel->peer_tunnel_id) {
                       /* Seems to be an SCCRQ retry ... */
                       return bbl_l2tp_tunnel_delete(l2tp_tunnel);
                }
            }

            /* Assign tunnel id ... */
            while(true) {
                key.ip = l2tp_server->ip;
                key.tunnel_id = l2tp_server->next_tunnel_id++;
                key.session_id = 0;
                search = dict_search(ctx->l2tp_session_dict, &key);
                if(search) {
                    /* Used, try next ... */
                    key.tunnel_id = l2tp_server->next_tunnel_id++;
                } else {
                    break;
                }
            }
            l2tp_tunnel->tunnel_id = key.tunnel_id;

            /* Add dummy tunnel session, this session is only used 
             * to search for tunnel using the same dictionary. */
            l2tp_session = calloc(1, sizeof(bbl_l2tp_session_t));
            l2tp_session->state = BBL_L2TP_SESSION_MAX;
            l2tp_session->tunnel = l2tp_tunnel;
            l2tp_session->key.ip = key.ip;
            l2tp_session->key.tunnel_id = key.tunnel_id;
            result = dict_insert(ctx->l2tp_session_dict, &key);
            if (!result.inserted) {
                /* TODO: Here we need to handle this properly but actually 
                 * this should not happen. */
                free(l2tp_session);
                return;
            }
            *result.datum_ptr = l2tp_session;
            CIRCLEQ_INIT(&l2tp_tunnel->txq_qhead);
            CIRCLEQ_INIT(&l2tp_tunnel->session_qhead);
            CIRCLEQ_INSERT_TAIL(&l2tp_tunnel->session_qhead, l2tp_session, session_qnode);

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
                    l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                }
            } else {
                if(l2tp_tunnel->peer_challenge_len) {
                    /* We are not able to setup a session if challenge
                     * is received but not secret configured! */
                    l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                }
            }
            /* Add tunnel to server */
            CIRCLEQ_INSERT_TAIL(&l2tp_server->tunnel_qhead, l2tp_tunnel, tunnel_qnode);
            /* Start control job */
            timer_add_periodic(&ctx->timer_root, &l2tp_tunnel->timer_ctrl, "L2TP Control", 1, 0, l2tp_tunnel, bbl_l2tp_tunnel_control_job);
            
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
}

static void
bbl_l2tp_scccn_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_tunnel_t *l2tp_tunnel) {
    bbl_ctx_s *ctx = interface->ctx;
    
    UNUSED(ctx);
    UNUSED(eth);
    UNUSED(l2tp);

    if(l2tp_tunnel->state == BBL_L2TP_TUNNEL_WAIT_CTR_CONN) {
        l2tp_tunnel->state = BBL_L2TP_TUNNEL_ESTABLISHED;
        LOG(L2TP, "L2TP Info (%s) Tunnel from %s (%s) estbalished\n",
                  l2tp_tunnel->server->host_name, l2tp_tunnel->peer_name, format_ipv4_address(&l2tp_tunnel->peer_ip));    
    }
}

static void
bbl_l2tp_stopccn_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_tunnel_t *l2tp_tunnel) {
    bbl_ctx_s *ctx = interface->ctx;

    UNUSED(ctx);
    UNUSED(eth);
    UNUSED(l2tp);

    l2tp_tunnel->state = BBL_L2TP_TUNNEL_TERMINATED;
}

static void
bbl_l2tp_icrq_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_tunnel_t *l2tp_tunnel) {
    bbl_ctx_s *ctx = interface->ctx;

    l2tp_key_t key;
    dict_insert_result result;
    void **search;

    bbl_l2tp_session_t *l2tp_session = calloc(1, sizeof(bbl_l2tp_session_t));

    UNUSED(eth);
    UNUSED(l2tp);

    l2tp_session->tunnel = l2tp_tunnel;
    l2tp_tunnel->state = BBL_L2TP_SESSION_WAIT_CONN;

    if(!bbl_l2tp_avp_decode_session(l2tp, l2tp_tunnel, l2tp_session)) {
        return bbl_l2tp_session_delete(l2tp_session);
    }

    /* Assign session id ... */
    while(true) {
        key.ip = l2tp_tunnel->server->ip;
        key.tunnel_id = l2tp_tunnel->tunnel_id;
        key.session_id = l2tp_tunnel->next_session_id++;
        search = dict_search(ctx->l2tp_session_dict, &key);
        if(search) {
            /* Used, try next ... */
            key.session_id = l2tp_tunnel->next_session_id++;
        } else {
            break;
        }
    }
    l2tp_session->key.ip = key.ip;
    l2tp_session->key.tunnel_id = key.tunnel_id;
    l2tp_session->key.session_id = key.session_id;

    result = dict_insert(ctx->l2tp_session_dict, &key);
    if (!result.inserted) {
        /* TODO: Here we need to handle this properly but actually 
         * this should not happen. */
        free(l2tp_session);
        return;
    }
    *result.datum_ptr = l2tp_session;
    CIRCLEQ_INSERT_TAIL(&l2tp_tunnel->session_qhead, l2tp_session, session_qnode);

    bbl_l2tp_send(l2tp_tunnel, l2tp_session, L2TP_MESSAGE_ICRP);
}

static void
bbl_l2tp_iccn_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_session_t *l2tp_session) {
    bbl_ctx_s *ctx = interface->ctx;

    UNUSED(ctx);
    UNUSED(eth);
    UNUSED(l2tp);

    if(l2tp_session->state == BBL_L2TP_SESSION_WAIT_CONN) {
        l2tp_session->state = BBL_L2TP_SESSION_ESTABLISHED;
    }
}

static void
bbl_l2tp_cdn_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_session_t *l2tp_session) {
    bbl_ctx_s *ctx = interface->ctx;

    UNUSED(ctx);
    UNUSED(eth);
    UNUSED(l2tp);

    l2tp_session->state = BBL_L2TP_SESSION_TERMINATED;
    bbl_l2tp_session_delete(l2tp_session);
}

static void
bbl_l2tp_data_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_session_t *l2tp_session) {
    bbl_ctx_s *ctx = interface->ctx;

    UNUSED(ctx);
    UNUSED(eth);
    UNUSED(l2tp);
    UNUSED(l2tp_session);

}

/** 
 * bbl_l2tp_handler_rx 
 *
 * This function ...
 * 
 * @param eth ... 
 * @param l2tp ...
 * @param interface ...
 */
void
bbl_l2tp_handler_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface) {
    bbl_ctx_s *ctx = interface->ctx;
    bbl_ipv4_t *ipv4 = (bbl_ipv4_t*)eth->next;
    bbl_l2tp_session_t *l2tp_session; 
    bbl_l2tp_tunnel_t *l2tp_tunnel; 

    l2tp_key_t key;
    void **search;
    
    if(l2tp->type == L2TP_MESSAGE_SCCRQ) {
        return bbl_l2tp_sccrq_rx(eth, l2tp, interface);
    }

    key.ip = ipv4->src;
    key.tunnel_id = l2tp->tunnel_id;
    key.session_id = l2tp->session_id;

    search = dict_search(interface->ctx->l2tp_session_dict, &key);
    if(search) {
        l2tp_session = *search;
        l2tp_tunnel = l2tp_session->tunnel;

        if(l2tp->type == L2TP_MESSAGE_DATA) {
            l2tp_tunnel->stats.data_rx++;
            return bbl_l2tp_data_rx(eth, l2tp, interface, l2tp_session);
        }
        if (L2TP_SEQ_GT(l2tp->nr, l2tp_tunnel->peer_nr)) {
            l2tp_tunnel->peer_nr = l2tp->nr;
        }
        if (l2tp_tunnel->nr == l2tp->ns) {
            /* In-Order packet received */
            l2tp_tunnel->peer_ns = l2tp->ns;
            l2tp_tunnel->nr = (l2tp->ns + 1);
            l2tp_tunnel->zlb = true;
            l2tp_tunnel->stats.control_rx++;
            if(!l2tp_tunnel->timer_tx_active) {
                timer_add(&ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 0, 10 * MSEC, l2tp_tunnel, bbl_l2tp_tunnel_tx_job);
                l2tp_tunnel->timer_tx_active = true;
            }
            if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_TERMINATED) {
                switch (l2tp->type) {
                    case L2TP_MESSAGE_SCCCN:
                        return bbl_l2tp_scccn_rx(eth, l2tp, interface, l2tp_tunnel);
                    case L2TP_MESSAGE_STOPCCN:
                        return bbl_l2tp_stopccn_rx(eth, l2tp, interface, l2tp_tunnel);
                    case L2TP_MESSAGE_ICRQ:
                        return bbl_l2tp_icrq_rx(eth, l2tp, interface, l2tp_tunnel);
                    case L2TP_MESSAGE_ICCN:
                        return bbl_l2tp_iccn_rx(eth, l2tp, interface, l2tp_session);
                    case L2TP_MESSAGE_CDN:
                        return bbl_l2tp_cdn_rx(eth, l2tp, interface, l2tp_session);
                    default:
                        break;
                }
            }
        } else {
            if (L2TP_SEQ_LT(l2tp->ns, l2tp_tunnel->nr)) {
                /* Duplicate packet received */
                l2tp_tunnel->zlb = true;
                l2tp_tunnel->stats.control_rx_dup++;
                if(!l2tp_tunnel->timer_tx_active) {
                    timer_add(&ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 0, 10 * MSEC, l2tp_tunnel, bbl_l2tp_tunnel_tx_job);
                    l2tp_tunnel->timer_tx_active = true;
                }
            } else {
                /* Out-of-Order packet received */
                l2tp_tunnel->stats.control_rx_ooo++;
            }
        }
    }
}