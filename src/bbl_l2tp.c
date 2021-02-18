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

static void
bbl_l2tp_send(bbl_l2tp_tunnel_t *l2tp_tunnel, bbl_l2tp_session_t *l2tp_session, l2tp_message_type l2tp_type);

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
    bbl_ctx_s *ctx;
    
    if(l2tp_session) {
        ctx = l2tp_session->tunnel->interface->ctx;
        /* Remove session from tunnel object */
        if(CIRCLEQ_NEXT(l2tp_session, session_qnode) != NULL) {
            CIRCLEQ_REMOVE(&l2tp_session->tunnel->session_qhead, l2tp_session, session_qnode);
            CIRCLEQ_NEXT(l2tp_session, session_qnode) = NULL;
        }
        /* Remove session from dict */
        dict_remove(ctx->l2tp_session_dict, &l2tp_session->key);
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
    bbl_interface_s *interface = l2tp_tunnel->interface;

    if(l2tp_tunnel) {
        LOG(L2TP, "L2TP DEBUG (%s) Tunnel (%u) from %s (%s) deleted\n",
                  l2tp_tunnel->server->host_name, l2tp_tunnel->tunnel_id, 
                  l2tp_tunnel->peer_name, 
                  format_ipv4_address(&l2tp_tunnel->peer_ip));   

        /* Delete timer */
        timer_del(l2tp_tunnel->timer_tx);
        timer_del(l2tp_tunnel->timer_ctrl);
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
                CIRCLEQ_REMOVE(&interface->l2tp_tx_qhead, q, tx_qnode);
                CIRCLEQ_NEXT(q, tx_qnode) = NULL;
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
    bbl_interface_s *interface = l2tp_tunnel->interface;
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

    if(l2tp_tunnel->state == BBL_L2TP_TUNNEL_SEND_STOPCCN) {
        if(CIRCLEQ_EMPTY(&l2tp_tunnel->txq_qhead)) {
            l2tp_tunnel->state = BBL_L2TP_TUNNEL_TERMINATED;
            l2tp_tunnel->state_seconds = 0;
        }
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
            continue;
        }
        if (L2TP_SEQ_LT(q->ns, max_ns)) {
            if(q->last_tx_time.tv_sec) {
                timespec_sub(&time_diff, &timestamp, &q->last_tx_time);
                time_diff_ms = round(time_diff.tv_nsec / 1.0e6) * (time_diff.tv_sec * 1000);
                if(time_diff_ms < 1000) {
                    q = CIRCLEQ_NEXT(q, txq_qnode);
                    continue;
                }
            }
            CIRCLEQ_INSERT_TAIL(&interface->l2tp_tx_qhead, q, tx_qnode);
            l2tp_tunnel->stats.control_tx++;
            interface->stats.l2tp_control_tx++;
            l2tp_tunnel->zlb = false;
            q->last_tx_time.tv_sec = timestamp.tv_sec;
            q->last_tx_time.tv_nsec = timestamp.tv_nsec;
            /* Update Nr. ... */
            *(uint16_t*)(q->packet + q->nr_offset) = htobe16(l2tp_tunnel->nr);
            if(q->retries) {
                l2tp_tunnel->stats.control_retry++;
                interface->stats.l2tp_control_retry++;
                if(q->retries > l2tp_tunnel->server->max_retry) {
                    l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                    l2tp_tunnel->state_seconds = 0;
                    bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
                }
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
 *
 * This function ...
 */
void
bbl_l2tp_tunnel_control_job (timer_s *timer) {
    bbl_l2tp_tunnel_t *l2tp_tunnel = timer->data;
    bbl_interface_s *interface = l2tp_tunnel->interface;
    bbl_ctx_s *ctx = interface->ctx;
    l2tp_tunnel->state_seconds++;
    switch(l2tp_tunnel->state) {
        case BBL_L2TP_TUNNEL_WAIT_CTR_CONN:
            if(l2tp_tunnel->state_seconds > 30) {
                l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                l2tp_tunnel->state_seconds = 0;
                bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
            }
            break;
        case BBL_L2TP_TUNNEL_ESTABLISHED: 
            if(l2tp_tunnel->server->hello_interval) {
                if(l2tp_tunnel->state_seconds % l2tp_tunnel->server->hello_interval == 0) {
                    bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_HELLO);
                }
            }
            break;
        case BBL_L2TP_TUNNEL_SEND_STOPCCN:
        case BBL_L2TP_TUNNEL_RCVD_STOPCCN:
            if(l2tp_tunnel->state_seconds > 5) {
                l2tp_tunnel->state = BBL_L2TP_TUNNEL_TERMINATED;
                l2tp_tunnel->state_seconds = 0;
            }
            break;
        case BBL_L2TP_TUNNEL_TERMINATED:
            timer->periodic = false;
            return bbl_l2tp_tunnel_delete(l2tp_tunnel);
        default:
            break;
    }
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

    bbl_interface_s *interface = l2tp_tunnel->interface;
    bbl_ctx_s *ctx = interface->ctx;

    bbl_l2tp_queue_t *q = calloc(1, sizeof(bbl_l2tp_queue_t));

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_udp_t udp = {0};
    bbl_l2tp_t l2tp = {0};

    uint8_t sp[L2TP_MAX_AVP_SIZE]; /* scratchpad memory to craft the AVP attributes */
    uint16_t sp_len = 0;
    uint len = 0;

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = ctx->config.network_vlan;
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
        if(l2tp_tunnel->initial_packet_send) {
            l2tp_tunnel->ns++;
        } else{
            l2tp_tunnel->initial_packet_send = true;
        }
        l2tp.ns = l2tp_tunnel->ns;
        bbl_l2tp_avp_encode_attributes(l2tp_tunnel, l2tp_session, l2tp_type, sp, &sp_len);
        l2tp.payload = sp;
        l2tp.payload_len = sp_len;
    }
    q->ns = l2tp.ns;
    q->tunnel = l2tp_tunnel;
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
        LOG(ERROR, "L2TP Encode Error!\n");
        free(q->packet);
        free(q);
    }
}

/** 
 * bbl_l2tp_send_data 
 *
 * This function ...
 * 
 * @param l2tp_tunnel Mandatory pointer to L2TP tunnel object. 
 * @param l2tp_session Mandatory pointer to L2TP session object. 
 * @param protocol ...
 * @param next ...
 */
static void
bbl_l2tp_send_data(bbl_l2tp_session_t *l2tp_session, uint16_t protocol, void *next) {

    bbl_l2tp_tunnel_t *l2tp_tunnel = l2tp_session->tunnel;
    bbl_interface_s *interface = l2tp_tunnel->interface;
    bbl_l2tp_queue_t *q = calloc(1, sizeof(bbl_l2tp_queue_t));
    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_udp_t udp = {0};
    bbl_l2tp_t l2tp = {0};
    uint len = 0;
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
    l2tp.type = L2TP_MESSAGE_DATA;
    l2tp.tunnel_id = l2tp_tunnel->peer_tunnel_id;
    l2tp.session_id = l2tp_session->peer_session_id;
    l2tp.protocol = protocol;
    l2tp.next = next;
    q->data = true;
    q->packet = malloc(L2TP_MAX_PACKET_SIZE);
    if(encode_ethernet(q->packet, &len, &eth) == PROTOCOL_SUCCESS) {
        q->packet_len = len;
        CIRCLEQ_INSERT_TAIL(&interface->l2tp_tx_qhead, q, tx_qnode);
        l2tp_tunnel->stats.data_tx++;
        interface->stats.l2tp_data_tx++;
    } else {
        /* Encode error.... */
        LOG(ERROR, "L2TP Data Encode Error!\n");
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

    dict_insert_result result;
    void **search = NULL;

    uint8_t l2tp_type;

    while(l2tp_server) {
        if(l2tp_server->ip == ipv4->dst) {
            LOG(DEBUG, "L2TP Debug (%s) SCCRQ received from %s\n",
                       l2tp_server->host_name, 
                       format_ipv4_address(&ipv4->src));
            /* Init tunnel ... */
            l2tp_tunnel = calloc(1, sizeof(bbl_l2tp_tunnel_t));
            CIRCLEQ_INIT(&l2tp_tunnel->txq_qhead);
            CIRCLEQ_INIT(&l2tp_tunnel->session_qhead);
            l2tp_tunnel->interface = interface;
            l2tp_tunnel->server = l2tp_server;
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
                return bbl_l2tp_tunnel_delete(l2tp_tunnel);
            }
            if(!l2tp_tunnel->peer_tunnel_id ||
               !l2tp_tunnel->peer_name) {
                LOG(ERROR, "L2TP Error (%s) Invalid SCCRQ received from %s\n",
                           l2tp_server->host_name, 
                           format_ipv4_address(&ipv4->src));
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

            /* Add dummy tunnel session, this session is only used 
             * to search for tunnel using the same dictionary. */
            l2tp_session = calloc(1, sizeof(bbl_l2tp_session_t));
            l2tp_session->state = BBL_L2TP_SESSION_MAX;
            l2tp_session->tunnel = l2tp_tunnel;
            l2tp_session->key.session_id = 0;
    
            /* Assign tunnel id ... */
            while(true) {
                l2tp_session->key.tunnel_id = ctx->next_tunnel_id++;
                if(l2tp_session->key.tunnel_id == 0) continue; /* skip tunnel 0 */
                search = dict_search(ctx->l2tp_session_dict, &l2tp_session->key);
                if(search) {
                    /* Used, try next ... */
                    continue;
                } else {
                    break;
                }
            }
            l2tp_tunnel->tunnel_id = l2tp_session->key.tunnel_id;
            result = dict_insert(ctx->l2tp_session_dict, &l2tp_session->key);
            if (!result.inserted) {
                LOG(ERROR, "L2TP Error (%s) Failed to add tunnel session\n",
                            l2tp_tunnel->server->host_name); 
                free(l2tp_session);
                return bbl_l2tp_tunnel_delete(l2tp_tunnel);
            }
            *result.datum_ptr = l2tp_session;
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
                    LOG(ERROR, "L2TP Error (%s) Missing challenge in SCCRQ from %s\n",
                               l2tp_tunnel->server->host_name, 
                               format_ipv4_address(&l2tp_tunnel->peer_ip));
                    l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                }
            } else {
                if(l2tp_tunnel->peer_challenge_len) {
                    /* We are not able to setup a session if challenge
                     * is received but not secret configured! */
                    LOG(ERROR, "L2TP Error (%s) No secret found but challenge received in SCCRQ from %s\n",
                               l2tp_tunnel->server->host_name, 
                               format_ipv4_address(&l2tp_tunnel->peer_ip));
                    l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                }
            }
            /* Add tunnel to server */
            CIRCLEQ_INSERT_TAIL(&l2tp_server->tunnel_qhead, l2tp_tunnel, tunnel_qnode);
            /* Start control job
             * WARNING: Do not change the interval! */
            timer_add_periodic(&ctx->timer_root, &l2tp_tunnel->timer_ctrl, "L2TP Control", 1, 0, l2tp_tunnel, bbl_l2tp_tunnel_control_job);
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
}

static void
bbl_l2tp_scccn_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_tunnel_t *l2tp_tunnel) {
    bbl_ctx_s *ctx = interface->ctx;

    uint8_t digest[L2TP_MD5_DIGEST_LEN];
    MD5_CTX md5_ctx;
    uint8_t l2tp_type = L2TP_MESSAGE_SCCCN;
 
    UNUSED(ctx);
    UNUSED(eth);

    if(l2tp_tunnel->state == BBL_L2TP_TUNNEL_WAIT_CTR_CONN) {
        if(!bbl_l2tp_avp_decode_tunnel(l2tp, l2tp_tunnel)) {
            LOG(ERROR, "L2TP Error (%s) Invalid SCCCN received from %s\n",
                       l2tp_tunnel->server->host_name, 
                       format_ipv4_address(&l2tp_tunnel->peer_ip));
            l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
            l2tp_tunnel->state_seconds = 0;
            return bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
        }
        /* Check challenge response ... */
        if(l2tp_tunnel->server->secret) {
            if(l2tp_tunnel->peer_challenge_response_len) {
                MD5_Init(&md5_ctx);
                MD5_Update(&md5_ctx, &l2tp_type, 1);
                MD5_Update(&md5_ctx, (unsigned char *) l2tp_tunnel->server->secret, strlen(l2tp_tunnel->server->secret));
                MD5_Update(&md5_ctx, l2tp_tunnel->challenge, l2tp_tunnel->challenge_len);
                MD5_Final(digest, &md5_ctx);
                if (memcmp(digest, l2tp_tunnel->peer_challenge_response, L2TP_MD5_DIGEST_LEN) != 0) {
                    LOG(ERROR, "L2TP Error (%s) Wrong challenge response in SCCCN from %s\n",
                               l2tp_tunnel->server->host_name, 
                               format_ipv4_address(&l2tp_tunnel->peer_ip));
                    l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                    l2tp_tunnel->state_seconds = 0;
                    return bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
                }
            } else {
                LOG(ERROR, "L2TP Error (%s) Missing challenge response in SCCCN from %s\n",
                           l2tp_tunnel->server->host_name, 
                           format_ipv4_address(&l2tp_tunnel->peer_ip));
                l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                l2tp_tunnel->state_seconds = 0;
                return bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
            }
        }
        l2tp_tunnel->state = BBL_L2TP_TUNNEL_ESTABLISHED;
        l2tp_tunnel->state_seconds = 0;
        LOG(L2TP, "L2TP Info (%s) Tunnel (%u) from %s (%s) estbalished\n",
                  l2tp_tunnel->server->host_name, l2tp_tunnel->tunnel_id, 
                  l2tp_tunnel->peer_name, 
                  format_ipv4_address(&l2tp_tunnel->peer_ip));    
    }
}

static void
bbl_l2tp_stopccn_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_tunnel_t *l2tp_tunnel) {
    bbl_ctx_s *ctx = interface->ctx;

    UNUSED(ctx);
    UNUSED(eth);
    UNUSED(l2tp);

    l2tp_tunnel->state = BBL_L2TP_TUNNEL_RCVD_STOPCCN;
    l2tp_tunnel->state_seconds = 0;
}

static void
bbl_l2tp_icrq_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_tunnel_t *l2tp_tunnel) {
    bbl_ctx_s *ctx = interface->ctx;

    dict_insert_result result;
    void **search;

    UNUSED(eth);

    if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_ESTABLISHED) {
        return;
    }

    bbl_l2tp_session_t *l2tp_session = calloc(1, sizeof(bbl_l2tp_session_t));
    l2tp_session->tunnel = l2tp_tunnel;
    l2tp_session->state = BBL_L2TP_SESSION_WAIT_CONN;

    if(!bbl_l2tp_avp_decode_session(l2tp, l2tp_tunnel, l2tp_session)) {
        return bbl_l2tp_session_delete(l2tp_session);
    }

    l2tp_session->key.tunnel_id = l2tp_tunnel->tunnel_id;

    /* Assign session id ... */
    while(true) {
        l2tp_session->key.session_id = l2tp_tunnel->next_session_id++;
        if(l2tp_session->key.session_id == 0) continue; /* skip tunnel 0 */
        search = dict_search(ctx->l2tp_session_dict, &l2tp_session->key);
        if(search) {
            /* Used, try next ... */
            continue;
        } else {
            break;
        }
    }
    result = dict_insert(ctx->l2tp_session_dict, &l2tp_session->key);
    if (!result.inserted) {
        LOG(ERROR, "L2TP Error (%s) Failed to add session\n",
                    l2tp_tunnel->server->host_name); 
        free(l2tp_session);
        return ;
    }
    *result.datum_ptr = l2tp_session;
    CIRCLEQ_INSERT_TAIL(&l2tp_tunnel->session_qhead, l2tp_session, session_qnode);
    bbl_l2tp_send(l2tp_tunnel, l2tp_session, L2TP_MESSAGE_ICRP);
}

static void
bbl_l2tp_iccn_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_session_t *l2tp_session) {
    bbl_ctx_s *ctx = interface->ctx;
    bbl_l2tp_tunnel_t *l2tp_tunnel = l2tp_session->tunnel;

    UNUSED(ctx);
    UNUSED(eth);
    UNUSED(l2tp);

    if(!bbl_l2tp_avp_decode_session(l2tp, l2tp_tunnel, l2tp_session)) {
        bbl_l2tp_send(l2tp_tunnel, l2tp_session, L2TP_MESSAGE_CDN);
        return bbl_l2tp_session_delete(l2tp_session);
    }
    if(l2tp_session->state == BBL_L2TP_SESSION_WAIT_CONN) {
        l2tp_session->state = BBL_L2TP_SESSION_ESTABLISHED;
        LOG(L2TP, "L2TP Info (%s) Tunnel (%u) from %s (%s) session (%u) estbalished\n",
                  l2tp_tunnel->server->host_name, l2tp_tunnel->tunnel_id, 
                  l2tp_tunnel->peer_name, 
                  format_ipv4_address(&l2tp_tunnel->peer_ip),
                  l2tp_session->key.session_id);    
    }
}

static void
bbl_l2tp_cdn_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_session_t *l2tp_session) {
    bbl_ctx_s *ctx = interface->ctx;
    bbl_l2tp_tunnel_t *l2tp_tunnel = l2tp_session->tunnel;

    UNUSED(ctx);
    UNUSED(eth);
    UNUSED(l2tp);

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
bbl_l2tp_data_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface, bbl_l2tp_session_t *l2tp_session) {
    bbl_ctx_s *ctx = interface->ctx;

    bbl_lcp_t   *lcp_rx;
    bbl_pap_t   *pap_rx;
    bbl_pap_t    pap_tx;
    bbl_ipcp_t  *ipcp_rx;
    bbl_ipcp_t   ipcp_tx;
    bbl_ip6cp_t *ip6cp_rx;
    bbl_ip6cp_t  ip6cp_tx;

    UNUSED(ctx);
    UNUSED(eth);

    if(l2tp_session->state != BBL_L2TP_SESSION_ESTABLISHED) {
        return;
    }

    switch (l2tp->protocol) {
        case PROTOCOL_LCP:
            lcp_rx = (bbl_lcp_t*)l2tp->next;
            if(lcp_rx->code == PPP_CODE_TERM_REQUEST) {
                bbl_l2tp_send(l2tp_session->tunnel, l2tp_session, L2TP_MESSAGE_CDN);
                return bbl_l2tp_session_delete(l2tp_session);
            }
            if(lcp_rx->code == PPP_CODE_ECHO_REQUEST) {
                lcp_rx->code = PPP_CODE_ECHO_REPLY;
                bbl_l2tp_send_data(l2tp_session, PROTOCOL_LCP, lcp_rx);
            }
            break;
        case PROTOCOL_PAP:
            memset(&pap_tx, 0x0, sizeof(bbl_pap_t));
            pap_rx = (bbl_pap_t*)l2tp->next;
            pap_tx.code = PAP_CODE_ACK;
            pap_tx.identifier = pap_rx->identifier;
            bbl_l2tp_send_data(l2tp_session, PROTOCOL_PAP, &pap_tx);
            break;
        case PROTOCOL_IPCP:
            ipcp_rx = (bbl_ipcp_t*)l2tp->next;
            memset(&ipcp_tx, 0x0, sizeof(bbl_ipcp_t));
            if(ipcp_rx->code == PPP_CODE_CONF_REQUEST) {
                ipcp_rx->options = NULL;
                ipcp_rx->options_len = 0;
                if(ipcp_rx->address == L2TP_IPCP_IP_REMOTE) {
                    ipcp_rx->code = PPP_CODE_CONF_ACK;
                    if(l2tp_session->ipcp_state == BBL_PPP_LOCAL_ACK) {
                        l2tp_session->ipcp_state = BBL_PPP_OPENED;
                    } else {
                        l2tp_session->ipcp_state = BBL_PPP_PEER_ACK;
                        ipcp_tx.code = PPP_CODE_CONF_REQUEST;
                        ipcp_tx.identifier = 1;
                        ipcp_tx.address = L2TP_IPCP_IP_LOCAL;
                        ipcp_tx.option_address = true;
                        bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, &ipcp_tx);
                    }
                } else {
                    ipcp_rx->code = PPP_CODE_CONF_NAK;
                    ipcp_rx->address = L2TP_IPCP_IP_REMOTE;
                    ipcp_rx->option_address = true;
                    ipcp_rx->option_dns1 = false;
                    ipcp_rx->option_dns2 = false;
                }
                bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, ipcp_rx);
            } else if (ipcp_rx->code == PPP_CODE_CONF_ACK) {
                if(l2tp_session->ipcp_state == BBL_PPP_PEER_ACK) {
                    l2tp_session->ipcp_state = BBL_PPP_OPENED;
                } else {
                    l2tp_session->ipcp_state = BBL_PPP_LOCAL_ACK;
                    ipcp_tx.code = PPP_CODE_CONF_REQUEST;
                    ipcp_tx.identifier = 1;
                    ipcp_tx.address = L2TP_IPCP_IP_LOCAL;
                    ipcp_tx.option_address = true;
                    bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, &ipcp_tx);
                }
            }
            break;
        case PROTOCOL_IP6CP:
            ip6cp_rx = (bbl_ip6cp_t*)l2tp->next;
            memset(&ip6cp_tx, 0x0, sizeof(bbl_ip6cp_t));
            if(ip6cp_rx->code == PPP_CODE_CONF_REQUEST) {
                ip6cp_rx->code = PPP_CODE_CONF_ACK;
                if(l2tp_session->ip6cp_state == BBL_PPP_LOCAL_ACK) {
                    l2tp_session->ip6cp_state = BBL_PPP_OPENED;
                } else {
                    l2tp_session->ip6cp_state = BBL_PPP_PEER_ACK;
                    ip6cp_tx.code = PPP_CODE_CONF_REQUEST;
                    ip6cp_tx.identifier = 1;
                    ip6cp_tx.ipv6_identifier = 1;
                    bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, &ip6cp_tx);
                }
                bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, ip6cp_rx);
            } else if (ip6cp_rx->code == PPP_CODE_CONF_ACK) {
                if(l2tp_session->ip6cp_state == BBL_PPP_PEER_ACK) {
                    l2tp_session->ip6cp_state = BBL_PPP_OPENED;
                } else {
                    l2tp_session->ip6cp_state = BBL_PPP_LOCAL_ACK;
                    ip6cp_tx.code = PPP_CODE_CONF_REQUEST;
                    ip6cp_tx.identifier = 1;
                    ip6cp_tx.ipv6_identifier = 1;
                    bbl_l2tp_send_data(l2tp_session, PROTOCOL_IPCP, &ip6cp_tx);
                }
            }
            break;
        default:
            break;
    }

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

    l2tp_key_t key = {0};
    void **search = NULL;
    
    if(l2tp->type == L2TP_MESSAGE_SCCRQ) {
        return bbl_l2tp_sccrq_rx(eth, l2tp, interface);
    }

    key.tunnel_id = l2tp->tunnel_id;
    key.session_id = l2tp->session_id;
    search = dict_search(ctx->l2tp_session_dict, &key);
    if(search) {
        l2tp_session = *search;
        l2tp_tunnel = l2tp_session->tunnel;

        if(l2tp->type == L2TP_MESSAGE_DATA) {
            l2tp_tunnel->stats.data_rx++;
            interface->stats.l2tp_data_rx++;
            return bbl_l2tp_data_rx(eth, l2tp, interface, l2tp_session);
        }
        if (L2TP_SEQ_GT(l2tp->nr, l2tp_tunnel->peer_nr)) {
            l2tp_tunnel->peer_nr = l2tp->nr;
        }
        if (l2tp_tunnel->nr == l2tp->ns) {
            /* In-Order packet received */
            LOG(DEBUG, "L2TP Debug (%s) %s received from %s\n",
                       l2tp_tunnel->server->host_name, 
                       l2tp_message_string(l2tp->type), 
                       format_ipv4_address(&ipv4->src));

            /* Update tunnel */
            l2tp_tunnel->peer_ns = l2tp->ns;
            l2tp_tunnel->nr = (l2tp->ns + 1);
            if(l2tp->type != L2TP_MESSAGE_ZLB) {
                l2tp_tunnel->zlb = true;
            }
            if(l2tp_tunnel->cwnd < l2tp_tunnel->peer_receive_window) {
                l2tp_tunnel->cwnd++;
            }
            l2tp_tunnel->stats.control_rx++;
            interface->stats.l2tp_control_rx++;
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
                interface->stats.l2tp_control_rx_dup++;
                if(!l2tp_tunnel->timer_tx_active) {
                    timer_add(&ctx->timer_root, &l2tp_tunnel->timer_tx, "L2TP TX", 0, 10 * MSEC, l2tp_tunnel, bbl_l2tp_tunnel_tx_job);
                    l2tp_tunnel->timer_tx_active = true;
                }
            } else {
                /* Out-of-Order packet received */
                l2tp_tunnel->stats.control_rx_ooo++;
                interface->stats.l2tp_control_rx_ooo++;
            }
        }
    }
}

void
bbl_l2tp_stop_all_tunnel(bbl_ctx_s *ctx) {
    bbl_l2tp_server_t *l2tp_server = ctx->config.l2tp_server;
    bbl_l2tp_tunnel_t *l2tp_tunnel;
    while(l2tp_server) {
        CIRCLEQ_FOREACH(l2tp_tunnel, &l2tp_server->tunnel_qhead, tunnel_qnode) {
            if(l2tp_tunnel->state < BBL_L2TP_TUNNEL_SEND_STOPCCN) {
                l2tp_tunnel->state = BBL_L2TP_TUNNEL_SEND_STOPCCN;
                l2tp_tunnel->state_seconds = 0;
                bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
            }
        }
        l2tp_server = l2tp_server->next;
    }
}

uint16_t
bbl_l2tp_tunnel_count(bbl_ctx_s *ctx) {
    bbl_l2tp_server_t *l2tp_server = ctx->config.l2tp_server;
    bbl_l2tp_tunnel_t *l2tp_tunnel;
    uint16_t active = 0;

    while(l2tp_server) {
        CIRCLEQ_FOREACH(l2tp_tunnel, &l2tp_server->tunnel_qhead, tunnel_qnode) {
            active++;
        }
        l2tp_server = l2tp_server->next;
    }
    LOG(DEBUG, "TUNNEL %u\n", active); 
    return active;
}

