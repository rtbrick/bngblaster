/*
 * BNG Blaster (BBL) - LDP Session
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"
extern bool g_init_phase;
extern volatile bool g_teardown;

/* One listen socket is shared by all passive sessions, as they use the
 * same local address and port 646 stays in use by closed connections. */
static bbl_tcp_ctx_s *g_ldp_listen = NULL;

const char *
ldp_session_state_string(ldp_state_t state)
{
    switch(state) {
        case LDP_CLOSED: return "closed";
        case LDP_IDLE: return "idle";
        case LDP_LISTEN: return "listen";
        case LDP_CONNECT: return "connect";
        case LDP_INITIALIZED: return "initialized";
        case LDP_OPENREC: return "open-received";
        case LDP_OPENSENT: return "open-sent";
        case LDP_OPERATIONAL: return "operational";
        case LDP_CLOSING: return "closing";
        case LDP_ERROR: return "error";
        default: return "unknown";
    }
}

static void
ldp_session_state_change(ldp_session_s *session, ldp_state_t new_state)
{
    if(session->state != new_state) {
        if(session->state == LDP_OPERATIONAL || new_state == LDP_OPERATIONAL) {
            session->state_transitions++;
        }
        LOG(LDP, "LDP (%s - %s) state changed from %s -> %s\n",
            ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
            ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
            ldp_session_state_string(session->state),
            ldp_session_state_string(new_state));
        if(session->state == LDP_OPERATIONAL) {
            /* The label mappings learned from the session are
             * no longer valid if the session goes down. */
            ldb_db_withdraw_session(session, 0, true);
        }
        session->state = new_state;
    }
}

/**
 * ldp_session_reset_read_buffer
 * 
 * @param session LDP session
 */
void
ldp_session_reset_read_buffer(ldp_session_s *session)
{
    session->read_buf.idx = 0;
    session->read_buf.start_idx = 0;
}

/**
 * ldp_session_reset_write_buffer
 * 
 * @param session LDP session
 */
void
ldp_session_reset_write_buffer(ldp_session_s *session)
{
    if(session->tcpc && session->tcpc->state == BBL_TCP_STATE_SENDING) {
        return;
    }
    session->write_buf.idx = 0;
    session->write_buf.start_idx = 0;
}

/**
 * ldp_session_send
 * 
 * @param session LDP session
 */
static bool
ldp_session_send(ldp_session_s *session)
{
    bbl_tcp_ctx_s *tcpc = session->tcpc;
    if(tcpc && tcpc->state == BBL_TCP_STATE_SENDING && 
       tcpc->tx.buf == session->write_buf.data &&
       tcpc->tx.len < session->write_buf.idx) {
        tcpc->tx.len = session->write_buf.idx;
        return true;
    }
    return bbl_tcp_send(session->tcpc, session->write_buf.data, session->write_buf.idx);
}

void 
ldp_raw_update_stop_cb(void *arg)
{
    ldp_session_s *session = (ldp_session_s*)arg;
    struct timespec time_diff;

    session->tcpc->idle_cb = NULL;

    clock_gettime(CLOCK_MONOTONIC, &session->update_stop_timestamp);
    timespec_sub(&time_diff, 
                 &session->update_stop_timestamp, 
                 &session->update_start_timestamp);

    session->raw_update_sending = false;
    session->stats.pdu_tx += session->raw_update->pdu;
    session->stats.message_tx += session->raw_update->messages;
    
    LOG(LDP, "LDP (%s - %s) raw update stop after %lds\n",
        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
        time_diff.tv_sec);
}

void
ldp_session_update_job(timer_s *timer) 
{
    ldp_session_s *session = timer->data;

    if(session->state == LDP_OPERATIONAL) {
        if(session->raw_update && !session->raw_update_sending) {
            if(bbl_tcp_send(session->tcpc, session->raw_update->buf, session->raw_update->len)) {
                session->raw_update_sending = true;

                LOG(LDP, "LDP (%s - %s) raw update start\n",
                    ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                    ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));

                clock_gettime(CLOCK_MONOTONIC, &session->update_start_timestamp);
                session->tcpc->idle_cb = ldp_raw_update_stop_cb;
            } else {
                goto RETRY;
            }
        }
    }
    timer->periodic = false;
    return;

RETRY:
    /* Try again ... */
    timer_add_periodic(&g_ctx->timer_root, &session->connect_timer, 
                       "LDP UPDATE", 1, 0, session,
                       &ldp_session_update_job);

}

void
ldp_session_keepalive_job(timer_s *timer)
{
    ldp_session_s *session = timer->data;

    if(session->state == LDP_OPERATIONAL) {
        if(session->tcpc && session->tcpc->state == BBL_TCP_STATE_IDLE) {
            ldp_session_reset_write_buffer(session);
            ldp_pdu_init(session);
            ldp_push_keepalive_message(session);
            ldp_pdu_close(session);
            ldp_session_send(session);
        }
    }
}

void
ldp_session_keepalive_timeout_job(timer_s *timer)
{
    ldp_session_s *session = timer->data;

    LOG(LDP, "LDP (%s - %s) keepalive timer expired\n",
        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));

    if(!session->error_code) {
        session->error_code = LDP_STATUS_KEEPALIVE_TIMER_EXPIRED|LDP_STATUS_FATAL_ERROR;
    }
    ldp_session_close(session);
}

void
ldp_session_restart_keepalive_timeout(ldp_session_s *session)
{
    timer_add(&g_ctx->timer_root, &session->keepalive_timeout_timer, 
              "LDP TIMEOUT", session->keepalive_time, 0, session, &ldp_session_keepalive_timeout_job);
}

static void
ldp_session_operational(ldp_session_s *session)
{
    time_t keepalive_interval;

    ldp_session_state_change(session, LDP_OPERATIONAL);
    clock_gettime(CLOCK_MONOTONIC, &session->operational_timestamp);

    /* Select max PDU length. */
    if(session->peer.max_pdu_len > 255 && 
       session->peer.max_pdu_len < session->local.max_pdu_len) {
        session->max_pdu_len = session->peer.max_pdu_len;
    } else {
        session->max_pdu_len = session->local.max_pdu_len;
    }

    /* Start LDP keepalive. */
    if(session->peer.keepalive_time > 0 && 
       session->peer.keepalive_time < session->local.keepalive_time) {
        session->keepalive_time = session->peer.keepalive_time;
    } else {
        session->keepalive_time = session->local.keepalive_time;
    }
    keepalive_interval = session->keepalive_time/3U;
    if(!keepalive_interval) {
        keepalive_interval = 1;
    }

    timer_add_periodic(&g_ctx->timer_root, &session->keepalive_timer, 
                       "LDP KEEPALIVE", keepalive_interval, 0, session,
                       &ldp_session_keepalive_job);

    /* Start LDP updates. */
    timer_add(&g_ctx->timer_root, &session->update_timer, 
              "LDP UPDATE", 0, 0, session,
              &ldp_session_update_job);
}

void
ldp_session_fsm(ldp_session_s *session, ldp_event_t event)
{
    switch(event) {
        case LDP_EVENT_START:
            ldp_session_state_change(session, LDP_INITIALIZED);
            if(session->active) {
                ldp_session_reset_write_buffer(session);
                ldp_pdu_init(session);
                ldp_push_init_message(session);
                ldp_pdu_close(session);
                ldp_session_send(session);
                ldp_session_state_change(session, LDP_OPENSENT);
            }
            break;
        case LDP_EVENT_RX_INITIALIZED:
            if(session->state == LDP_INITIALIZED) {
                ldp_session_reset_write_buffer(session);
                ldp_pdu_init(session);
                ldp_push_init_message(session);
                ldp_push_keepalive_message(session);
                ldp_pdu_close(session);
                ldp_session_send(session);
                ldp_session_state_change(session, LDP_OPENREC);
            } else if(session->state == LDP_OPENSENT) {
                ldp_session_reset_write_buffer(session);
                ldp_pdu_init(session);
                ldp_push_keepalive_message(session);
                ldp_pdu_close(session);
                ldp_session_send(session);
                ldp_session_state_change(session, LDP_OPENREC);
            } else {
                if(!session->error_code) {
                    session->error_code = LDP_STATUS_INTERNAL_ERROR|LDP_STATUS_FATAL_ERROR;
                }
                ldp_session_close(session);
            }
            break;
        case LDP_EVENT_RX_KEEPALIVE:
            if(session->state == LDP_OPENREC) {
                ldp_session_operational(session);
                ldp_session_reset_write_buffer(session);
                ldp_pdu_init(session);
                ldp_push_self_message(session);
                ldp_pdu_close(session);
                ldp_session_send(session);
            }
            break;
        default:
            break;
    }
}

void 
ldp_connected_cb(void *arg)
{
    ldp_session_s *session = (ldp_session_s*)arg;
    if(!session->counted) {
        session->counted = true;
        g_ctx->routing_sessions++;
    }
    ldp_session_fsm(session, LDP_EVENT_START);
}

void 
ldp_error_cb(void *arg, err_t err) {
    ldp_session_s *session = (ldp_session_s*)arg;

    LOG(LDP, "LDP (%s - %s) TCP error %d (%s)\n",
        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
        err, tcp_err_string(err));

    ldp_session_state_change(session, LDP_ERROR);
    ldp_session_close(session);
}

void
ldp_session_connect_job(timer_s *timer)
{
    ldp_session_s *session = timer->data;
    time_t timeout = 5;

    if(g_init_phase) {
        /* Wait for all network interfaces to be resolved */
        timeout = 1;
    } else if(session->state == LDP_IDLE) {
        /* Connect TCP session */
        if(session->ipv6) {
            session->tcpc = bbl_tcp_ipv6_connect(
                session->interface,
                &session->local.ipv6_address,
                &session->peer.ipv6_address,
                LDP_PORT,
                0, session->instance->config->tos, NULL);
        } else {
            session->tcpc = bbl_tcp_ipv4_connect(
                session->interface,
                &session->local.ipv4_address,
                &session->peer.ipv4_address,
                LDP_PORT,
                0, session->instance->config->tos, NULL);
        }

        if(session->tcpc) {
            session->tcpc->arg = session;
            session->tcpc->connected_cb = ldp_connected_cb;
            session->tcpc->receive_cb = ldp_receive_cb;
            session->tcpc->error_cb = ldp_error_cb;
            ldp_session_state_change(session, LDP_CONNECT);
            /* Close session if not established within 60 seconds */
            timeout = 60; 
        } else {
            LOG(LDP, "LDP (%s - %s) TCP connect failed\n", 
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
        }
    } else if(session->state == LDP_OPERATIONAL) {
        timer->periodic = false;
        return;
    } else {
        LOG(LDP, "LDP (%s - %s) connect timeout\n", 
            ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
            ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));

        ldp_session_close(session);
        timer->periodic = false;
        return;
    }

    timer_add_periodic(&g_ctx->timer_root, &session->connect_timer, 
                       "LDP CONNECT", timeout, 0, session,
                       &ldp_session_connect_job);
}

/**
 * ldp_session_find_listen
 *
 * @param local local address of the connection
 * @param remote remote address of the connection
 * @return passive session waiting for this connection or NULL
 */
static ldp_session_s *
ldp_session_find_listen(const ip_addr_t *local, const ip_addr_t *remote)
{
    ldp_instance_s *instance = g_ctx->ldp_instances;
    ldp_session_s *session;
    bool ipv6 = IP_IS_V6_VAL(*remote);

    while(instance) {
        session = instance->sessions;
        while(session) {
            if(session->state == LDP_LISTEN && session->ipv6 == ipv6) {
                if(ipv6) {
                    if(memcmp(&session->local.ipv6_address, &local->u_addr.ip6.addr, IPV6_ADDR_LEN) == 0 &&
                       memcmp(&session->peer.ipv6_address, &remote->u_addr.ip6.addr, IPV6_ADDR_LEN) == 0) {
                        return session;
                    }
                } else if(session->local.ipv4_address == local->u_addr.ip4.addr &&
                          session->peer.ipv4_address == remote->u_addr.ip4.addr) {
                    return session;
                }
            }
            session = session->next;
        }
        instance = instance->next;
    }
    return NULL;
}

static bool
ldp_pre_accept_cb(struct tcp_pcb *new_pcb, void *arg)
{
    ldp_session_s *session = ldp_session_find_listen(&new_pcb->local_ip, &new_pcb->remote_ip);

    UNUSED(arg);

    if(!session) {
        return false;
    }
    tcp_bind_netif(new_pcb, &session->interface->netif);
    new_pcb->tos = session->instance->config->tos;
    return true;
}

err_t
ldp_accepted_cb(bbl_tcp_ctx_s *tcpc, void *arg)
{
    ldp_session_s *session = ldp_session_find_listen(&tcpc->pcb->local_ip, &tcpc->pcb->remote_ip);

    UNUSED(arg);

    if(!session) {
        return ERR_ABRT;
    }
    session->tcpc = tcpc;
    tcpc->arg = session;
    tcpc->connected_cb = ldp_connected_cb;
    tcpc->receive_cb = ldp_receive_cb;
    tcpc->error_cb = ldp_error_cb;
    return ERR_OK;
}

static void
ldp_session_listen(ldp_session_s *session);

static void
ldp_session_listen_job(timer_s *timer)
{
    ldp_session_s *session = timer->data;

    if(!session->teardown && session->state == LDP_CLOSED) {
        ldp_session_listen(session);
    }
}

static void
ldp_session_listen(ldp_session_s *session)
{
    if(!g_ldp_listen) {
        g_ldp_listen = bbl_tcp_listen_any(LDP_PORT);
        if(g_ldp_listen) {
            g_ldp_listen->pre_accept_cb = ldp_pre_accept_cb;
            g_ldp_listen->accepted_cb = ldp_accepted_cb;
        }
    }

    if(g_ldp_listen) {
        ldp_session_state_change(session, LDP_LISTEN);
        timer_add_periodic(&g_ctx->timer_root, &session->connect_timer, 
                           "LDP CONNECT", 60, 0, session,
                           &ldp_session_connect_job);
    } else {
        LOG(LDP, "LDP (%s - %s) TCP listen failed\n", 
            ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
            ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
        timer_add(&g_ctx->timer_root, &session->connect_timer, 
                  "LDP LISTEN", 5, 0, session,
                  &ldp_session_listen_job);
    }
}

/**
 * ldp_session_listen_teardown
 *
 * Close and free the LDP listen socket.
 */
void
ldp_session_listen_teardown(void)
{
    bbl_tcp_ctx_free(g_ldp_listen);
    g_ldp_listen = NULL;
}

/**
 * ldp_session_connect
 * 
 * @param session BGP session
 * @param delay delay
 */
void
ldp_session_connect(ldp_session_s *session, time_t delay)
{
    if(!session->teardown && session->state == LDP_CLOSED) {
        bbl_tcp_ctx_free(session->tcpc);
        session->tcpc = NULL;

        ldp_session_reset_read_buffer(session);
        ldp_session_reset_write_buffer(session);

        session->pdu_start_idx = 0;
        session->msg_start_idx = 0;
        session->tlv_start_idx = 0;
        session->message_id = 0;
        session->error_code = 0;
        session->decode_error = false;
        session->max_pdu_len = LDP_MAX_PDU_LEN_INIT;
        session->keepalive_time = session->local.keepalive_time;

        session->stats.pdu_rx = 0;
        session->stats.pdu_tx = 0;
        session->stats.message_rx = 0;
        session->stats.message_tx = 0;
        session->stats.keepalive_rx = 0;
        session->stats.keepalive_tx = 0;

        session->raw_update = session->raw_update_start;
        session->raw_update_sending = false;

        session->operational_timestamp.tv_sec = 0;
        session->operational_timestamp.tv_nsec = 0;
        session->update_start_timestamp.tv_sec = 0;
        session->update_start_timestamp.tv_nsec = 0;
        session->update_stop_timestamp.tv_sec = 0;
        session->update_stop_timestamp.tv_nsec = 0;

        if(session->active) {
            ldp_session_state_change(session, LDP_IDLE);
            timer_add(&g_ctx->timer_root, &session->connect_timer, 
                      "LDP CONNECT", delay, 0, session,
                      &ldp_session_connect_job);
        } else {
            ldp_session_listen(session);
        }
    }
}

int
ldp_session_key_compare(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof(ldp_session_key_s));
}

uint32_t
ldp_session_key_hash(const void *k)
{
    const uint8_t *key = k;
    uint32_t hash = 2166136261U;
    size_t i;

    /* FNV-1a */
    for(i = 0; i < sizeof(ldp_session_key_s); i++) {
        hash ^= key[i];
        hash *= 16777619U;
    }
    return hash;
}

static ldp_session_s *
ldp_session_find_key(ldp_session_key_s *key)
{
    void **search = dict_search(g_ctx->ldp_session_dict, key);
    if(search) {
        return *search;
    }
    return NULL;
}

ldp_session_s *
ldp_session_find_ipv4(ipv4addr_t local_address, ipv4addr_t peer_address)
{
    ldp_session_key_s key = {0};

    key.af = AF_INET;
    memcpy(key.local_address, &local_address, sizeof(ipv4addr_t));
    memcpy(key.peer_address, &peer_address, sizeof(ipv4addr_t));
    return ldp_session_find_key(&key);
}

ldp_session_s *
ldp_session_find_ipv6(ipv6addr_t *local_address, ipv6addr_t *peer_address)
{
    ldp_session_key_s key;

    key.af = AF_INET6;
    memcpy(key.local_address, local_address, IPV6_ADDR_LEN);
    memcpy(key.peer_address, peer_address, IPV6_ADDR_LEN);
    return ldp_session_find_key(&key);
}

/**
 * ldp_session_index
 *
 * Add the session with its current addresses to the hashtable searched
 * for received TCP packets. The peer address can change if the session
 * is reused. If several sessions have the same addresses, the first one
 * is found as before with the session list.
 *
 * @param session LDP session
 */
static void
ldp_session_index(ldp_session_s *session)
{
    ldp_session_key_s key = {0};
    dict_insert_result result;
    void **search;

    if(session->ipv6) {
        key.af = AF_INET6;
        memcpy(key.local_address, &session->local.ipv6_address, IPV6_ADDR_LEN);
        memcpy(key.peer_address, &session->peer.ipv6_address, IPV6_ADDR_LEN);
    } else {
        key.af = AF_INET;
        memcpy(key.local_address, &session->local.ipv4_address, sizeof(ipv4addr_t));
        memcpy(key.peer_address, &session->peer.ipv4_address, sizeof(ipv4addr_t));
    }
    if(session->indexed) {
        if(memcmp(&key, &session->key, sizeof(key)) == 0) {
            return;
        }
        search = dict_search(g_ctx->ldp_session_dict, &session->key);
        if(search && *search == session) {
            dict_remove(g_ctx->ldp_session_dict, &session->key);
        }
        session->indexed = false;
    }
    session->key = key;
    result = dict_insert(g_ctx->ldp_session_dict, &session->key);
    if(result.inserted) {
        *result.datum_ptr = session;
        session->indexed = true;
    }
}

/**
 * ldp_session_ipv4_init
 * 
 * @param session LDP session (optional)
 * @param adjacency LDP adjacency
 * @param ipv4 received IPv4 header
 * @param ldp received LDP hello PDU
 */
void
ldp_session_ipv4_init(ldp_session_s *session, ldp_adjacency_s *adjacency,
                 bbl_ipv4_s *ipv4, bbl_ldp_hello_s *ldp)
{
    ldp_instance_s *instance = adjacency->instance;
    ldp_config_s *config = instance->config;

    if(!session) {
        session = calloc(1, sizeof(ldp_session_s));
        session->instance = instance;
        session->local.ipv4_address = config->ipv4_transport_address;
        session->local.lsr_id = config->lsr_id;
        session->local.label_space_id = 0;
        session->local.keepalive_time = config->keepalive_time;
        session->local.max_pdu_len = LDP_MAX_PDU_LEN_INIT;
        if(config->raw_update_file) {
            session->raw_update_start = ldp_raw_update_load(config->raw_update_file, true);
        }
        session->next = instance->sessions;
        instance->sessions = session;
    }
    session->interface = adjacency->interface;
    session->max_pdu_len = session->local.max_pdu_len;
    session->keepalive_time = session->local.keepalive_time;
    session->teardown = instance->teardown;
    session->wait_hello = false;

    if(ldp->ipv4_transport_address) {
        session->peer.ipv4_address = ldp->ipv4_transport_address;
    } else {
        session->peer.ipv4_address = ipv4->src;
    }
    session->peer.lsr_id = ldp->lsr_id;
    session->peer.label_space_id = ldp->label_space_id;
    ldp_session_index(session);
    session->peer.keepalive_time = 0;
    session->peer.max_pdu_len = 0;

    /* Init read/write buffer, which are kept if the session is reused. */
    if(!session->read_buf.data) {
        session->read_buf.data = malloc(LDP_BUF_SIZE);
        session->read_buf.size = LDP_BUF_SIZE;
    }
    if(!session->write_buf.data) {
        session->write_buf.data = malloc(LDP_BUF_SIZE);
        session->write_buf.size = LDP_BUF_SIZE;
    }

    if(be32toh(session->local.ipv4_address) > be32toh(session->peer.ipv4_address)) {
        session->active = true;
    } else {
        session->active = false;
    }

    ldp_session_hello(session, adjacency->hold_time);
    ldp_session_connect(session, 0);
}

/**
 * ldp_session_ipv4_init
 * 
 * @param session LDP session (optional)
 * @param adjacency LDP adjacency
 * @param ipv6 received IPv6 header
 * @param ldp received LDP hello PDU
 */
void
ldp_session_ipv6_init(ldp_session_s *session, ldp_adjacency_s *adjacency,
                      bbl_ipv6_s *ipv6, bbl_ldp_hello_s *ldp)
{
    ldp_instance_s *instance = adjacency->instance;
    ldp_config_s *config = instance->config;

    if(!session) {
        session = calloc(1, sizeof(ldp_session_s));
        session->instance = instance;
        session->ipv6 = true;
        memcpy(&session->local.ipv6_address, &config->ipv6_transport_address, sizeof(ipv6addr_t));
        session->local.lsr_id = config->lsr_id;
        session->local.label_space_id = 0;
        session->local.keepalive_time = config->keepalive_time;
        session->local.max_pdu_len = LDP_MAX_PDU_LEN_INIT;
        if(config->raw_update_file) {
            session->raw_update_start = ldp_raw_update_load(config->raw_update_file, true);
        }
        session->next = instance->sessions;
        instance->sessions = session;
    }
    session->interface = adjacency->interface;
    session->max_pdu_len = session->local.max_pdu_len;
    session->keepalive_time = session->local.keepalive_time;
    session->teardown = instance->teardown;
    session->wait_hello = false;

    if(ldp->ipv6_transport_address) {
        memcpy(&session->peer.ipv6_address, ldp->ipv6_transport_address, sizeof(ipv6addr_t));
    } else {
        memcpy(&session->peer.ipv6_address, ipv6->src, sizeof(ipv6addr_t));
    }
    session->peer.lsr_id = ldp->lsr_id;
    session->peer.label_space_id = ldp->label_space_id;
    ldp_session_index(session);
    session->peer.keepalive_time = 0;
    session->peer.max_pdu_len = 0;

    /* Init read/write buffer, which are kept if the session is reused. */
    if(!session->read_buf.data) {
        session->read_buf.data = malloc(LDP_BUF_SIZE);
        session->read_buf.size = LDP_BUF_SIZE;
    }
    if(!session->write_buf.data) {
        session->write_buf.data = malloc(LDP_BUF_SIZE);
        session->write_buf.size = LDP_BUF_SIZE;
    }

    if(memcmp(&session->local.ipv6_address, &session->peer.ipv6_address, sizeof(ipv6addr_t)) > 0) {
        session->active = true;
    } else {
        session->active = false;
    }

    ldp_session_hello(session, adjacency->hold_time);
    ldp_session_connect(session, 0);
}

void
ldp_session_close_job(timer_s *timer)
{
    ldp_session_closed(timer->data);
}

/**
 * ldp_session_closed
 *
 * Close the TCP session and change state to closed.
 *
 * @param session LDP session
 */
void
ldp_session_closed(ldp_session_s *session)
{
    timer_del(session->close_timer);

    /* Only sessions counted when connected are uncounted. */
    if(session->counted) {
        session->counted = false;
        if(g_ctx->routing_sessions) g_ctx->routing_sessions--;
    }
    timer_del(session->keepalive_timeout_timer);

    /* Close TCP session */
    if(session->state > LDP_IDLE) {
        bbl_tcp_ctx_free(session->tcpc);
        session->tcpc = NULL;
    }
    ldp_session_state_change(session, LDP_CLOSED);
    if(!(session->teardown || session->wait_hello)) {
        ldp_session_connect(session, 5);
    }
}

static void
ldp_session_close_internal(ldp_session_s *session, bool notification)
{
    time_t delay = 0;

    LOG(LDP, "LDP (%s - %s) close session\n",
        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));

    /* Stop all timers */
    timer_del(session->connect_timer);
    timer_del(session->keepalive_timer);
    timer_del(session->keepalive_timeout_timer);
    timer_del(session->update_timer);

    if(!session->error_code) {
        session->error_code = LDP_STATUS_SHUTDOWN|LDP_STATUS_FATAL_ERROR;
    }

    if(session->state > LDP_CONNECT && session->state < LDP_CLOSING) {
        delay = 3;
        if(notification) {
            LOG(LDP, "LDP (%s - %s) send notification message\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));

            ldp_session_reset_write_buffer(session);
            ldp_pdu_init(session);
            ldp_push_notification_message(session);
            ldp_pdu_close(session);
            if(!ldp_session_send(session)) {
                /* E.g. while a RAW update is sent, the TCP
                 * session is closed without notification. */
                LOG(LDP, "LDP (%s - %s) failed to send notification message\n",
                    ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                    ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
                delay = 0;
            }
        } else {
            delay = 0;
        }
        ldp_session_state_change(session, LDP_CLOSING);
    }

    timer_add(&g_ctx->timer_root, &session->close_timer, 
              "LDP CLOSE", delay, 0, session,
              &ldp_session_close_job);
}

/**
 * ldp_session_close
 * 
 * Close the session with notification.
 *
 * @param session LDP session
 */
void
ldp_session_close(ldp_session_s *session)
{
    ldp_session_close_internal(session, true);
}

/**
 * ldp_session_close_received
 * 
 * Close the session without notification after
 * a fatal error notification was received.
 *
 * @param session LDP session
 */
void
ldp_session_close_received(ldp_session_s *session)
{
    ldp_session_close_internal(session, false);
}

static void
ldp_session_hello_timeout_job(timer_s *timer)
{
    ldp_session_s *session = timer->data;

    if(session->state == LDP_CLOSED || session->teardown) {
        return;
    }
    LOG(LDP, "LDP (%s - %s) hello adjacency lost\n",
        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));

    /* The session is terminated if the last hello adjacency is lost
     * (RFC 5036 section 2.5.5) and initialised again by the next hello. */
    session->wait_hello = true;
    if(session->state == LDP_CLOSING) {
        return;
    }
    if(!session->error_code) {
        session->error_code = LDP_STATUS_HOLD_TIMER_EXPIRED|LDP_STATUS_FATAL_ERROR;
    }
    ldp_session_close(session);
}

/**
 * ldp_session_hello
 *
 * Restart the hello hold timer of the session with a hello
 * of any adjacency (link or targeted) received from the peer.
 *
 * @param session LDP session
 * @param hold_time hold time of the adjacency
 */
void
ldp_session_hello(ldp_session_s *session, uint16_t hold_time)
{
    timer_add(&g_ctx->timer_root, &session->hello_hold_timer,
              "LDP HELLO HOLD", hold_time, 0, session,
              &ldp_session_hello_timeout_job);
}