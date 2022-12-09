/*
 * BNG Blaster (BBL) - LDP Session
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"
extern bool g_init_phase;
extern volatile bool g_teardown;

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
        LOG(LDP, "LDP (%s:%u - %s:%u) state changed from %s -> %s\n",
            format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
            format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id,
            ldp_session_state_string(session->state),
            ldp_session_state_string(new_state));
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
    
    LOG(LDP, "LDP (%s:%u - %s:%u) raw update stop after %lds\n",
        format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
        format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id,
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

                LOG(LDP, "LDP (%s:%u - %s:%u) raw update start\n",
                    format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
                    format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id);

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
            ldp_push_keepalive_message(session);
            if(ldp_session_send(session)) {
                session->stats.pdu_tx++;
                session->stats.message_tx++;
                session->stats.keepalive_tx++;
            }
        }
    }
}

void
ldp_session_keepalive_timeout_job(timer_s *timer)
{
    ldp_session_s *session = timer->data;

    LOG(LDP, "LDP (%s:%u - %s:%u) keepalive timer expired\n",
        format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
        format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id);

    if(!session->error_code) {
        session->error_code = LDP_STATUS_KEEPALIVE_TIMER_EXPIRED;
    }
    ldp_session_close(session);
}

static void
ldp_session_restart_keepalive_timeout(ldp_session_s *session)
{
    timer_add(&g_ctx->timer_root, &session->keepalive_timer, 
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

    /* Start LDP keepalive */
    if(session->peer.keepalive_time > 0 && 
       session->peer.keepalive_time < session->local.keepalive_time) {
        session->keepalive_time = session->peer.keepalive_time;
    } else {
        session->keepalive_time = session->local.keepalive_time;
    }
    keepalive_interval = session->keepalive_time/2U;
    if(!keepalive_interval) {
        keepalive_interval = 1;
    }

    timer_add_periodic(&g_ctx->timer_root, &session->keepalive_timer, 
                       "LDP KEEPALIVE", keepalive_interval, 0, session,
                       &ldp_session_keepalive_job);

    /* Start LDP updates */
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
                ldp_push_init_message(session, false);
                ldp_session_send(session);
                session->stats.pdu_tx++;
                session->stats.message_tx++;
                ldp_session_state_change(session, LDP_OPENSENT);
            }
            break;
        case LDP_EVENT_RX_INITIALIZED:
            if(session->state == LDP_INITIALIZED) {
                ldp_session_reset_write_buffer(session);
                ldp_push_init_message(session, true);
                ldp_session_send(session);
                session->stats.pdu_tx++;
                session->stats.message_tx++;
                ldp_session_state_change(session, LDP_OPENREC);
            } else if(session->state == LDP_OPENSENT) {
                ldp_session_reset_write_buffer(session);
                ldp_push_keepalive_message(session);
                ldp_session_send(session);
                session->stats.pdu_tx++;
                session->stats.message_tx++;
                ldp_session_state_change(session, LDP_OPENREC);
            } else {
                if(!session->error_code) {
                    session->error_code = LDP_STATUS_INTERNAL_ERROR;
                }
                ldp_session_close(session);
            }
            break;
        case LDP_EVENT_RX_KEEPALIVE:
            if(session->state == LDP_OPENREC) {
                ldp_session_operational(session);
            }
            ldp_session_restart_keepalive_timeout(session);
            break;
        default:
            break;
    }
}

void 
ldp_connected_cb(void *arg)
{
    ldp_session_s *session = (ldp_session_s*)arg;
    ldp_session_fsm(session, LDP_EVENT_START);
}

void 
ldp_error_cb(void *arg, err_t err) {
    ldp_session_s *session = (ldp_session_s*)arg;

    LOG(LDP, "LDP (%s:%u - %s:%u) TCP error %d (%s)\n",
        format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
        format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id,
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
        session->tcpc = bbl_tcp_ipv4_connect(
            session->interface,
            &session->local.ipv4_address,
            &session->peer.ipv4_address,
            LDP_PORT);

        if(session->tcpc) {
            session->tcpc->arg = session;
            session->tcpc->connected_cb = ldp_connected_cb;
            session->tcpc->receive_cb = ldp_receive_cb;
            session->tcpc->error_cb = ldp_error_cb;
            ldp_session_state_change(session, LDP_CONNECT);
            /* Close session if not established within 60 seconds */
            timeout = 60; 
        } else {
            LOG(LDP, "LDP (%s:%u - %s:%u) TCP connect failed\n", 
                format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
                format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id);
        }
    } else if(session->state == LDP_OPERATIONAL) {
        timer->periodic = false;
        return;
    } else {
        LOG(LDP, "LDP (%s:%u - %s:%u) connect timeout\n", 
            format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
            format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id);

        ldp_session_close(session);
        timer->periodic = false;
        return;
    }

    timer_add_periodic(&g_ctx->timer_root, &session->connect_timer, 
                       "LDP CONNECT", timeout, 0, session,
                       &ldp_session_connect_job);
}

static void
ldp_session_listen(ldp_session_s *session)
{
    session->tcpc = bbl_tcp_ipv4_listen(
        session->interface,
        &session->local.ipv4_address,
        LDP_PORT);

    if(session->tcpc) {
        session->tcpc->arg = session;
        session->tcpc->connected_cb = ldp_connected_cb;
        session->tcpc->receive_cb = ldp_receive_cb;
        session->tcpc->error_cb = ldp_error_cb;

        ldp_session_state_change(session, LDP_LISTEN);
        timer_add_periodic(&g_ctx->timer_root, &session->connect_timer, 
                           "LDP CONNECT", 60, 0, session,
                           &ldp_session_connect_job);
    } else {
        LOG(LDP, "LDP (%s:%u - %s:%u) TCP listen failed\n", 
            format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
            format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id);
        ldp_session_close(session);
    }
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

/**
 * ldp_session_init
 * 
 * @param session LDP session (optional)
 * @param adjacency LDP adjacency
 * @param ipv4 received IPv4 header
 * @param ldp received LDP hello PDU
 */
void
ldp_session_init(ldp_session_s *session, ldp_adjacency_s *adjacency,
                 bbl_ipv4_s *ipv4, bbl_ldp_hello_s *ldp)
{
    ldp_instance_s *instance = adjacency->instance;
    ldp_config_s *config = instance->config;

    if(!session) {
        session = calloc(1, sizeof(ldp_session_s));
        session->next = instance->sessions;
        instance->sessions = session;
        session->local.ipv4_address = config->ipv4_transport_address;
        session->local.lsr_id = config->lsr_id;
        session->local.label_space_id = 0;
        session->local.keepalive_time = config->keepalive_interval;
        session->local.max_pdu_len = LDP_MAX_PDU_LEN_INIT;
    }
    session->interface = adjacency->interface;
    session->max_pdu_len = session->local.max_pdu_len;
    session->keepalive_time = session->local.keepalive_time;

    if(ldp->ipv4_transport_address) {
        session->peer.ipv4_address = ldp->ipv4_transport_address;
    } else {
        session->peer.ipv4_address = ipv4->src;
    }
    session->peer.lsr_id = ldp->lsr_id;
    session->peer.label_space_id = ldp->label_space_id;
    session->peer.keepalive_time = 0;
    session->peer.max_pdu_len = 0;

    if(be32toh(session->local.ipv4_address) > be32toh(session->peer.ipv4_address)) {
        session->active = true;
    } else {
        session->active = false;
    }

    ldp_session_connect(session, 0);
}

void
ldp_session_close_job(timer_s *timer)
{
    ldp_session_s *session = timer->data;
    if(session->state > LDP_IDLE) {
        /* Close TCP session */
        bbl_tcp_close(session->tcpc);
    }
    ldp_session_state_change(session, LDP_CLOSED);
    if(!session->teardown) {
        ldp_session_connect(session, 5);
    }
}

/**
 * ldp_session_close
 * 
 * @param session LDP session
 */
void
ldp_session_close(ldp_session_s *session)
{
    time_t delay = 0;

    /* Stop all timers */
    timer_del(session->connect_timer);
    timer_del(session->keepalive_timer);
    timer_del(session->update_timer);

    if(!session->error_code) {
        session->error_code = LDP_STATUS_SHUTDOWN;
    }

    if(session->state > LDP_CONNECT && session->state < LDP_CLOSING) {
        LOG(LDP, "LDP (%s:%u - %s:%u) send notification message\n",
            format_ipv4_address(&session->local.lsr_id), session->local.label_space_id,
            format_ipv4_address(&session->peer.lsr_id), session->peer.label_space_id);

        ldp_session_reset_write_buffer(session);
        ldp_push_notification_message(session);
        ldp_session_send(session);
        session->stats.pdu_tx++;
        session->stats.message_tx++;
        ldp_session_state_change(session, LDP_CLOSING);
        delay = 3;
    }

    timer_add(&g_ctx->timer_root, &session->close_timer, 
              "LDP CLOSE", delay, 0, session,
              &ldp_session_close_job);
}


