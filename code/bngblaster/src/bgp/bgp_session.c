/*
 * BNG Blaster (BBL) - BGP Session Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"
extern bool g_init_phase;
extern volatile bool g_teardown;

const char *
bgp_session_state_string(bgp_state_t state)
{
    switch(state) {
        case BGP_CLOSED: return "closed";
        case BGP_IDLE: return "idle";
        case BGP_CONNECT: return "connect";
        case BGP_ACTIVE: return "active";
        case BGP_OPENSENT: return "opensent";
        case BGP_OPENCONFIRM: return "openconfirm";
        case BGP_ESTABLISHED: return "established";
        case BGP_CLOSING: return "closing";
        default: return "unknown";
    }
}

/**
 * bgp_session_reset_read_buffer
 * 
 * @param session BGP session
 */
void
bgp_session_reset_read_buffer(bgp_session_s *session)
{
    session->read_buf.idx = 0;
    session->read_buf.start_idx = 0;
}

/**
 * bgp_session_reset_write_buffer
 * 
 * @param session BGP session
 */
void
bgp_session_reset_write_buffer(bgp_session_s *session)
{
    if(session->tcpc && session->tcpc->state == BBL_TCP_STATE_SENDING) {
        return;
    }
    session->write_buf.idx = 0;
    session->write_buf.start_idx = 0;
}

/**
 * bgp_session_send
 * 
 * @param session BGP session
 */
static bool
bgp_session_send(bgp_session_s *session)
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
bgp_session_keepalive_job(timer_s *timer)
{
    bgp_session_s *session = timer->data;

    if(session->state == BGP_ESTABLISHED) {
        if(session->tcpc && session->tcpc->state == BBL_TCP_STATE_IDLE) {
            bgp_session_reset_write_buffer(session);
            bgp_push_keepalive_message(session);
            if(bgp_session_send(session)) {
                session->stats.message_tx++;
                session->stats.keepalive_tx++;
            }
        }
    }
}

void 
bgp_raw_update_stop_cb(void *arg)
{
    bgp_session_s *session = (bgp_session_s*)arg;
    struct timespec time_diff;

    session->tcpc->idle_cb = NULL;

    clock_gettime(CLOCK_MONOTONIC, &session->update_stop_timestamp);
    timespec_sub(&time_diff, 
                 &session->update_stop_timestamp, 
                 &session->update_start_timestamp);

    session->raw_update_sending = false;
    session->stats.message_tx += session->raw_update->updates;
    session->stats.update_tx += session->raw_update->updates;
    
    LOG(BGP, "BGP (%s %s - %s) raw update stop after %lds\n",
        session->interface->name,
        format_ipv4_address(&session->ipv4_local_address),
        format_ipv4_address(&session->ipv4_peer_address),
        time_diff.tv_sec);

    if(session->config->start_traffic) {
        enable_disable_traffic(true);
    }
}

void
bgp_session_update_job(timer_s *timer) 
{
    bgp_session_s *session = timer->data;

    if(session->state == BGP_ESTABLISHED) {
        if(session->raw_update && !session->raw_update_sending) {
            if(bbl_tcp_send(session->tcpc, session->raw_update->buf, session->raw_update->len)) {
                session->raw_update_sending = true;

                LOG(BGP, "BGP (%s %s - %s) raw update start\n",
                    session->interface->name,
                    format_ipv4_address(&session->ipv4_local_address),
                    format_ipv4_address(&session->ipv4_peer_address));

                clock_gettime(CLOCK_MONOTONIC, &session->update_start_timestamp);
                session->tcpc->idle_cb = bgp_raw_update_stop_cb;
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
                       "BGP UPDATE", 1, 0, session,
                       &bgp_session_update_job);

}

static void
bgp_session_state_opensent(bgp_session_s *session)
{
    bgp_session_reset_write_buffer(session);
    bgp_push_open_message(session);
    bgp_session_send(session);
    session->stats.message_tx++;
}

static void
bgp_session_state_openconfirm(bgp_session_s *session)
{
    bgp_session_reset_write_buffer(session);
    bgp_push_keepalive_message(session);
    bgp_session_send(session);
    session->stats.message_tx++;
    session->stats.keepalive_tx++;
}

static void
bgp_session_state_established(bgp_session_s *session)
{
    time_t keepalive_interval;

    clock_gettime(CLOCK_MONOTONIC, &session->established_timestamp);

    /* Start BGP keepalive */
    if(session->peer.holdtime < session->config->holdtime) {
        keepalive_interval = session->peer.holdtime/2U;
    } else {
        keepalive_interval = session->config->holdtime/2U;
    }
    if(!keepalive_interval) {
        keepalive_interval = 1;
    }

    timer_add_periodic(&g_ctx->timer_root, &session->keepalive_timer, 
                       "BGP KEEPALIVE", keepalive_interval, 0, session,
                       &bgp_session_keepalive_job);

    /* Start BGP updates */
    timer_add(&g_ctx->timer_root, &session->update_timer, 
              "BGP UPDATE", 0, 0, session,
              &bgp_session_update_job);
}

/**
 * bgp_session_state_change
 * 
 * @param session BGP session
 */
void
bgp_session_state_change(bgp_session_s *session, bgp_state_t new_state)
{
    if(session->state == new_state) {
        return;
    }

    LOG(BGP, "BGP (%s %s - %s) state changed from %s -> %s\n",
        session->interface->name,
        format_ipv4_address(&session->ipv4_local_address),
        format_ipv4_address(&session->ipv4_peer_address),
        bgp_session_state_string(session->state),
        bgp_session_state_string(new_state));

    session->state = new_state;

    switch (new_state) {
        case BGP_OPENSENT:
            bgp_session_state_opensent(session);
            break;
        case BGP_OPENCONFIRM:
            bgp_session_state_openconfirm(session);
            break;
        case BGP_ESTABLISHED:
            bgp_session_state_established(session);
            break;
        default:
            break;
    }
}

void 
bgp_connected_cb(void *arg)
{
    bgp_session_s *session = (bgp_session_s*)arg;
    bgp_session_state_change(session, BGP_OPENSENT);
}

void 
bgp_error_cb(void *arg, err_t err) {
    bgp_session_s *session = (bgp_session_s*)arg;

    LOG(BGP, "BGP (%s %s - %s) TCP error %d (%s)\n",
        session->interface->name,
        format_ipv4_address(&session->ipv4_local_address),
        format_ipv4_address(&session->ipv4_peer_address),
        err, tcp_err_string(err));

    session->error_code = 0;
    bgp_session_close(session);
}

void
bgp_session_connect_job(timer_s *timer)
{
    bgp_session_s *session = timer->data;
    time_t timeout = 5;

    if(g_init_phase) {
        /* Wait for all network interfaces to be resolved */
        timeout = 1;
    } else if(session->state == BGP_IDLE) {
        /* Connect TCP session */
        session->tcpc = bbl_tcp_ipv4_connect(
            session->interface, 
            &session->ipv4_local_address,
            &session->ipv4_peer_address,
            BGP_PORT);

        if(session->tcpc) {
            session->tcpc->arg = session;
            session->tcpc->connected_cb = bgp_connected_cb;
            session->tcpc->receive_cb = bgp_receive_cb;
            session->tcpc->error_cb = bgp_error_cb;
            bgp_session_state_change(session, BGP_CONNECT);
            /* Close session if not established within 60 seconds */
            timeout = 60; 
        } else {
            LOG(BGP, "BGP (%s %s - %s) TCP connect failed\n", 
                session->interface->name,
                format_ipv4_address(&session->ipv4_local_address),
                format_ipv4_address(&session->ipv4_peer_address));
        }
    } else if(session->state == BGP_ESTABLISHED) {
        timer->periodic = false;
        return;
    } else {
        LOG(BGP, "BGP (%s %s - %s) connect timeout\n", 
            session->interface->name,
            format_ipv4_address(&session->ipv4_local_address),
            format_ipv4_address(&session->ipv4_peer_address));

        bgp_session_close(session);
        timer->periodic = false;
        return;
    }

    timer_add_periodic(&g_ctx->timer_root, &session->connect_timer, 
                       "BGP CONNECT", timeout, 0, session,
                       &bgp_session_connect_job);
}

/**
 * bgp_session_connect
 * 
 * @param session BGP session
 * @param delay delay
 */
void
bgp_session_connect(bgp_session_s *session, time_t delay)
{
    if(session->state == BGP_CLOSED) {
        bbl_tcp_ctx_free(session->tcpc);
        session->tcpc = NULL;

        bgp_session_reset_read_buffer(session);
        bgp_session_reset_write_buffer(session);

        session->peer.as = 0;
        session->peer.id = 0;
        session->peer.holdtime = 0;

        session->stats.message_rx = 0;
        session->stats.message_tx = 0;
        session->stats.keepalive_rx = 0;
        session->stats.keepalive_tx = 0;
        session->stats.update_rx = 0;
        session->stats.update_tx = 0;

        session->raw_update = session->raw_update_start;
        session->raw_update_sending = false;

        session->established_timestamp.tv_sec = 0;
        session->established_timestamp.tv_nsec = 0;
        session->update_start_timestamp.tv_sec = 0;
        session->update_start_timestamp.tv_nsec = 0;
        session->update_stop_timestamp.tv_sec = 0;
        session->update_stop_timestamp.tv_nsec = 0;

        session->error_code = 0;
        session->error_subcode = 0;

        bgp_session_state_change(session, BGP_IDLE);

        timer_add(&g_ctx->timer_root, &session->connect_timer, 
                  "BGP CONNECT", delay, 0, session,
                  &bgp_session_connect_job);
    }
}

void
bgp_session_close_job(timer_s *timer)
{
    bgp_session_s *session = timer->data;
    if(session->state > BGP_IDLE) {
        /* Close TCP session */
        bbl_tcp_close(session->tcpc);
    }
    bgp_session_state_change(session, BGP_CLOSED);
    if(!session->teardown && session->config->reconnect) {
        bgp_session_connect(session, 5);
    }
}

/**
 * bgp_session_close
 * 
 * @param session BGP session
 */
void
bgp_session_close(bgp_session_s *session)
{
    time_t delay = 0;

    /* Stop all timers */
    timer_del(session->connect_timer);
    timer_del(session->send_open_timer);
    timer_del(session->open_sent_timer);
    timer_del(session->keepalive_timer);
    timer_del(session->hold_timer);
    timer_del(session->update_timer);

    if(session->state > BGP_CONNECT && 
       session->state < BGP_CLOSING &&
       session->error_code > 0) {
        /* Send notification messages */
        LOG(BGP, "BGP (%s %s - %s) send notification message (error code %u sub-code %u)\n",
            session->interface->name,
            format_ipv4_address(&session->ipv4_local_address),
            format_ipv4_address(&session->ipv4_peer_address),
            session->error_code, session->error_subcode);
        bgp_session_reset_write_buffer(session);
        bgp_push_notification_message(session);
        bgp_session_send(session);
        session->stats.message_tx++;
        bgp_session_state_change(session, BGP_CLOSING);
        delay = 3;
    }

    timer_add(&g_ctx->timer_root, &session->close_timer, 
              "BGP CLOSE", delay, 0, session,
              &bgp_session_close_job);
}

void
bgp_session_hold_timer_job(timer_s *timer)
{
    bgp_session_s *session = timer->data;

    LOG(BGP, "BGP (%s %s - %s) session timeout\n",
        session->interface->name,
        format_ipv4_address(&session->ipv4_local_address),
        format_ipv4_address(&session->ipv4_peer_address));

    if(!session->error_code) {
        session->error_code = 4; /* hold timer expired */
        session->error_subcode = 0;
    }
    bgp_session_close(session);
}

/**
 * bgp_restart_hold_timer
 * 
 * @param session BGP session
 * @param timeout timeout in seconds
 */
void
bgp_restart_hold_timer(bgp_session_s *session, time_t timeout)
{
    timer_add(&g_ctx->timer_root, &session->hold_timer, 
              "BGP TIMEOUT", timeout, 0, session, &bgp_session_hold_timer_job);
}