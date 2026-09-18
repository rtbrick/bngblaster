/*
 * BNG Blaster (BBL) - BGP Session Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
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
 * bgp_session_find_ipv4
 *
 * Find a configured BGP session matching an exact (local, peer) IPv4
 * address pair.
 *
 * @param local_address local IPv4 address
 * @param peer_address peer IPv4 address
 * @return matching BGP session or NULL
 */
bgp_session_s *
bgp_session_find_ipv4(ipv4addr_t local_address, ipv4addr_t peer_address)
{
    bgp_session_s *bgp_session = g_ctx->bgp_sessions;
    while(bgp_session) {
        if(bgp_session->af == AF_INET &&
           bgp_session->ipv4_local_address == local_address &&
           bgp_session->ipv4_peer_address == peer_address) {
            return bgp_session;
        }
        bgp_session = bgp_session->next;
    }
    return NULL;
}

/**
 * bgp_session_find_ipv6
 *
 * Find a configured BGP session matching an exact (local, peer) IPv6
 * address pair.
 *
 * @param local_address local IPv6 address
 * @param peer_address peer IPv6 address
 * @return matching BGP session or NULL
 */
bgp_session_s *
bgp_session_find_ipv6(ipv6addr_t *local_address, ipv6addr_t *peer_address)
{
    bgp_session_s *bgp_session = g_ctx->bgp_sessions;
    while(bgp_session) {
        if(bgp_session->af == AF_INET6 &&
           bgp_session->ipv6_local_address && bgp_session->ipv6_peer_address &&
           memcmp(bgp_session->ipv6_local_address, local_address, IPV6_ADDR_LEN) == 0 &&
           memcmp(bgp_session->ipv6_peer_address, peer_address, IPV6_ADDR_LEN) == 0) {
            return bgp_session;
        }
        bgp_session = bgp_session->next;
    }
    return NULL;
}

static bgp_listen_s *g_bgp_listen_sockets = NULL;

static void
bgp_pre_accept_cb(struct tcp_pcb *new_pcb, void *arg)
{
    bgp_session_s *session;
    bbl_tcp_ao_key_s ao;

    UNUSED(arg);

    if(IP_IS_V6_VAL(new_pcb->remote_ip)) {
        session = bgp_session_find_ipv6((ipv6addr_t*)&new_pcb->local_ip.u_addr.ip6.addr,
                                         (ipv6addr_t*)&new_pcb->remote_ip.u_addr.ip6.addr);
    } else {
        session = bgp_session_find_ipv4(new_pcb->local_ip.u_addr.ip4.addr,
                                         new_pcb->remote_ip.u_addr.ip4.addr);
    }
    if(session && session->config->tcp_ao_enabled) {
        ao.key = (uint8_t*)session->config->tcp_ao_key;
        ao.key_len = (uint16_t)strlen(session->config->tcp_ao_key);
        ao.key_id = session->config->tcp_ao_key_id;
        ao.rnext_key_id = session->config->tcp_ao_rnext_key_id;
        ao.algo = session->config->tcp_ao_algo;
        if(!bbl_tcp_ao_enable(new_pcb, &ao)) {
            LOG(BGP, "BGP (%s %s - %s) failed to enable TCP-AO on accepted connection\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str);
        } else {
            /* The peer's ISN (from the SYN that triggered this accept) is
             * already reflected in rcv_nxt at this point (lwIP sets it in
             * tcp_listen_input() before invoking this hook), but was never
             * learned by the normal SYN-tracking verification logic, since
             * that SYN was checked (if at all) against the listen pcb, not
             * this newly-created one. Without seeding it here, every
             * segment after the handshake fails MAC verification. */
            bbl_tcp_ao_set_remote_isn(new_pcb, new_pcb->rcv_nxt - 1);
        }
    }
}

static err_t
bgp_accepted_cb(bbl_tcp_ctx_s *tcpc, void *arg)
{
    bgp_session_s *session;

    UNUSED(arg);

    if(tcpc->af == AF_INET6) {
        session = bgp_session_find_ipv6((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr,
                                         (ipv6addr_t*)&tcpc->remote_addr.u_addr.ip6.addr);
    } else {
        session = bgp_session_find_ipv4(tcpc->local_addr.u_addr.ip4.addr,
                                         tcpc->remote_addr.u_addr.ip4.addr);
    }
    if(!session) {
        /* No configured peer for this address pair. */
        return ERR_ABRT;
    }
    /* On rejection just return an error: bbl_tcp_listen_accepted() owns the
     * context until we accept it, and tears it down (and resets the pcb)
     * itself. Closing or freeing it here would leave the caller using freed
     * memory. */
    if(!bgp_session_new_connection(session, tcpc, false)) {
        return ERR_ABRT;
    }
    return ERR_OK;
}

/**
 * bgp_session_listen
 *
 * Ensure a shared BGP listen socket exists for this session's
 * (interface, local address, address family), creating one only if no
 * earlier session already covers it.
 *
 * @param session BGP session
 */
void
bgp_session_listen(bgp_session_s *session)
{
    bgp_listen_s *bgp_listen = g_bgp_listen_sockets;
    bbl_tcp_ctx_s *tcpc;

    while(bgp_listen) {
        if(bgp_listen->af == session->af &&
           bgp_listen->interface == session->interface &&
           ((session->af == AF_INET && bgp_listen->ipv4_local_address == session->ipv4_local_address) ||
            (session->af == AF_INET6 && memcmp(&bgp_listen->ipv6_local_address, session->ipv6_local_address, IPV6_ADDR_LEN) == 0))) {
            /* Already listening for this (interface, local address, af). */
            return;
        }
        bgp_listen = bgp_listen->next;
    }

    if(session->af == AF_INET) {
        tcpc = bbl_tcp_ipv4_listen(session->interface, &session->ipv4_local_address,
                                    BGP_PORT, session->config->ttl, session->config->tos);
    } else {
        tcpc = bbl_tcp_ipv6_listen(session->interface, session->ipv6_local_address,
                                    BGP_PORT, session->config->ttl, session->config->tos);
    }
    if(!tcpc) {
        LOG(BGP, "BGP (%s %s) failed to enable passive/listen mode\n",
            session->interface->name, session->local_address_str);
        return;
    }
    tcpc->pre_accept_cb = bgp_pre_accept_cb;
    tcpc->accepted_cb = bgp_accepted_cb;

    bgp_listen = calloc(1, sizeof(bgp_listen_s));
    if(!bgp_listen) {
        bbl_tcp_ctx_free(tcpc);
        return;
    }
    bgp_listen->af = session->af;
    bgp_listen->interface = session->interface;
    if(session->af == AF_INET) {
        bgp_listen->ipv4_local_address = session->ipv4_local_address;
    } else {
        memcpy(&bgp_listen->ipv6_local_address, session->ipv6_local_address, IPV6_ADDR_LEN);
    }
    bgp_listen->tcpc = tcpc;
    bgp_listen->next = g_bgp_listen_sockets;
    g_bgp_listen_sockets = bgp_listen;
}

/**
 * bgp_session_listen_teardown
 *
 * Close and free every shared BGP listen socket.
 */
void
bgp_session_listen_teardown(void)
{
    bgp_listen_s *bgp_listen;
    while(g_bgp_listen_sockets) {
        bgp_listen = g_bgp_listen_sockets;
        g_bgp_listen_sockets = bgp_listen->next;
        bbl_tcp_ctx_free(bgp_listen->tcpc);
        free(bgp_listen);
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

    session->tcpc->idle_cb = NULL;

    clock_gettime(CLOCK_MONOTONIC, &session->update_stop_timestamp);
    timespec_sub(&session->update_duration, 
                 &session->update_stop_timestamp, 
                 &session->update_start_timestamp);

    session->raw_update_sending = false;
    session->stats.message_tx += session->raw_update->updates;
    session->stats.update_tx += session->raw_update->updates;
    
    LOG(BGP, "BGP (%s %s - %s) raw update stop after %lds\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str,
        session->update_duration.tv_sec);

    if(session->config->start_traffic) {
        LOG(BGP, "BGP (%s %s - %s) start traffic streams\n",
            session->interface->name,
            session->local_address_str,
            session->peer_address_str);
        global_traffic_enable(true);
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
                    session->local_address_str,
                    session->peer_address_str);

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
                       "BGP UPDATE", 0, 250 * MSEC, session,
                       &bgp_session_update_job);

}

static void
bgp_session_state_opensent(bgp_session_s *session)
{
    bgp_session_reset_write_buffer(session);
    bgp_push_open_message(session);
    bgp_session_send(session);
    session->stats.message_tx++;

    /* RFC 4271 8.2.2: bound the wait for the peer's OPEN. Without this a
     * connection that completes at TCP level but never delivers a valid
     * BGP message (e.g. every segment failing authentication) would hang
     * forever, since the hold timer is otherwise only armed on receive. */
    bgp_restart_hold_timer(session, BGP_OPENSENT_HOLD_TIME);
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
    if(session->peer.hold_time < session->config->hold_time) {
        keepalive_interval = session->peer.hold_time/2U;
    } else {
        keepalive_interval = session->config->hold_time/2U;
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
        session->local_address_str,
        session->peer_address_str,
        bgp_session_state_string(session->state),
        bgp_session_state_string(new_state));

    session->state = new_state;

    switch(new_state) {
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
    bbl_tcp_ctx_s *tcpc = session->connecting_tcpc;
    session->connecting_tcpc = NULL;
    if(!bgp_session_new_connection(session, tcpc, true)) {
        /* Rejected (session already established, or a collision is already
         * being resolved). The teardown is deferred because we are inside
         * this very connection's connected callback. */
        bgp_session_close_tcpc_with_notification(tcpc, 6, 7);
    }
}

static void
bgp_connecting_error_cb(void *arg, err_t err)
{
    bgp_session_s *session = (bgp_session_s*)arg;

    LOG(BGP, "BGP (%s %s - %s) active connect attempt TCP error %d (%s)\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str,
        err, tcp_err_string(err));

    bbl_tcp_ctx_free_deferred(session->connecting_tcpc);
    session->connecting_tcpc = NULL;
}

void
bgp_error_cb(void *arg, err_t err) {
    bgp_session_s *session = (bgp_session_s*)arg;

    LOG(BGP, "BGP (%s %s - %s) TCP error %d (%s)\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str,
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
    } else if(session->state == BGP_ESTABLISHED) {
        timer->periodic = false;
        return;
    } else if(session->connecting_tcpc) {
        /* An active connect attempt is already in flight (its own TCP
         * stack enforces the SYN retry/timeout, see bgp_connecting_error_cb);
         * nothing to do here but keep the periodic safety net alive. Note a
         * peer-initiated (passive) connection may independently already be
         * progressing this session past IDLE - that's expected and handled
         * via collision detection once both sides exchange OPEN. */
        timeout = 60;
    } else if(!(session->state == BGP_IDLE || session->state == BGP_CONNECT)) {
        /* A connection (ours, or one accepted from the peer) already
         * reached OpenSent or beyond. RFC 4271 8.2.2 stops the
         * ConnectRetryTimer at that point; redialing here would only churn
         * through extra TCP connections. Recovery from a stalled session is
         * the hold timer's job (armed when entering OpenSent). */
        timer->periodic = false;
        return;
    } else {
        bbl_tcp_ao_key_s ao;
        bbl_tcp_ao_key_s *ao_ptr = NULL;

        if(session->config->tcp_ao_enabled) {
            ao.key = (uint8_t*)session->config->tcp_ao_key;
            ao.key_len = (uint16_t)strlen(session->config->tcp_ao_key);
            ao.key_id = session->config->tcp_ao_key_id;
            ao.rnext_key_id = session->config->tcp_ao_rnext_key_id;
            ao.algo = session->config->tcp_ao_algo;
            ao_ptr = &ao;
        }

        /* Connect TCP session */
        if(session->af == AF_INET) {
            session->connecting_tcpc = bbl_tcp_ipv4_connect(
                session->interface,
                &session->ipv4_local_address,
                &session->ipv4_peer_address,
                BGP_PORT,
                session->config->ttl,
                session->config->tos,
                ao_ptr);
        } else {
            session->connecting_tcpc = bbl_tcp_ipv6_connect(
                session->interface,
                session->ipv6_local_address,
                session->ipv6_peer_address,
                BGP_PORT,
                session->config->ttl,
                session->config->tos,
                ao_ptr);
        }
        if(session->connecting_tcpc) {
            session->connecting_tcpc->arg = session;
            session->connecting_tcpc->connected_cb = bgp_connected_cb;
            session->connecting_tcpc->error_cb = bgp_connecting_error_cb;
            if(session->state == BGP_IDLE) {
                bgp_session_state_change(session, BGP_CONNECT);
            }
            timeout = 60;
        } else {
            LOG(BGP, "BGP (%s %s - %s) TCP connect failed\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str);
        }
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
        session->active = false;

        if(session->connecting_tcpc) {
            bbl_tcp_ctx_free(session->connecting_tcpc);
            session->connecting_tcpc = NULL;
        }
        if(session->collision) {
            bgp_session_collision_free(session);
        }

        bgp_session_reset_read_buffer(session);
        bgp_session_reset_write_buffer(session);

        session->peer.as = 0;
        session->peer.id = 0;
        session->peer.hold_time = 0;

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
    if(session->connecting_tcpc) {
        bbl_tcp_ctx_free(session->connecting_tcpc);
        session->connecting_tcpc = NULL;
    }
    if(session->collision) {
        bgp_session_collision_free(session);
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
    timer_del(session->keepalive_timer);
    timer_del(session->hold_timer);
    timer_del(session->update_timer);

    if(session->state > BGP_CONNECT && 
       session->state < BGP_CLOSING &&
       session->error_code > 0) {
        /* Send notification messages */
        LOG(BGP, "BGP (%s %s - %s) send notification message (error code %u sub-code %u)\n",
            session->interface->name,
            session->local_address_str,
            session->peer_address_str,
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
        session->local_address_str,
        session->peer_address_str);

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