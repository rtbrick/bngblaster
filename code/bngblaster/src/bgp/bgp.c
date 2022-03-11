/*
 * BNG Blaster (BBL) - BGP Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"
extern bool g_init_phase;
extern volatile bool g_teardown;

struct keyval_ bgp_fsm_state_names[] = {
    { BGP_CLOSED,       "closed" },
    { BGP_IDLE,         "idle" },
    { BGP_CONNECT,      "connect" },
    { BGP_ACTIVE,       "active" },
    { BGP_OPENSENT,     "opensent" },
    { BGP_OPENCONFIRM,  "openconfirm" },
    { BGP_ESTABLISHED,  "established" },
    { 0, NULL}
};

/**
 * bgp_state_change
 * 
 * @param session BGP session
 */
void
bgp_state_change(bgp_session_t *session, bgp_state_t new_state) {
    if (session->state == new_state) {
	    return;
    }

    LOG(BGP, "BGP %s:%s state change from %s -> %s\n", 
        format_ipv4_address(&session->ipv4_src_address),
        format_ipv4_address(&session->ipv4_dst_address),
        keyval_get_key(bgp_fsm_state_names, session->state),
        keyval_get_key(bgp_fsm_state_names, new_state));

    session->state = new_state;
}

static void
bgp_reset_read_buffer(bgp_session_t *session) {
    session->read_buf.idx = 0;
    session->read_buf.start_idx = 0;
}

void
bgp_reset_write_buffer(bgp_session_t *session) {
    if(session->tcpc && session->tcpc->state == BBL_TCP_STATE_SENDING) {
        return;
    }
    session->write_buf.idx = 0;
    session->write_buf.start_idx = 0;
}

/**
 * bgp_session_connect
 * 
 * @param session BGP session
 */
void
bgp_session_connect(bgp_session_t *session) {
    if(session->state == BGP_CLOSED) {
        bbl_tcp_ctx_free(session->tcpc);
        session->tcpc = NULL;
        bgp_reset_read_buffer(session);
        bgp_reset_write_buffer(session);
        session->peer.as = 0;
        session->peer.id = 0;
        session->peer.holdtime = 0;
        session->stats.keepalive_rx = 0;
        session->stats.update_rx = 0;
        bgp_state_change(session, BGP_IDLE);
    }
}

/**
 * bgp_session_close
 * 
 * @param session BGP session
 */
void
bgp_session_close(bgp_session_t *session) {
    if(session->state > BGP_IDLE) {
        bbl_tcp_close(session->tcpc);
        timer_del(session->keepalive_timer);
        timer_del(session->close_timer);
    }
    bgp_state_change(session, BGP_CLOSED);
    if(!g_teardown && session->config->reconnect) {
        bgp_session_connect(session);
    }
}

/**
 * bgp_send
 * 
 * @param session BGP session
 */
bool
bgp_send(bgp_session_t *session) {
    bbl_tcp_ctx_t *tcpc = session->tcpc;
    if(tcpc && tcpc->state == BBL_TCP_STATE_SENDING && 
       tcpc->tx.buf == session->write_buf.data &&
       tcpc->tx.len < session->write_buf.idx) {
        tcpc->tx.len = session->write_buf.idx;
        return true;
    }
    return bbl_tcp_send(session->tcpc, session->write_buf.data, session->write_buf.idx);
}

void
bgp_session_timeout_job(timer_s *timer) {
    bgp_session_t *session = timer->data;

    LOG(BGP, "BGP %s:%s session timeout\n", 
        format_ipv4_address(&session->ipv4_src_address),
        format_ipv4_address(&session->ipv4_dst_address));

    bgp_session_close(session);
}

/**
 * bgp_restart_timeout
 * 
 * @param session BGP session
 * @param timeout timeout in seconds
 */
void
bgp_restart_timeout(bgp_session_t *session, time_t timeout) {
    timer_add(&session->interface->ctx->timer_root, &session->close_timer, 
              "BGP TIMEOUT", timeout, 0, session, &bgp_session_timeout_job);
}

void 
bgp_connected_cb(void *arg) {
    bgp_session_t *session = (bgp_session_t*)arg;
    bgp_push_open_message(session);
    bgp_send(session);
    bgp_state_change(session, BGP_OPENSENT);
}

void
bgp_state_job(timer_s *timer) {
    bgp_session_t *session = timer->data;

    if(g_init_phase) {
        /* Wait for all network interfaces to be resolved */
        return;
    }
    if(g_teardown) {
        bgp_session_close(session);
        return;
    }
    bgp_reset_write_buffer(session);
    if(session->state == BGP_IDLE) {
        /* Connect TCP session */
        session->tcpc = bbl_tcp_ipv4_connect(
            session->interface, 
            &session->ipv4_src_address,
            &session->ipv4_dst_address,
            BGP_PORT);

        if(!session->tcpc) {
            /* Try again... */
            return;
        }
        session->tcpc->arg = session;
        session->tcpc->connected_cb = bgp_connected_cb;
        session->tcpc->receive_cb = bgp_receive_cb;
        bgp_state_change(session, BGP_CONNECT);
        bgp_restart_timeout(session, 30);
    } if(session->state == BGP_ESTABLISHED) {
        if(session->keepalive_countdown) {
            session->keepalive_countdown--;
        } else {
            session->keepalive_countdown = 10;
            if(session->tcpc && session->tcpc->state == BBL_TCP_STATE_IDLE) {
                bgp_reset_write_buffer(session);
                bgp_push_keepalive_message(session);
                bgp_send(session);
            }
        }
    }
}

/**
 * bgp_init
 * 
 * This function inits all BGP sessions. 
 * 
 * @param ctx global context
 */
bool
bgp_init(bbl_ctx_s *ctx) {

    bgp_config_t *config = ctx->config.bgp_config;
    bgp_session_t *session = NULL;
    bbl_interface_s *network_if;

    while(config) {
        if(session) {
            session->next = calloc(1, sizeof(bgp_session_t));
            session = session->next;
        } else {
            session = calloc(1, sizeof(bgp_session_t));
            ctx->bgp_sessions = session;
        }
        if(!session) {
            return false;
        }
        
        network_if = bbl_get_network_interface(ctx, config->network_interface);
        if(!network_if) {
            free(session);
            return false;
        }

        session->ctx = ctx;
        session->config = config;
        session->interface = network_if;

        if(config->ipv4_src_address) {
            session->ipv4_src_address = config->ipv4_src_address;
        } else {
            session->ipv4_src_address = network_if->ip.address;
        }
        session->ipv4_dst_address = config->ipv4_dst_address;
        
        /* Init read/write buffer */
        session->read_buf.data = malloc(BGP_BUF_SIZE);
        session->read_buf.size = BGP_BUF_SIZE;
        session->write_buf.data = malloc(BGP_BUF_SIZE);
        session->write_buf.size = BGP_BUF_SIZE;

        /* Start state timer */
        timer_add_periodic(&ctx->timer_root, &session->state_timer, 
                           "BGP STATE", 1, 0, session, &bgp_state_job);

        bgp_session_connect(session);

        config = config->next;
    }
    return true;
}