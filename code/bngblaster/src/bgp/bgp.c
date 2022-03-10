/*
 * BNG Blaster (BBL) - BGP Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

static const char *
bgp_state_string(uint32_t state) {
    switch(state) {
        case BGP_IDLE: return "Idle";
        case BGP_CONNECT: return "Connect";
        case BGP_ACTIVE: return "Active";
        case BGP_OPENSENT: return "OpenSent";
        case BGP_OPENCONFIRM: return "OpenConfirm";
        case BGP_ESTABLISHED: return "Established";
        default: return "N/A";
    }
}

static void
bgp_state_change(bgp_session_t *session, bgp_state_t new_state)
{
    if (session->state == new_state) {
	    return;
    }

    LOG(BGP, "BGP %s:%s state change from %s -> %s\n", 
        format_ipv4_address(&session->ipv4_src_address),
        format_ipv4_address(&session->ipv4_dst_address),
        bgp_state_string(session->state),
        bgp_state_string(new_state));

    session->state = new_state;
}

void 
bgp_receive_cb(void *arg, uint8_t *buf, uint16_t len) {
    bgp_session_t *session = (bgp_session_t*)arg;

    UNUSED(buf);
    UNUSED(len);
    UNUSED(session);

    switch(session->state) {
        case BGP_IDLE:
            bgp_state_change(session, BGP_CONNECT);
            break;
        default:
            break;
    }   
}

static void
bgp_idle(bgp_session_t *session) {
    if(!session->interface->arp_resolved || session->tcpc) {
        return;
    }

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
    session->tcpc->receive_cb = bgp_receive_cb;
}

static void
bgp_connect(bgp_session_t *session) {
    //bgp_message_open(session);
    static uint8_t tmp[] = {0x00, 0x01, 0x02, 0x03};

    bbl_tcp_send(session->tcpc, tmp, sizeof(tmp));
    bgp_state_change(session, BGP_OPENSENT);
}

void
bgp_state_job(timer_s *timer) {
    bgp_session_t *session = timer->data;

    switch(session->state) {
        case BGP_IDLE:
            bgp_idle(session);
            break;
        case BGP_CONNECT:
            bgp_connect(session);
            break;
        default:
            break;
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
        session->write_buf = malloc(BGP_WRITEBUFSIZE);
        session->write_idx = 0;

        timer_add_periodic(&ctx->timer_root, &session->state_timer, 
                           "BGP STATE", 1, 0, session, &bgp_state_job);
        
        config = config->next;
    }
    return true;
}