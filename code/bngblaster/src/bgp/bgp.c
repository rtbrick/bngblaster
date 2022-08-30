/*
 * BNG Blaster (BBL) - BGP Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

/**
 * bgp_init
 * 
 * This function inits all BGP sessions. 
 */
bool
bgp_init()
{
    bgp_config_s *config = g_ctx->config.bgp_config;
    bgp_session_s *session = NULL;
    bbl_network_interface_s *network_interface;

    while(config) {
        if(session) {
            session->next = calloc(1, sizeof(bgp_session_s));
            session = session->next;
        } else {
            session = calloc(1, sizeof(bgp_session_s));
            g_ctx->bgp_sessions = session;
        }
        if(!session) {
            return false;
        }
        
        network_interface = bbl_network_interface_get(config->network_interface);
        if(!network_interface) {
            free(session);
            return false;
        }

        session->config = config;
        session->interface = network_interface;

        if(config->ipv4_local_address) {
            session->ipv4_local_address = config->ipv4_local_address;
        } else {
            session->ipv4_local_address = network_interface->ip.address;
        }
        session->ipv4_peer_address = config->ipv4_peer_address;
        
        /* Init read/write buffer */
        session->read_buf.data = malloc(BGP_BUF_SIZE);
        session->read_buf.size = BGP_BUF_SIZE;
        session->write_buf.data = malloc(BGP_BUF_SIZE);
        session->write_buf.size = BGP_BUF_SIZE;

        /* Init RAW update file */
        if(config->raw_update_file) {
            session->raw_update_start = bgp_raw_update_load(config->raw_update_file, true);
            if(!session->raw_update_start) {
                return false;
            }
            session->raw_update = session->raw_update_start;
        }

        LOG(BGP, "BGP (%s %s - %s) init session\n",
            session->interface->name,
            format_ipv4_address(&session->ipv4_local_address),
            format_ipv4_address(&session->ipv4_peer_address));

        bgp_session_connect(session, 1);
        g_ctx->routing_sessions++;

        config = config->next;
    }
    return true;
}

void
bgp_teardown_job(timer_s *timer)
{
    UNUSED(timer);
    if(g_ctx->routing_sessions) {
        g_ctx->routing_sessions--;
    }
}

/**
 * bgp_teardown
 * 
 * This function stops all BGP sessions. 
 */
void
bgp_teardown()
{
    bgp_session_s *session  = g_ctx->bgp_sessions;
    while(session) {
        if(!session->teardown) {
            LOG(BGP, "BGP (%s %s - %s) teardown session\n",
                session->interface->name,
                format_ipv4_address(&session->ipv4_local_address),
                format_ipv4_address(&session->ipv4_peer_address));

            session->teardown = true;
            if(!session->error_code) {
                session->error_code = 6; /* Cease */
                session->error_subcode = 2; /* Shutdown */
            }
            bgp_session_close(session);

            timer_add(&g_ctx->timer_root, &session->teardown_timer, 
                      "BGP TEARDOWN", session->config->teardown_time, 0, session,
                      &bgp_teardown_job);
        }
        session = session->next;
    }
}