/*
 * BNG Blaster (BBL) - BGP Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

static bgp_raw_update_t *
bgp_raw_update_load(char *file) {
    bgp_raw_update_t *raw_update;
    long fsize;
    double fsize_kb;

    /* Open file */
    FILE *f = fopen(file, "rb");
    if (f == NULL) {
        LOG(ERROR, "Failed to open BGP RAW update file %s\n", file);
        return NULL;
    } 

    /* Get file size */
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fsize_kb = fsize/1024;
    fseek(f, 0, SEEK_SET);

    /* Load file into memory */
    LOG(INFO, "Load BGP RAW update file %s (%.2f KB)\n", file, fsize_kb);
    raw_update = malloc(sizeof(bgp_raw_update_t));
    raw_update->file = file;
    raw_update->buf = malloc(fsize);
    raw_update->len = fsize;
    fread(raw_update->buf, fsize, 1, f);
    fclose(f);
    return raw_update;
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

    bgp_raw_update_t *raw_update_root = NULL;
    bgp_raw_update_t *raw_update = NULL;

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

        /* Init RAW update file */
        if(config->raw_update_file) {
            raw_update = raw_update_root;
            while(raw_update){
                if (strcmp(config->raw_update_file, raw_update->file) == 0) {
                    session->raw_update = raw_update;
                    break;
                }
                raw_update = raw_update->next;
            }
            if(!session->raw_update) {
                session->raw_update = bgp_raw_update_load(config->raw_update_file);
                session->raw_update->next = raw_update_root;
                raw_update_root = session->raw_update;
            }
        }

        LOG(BGP, "Init BGP session %s %s:%s\n",
            session->interface->name,
            format_ipv4_address(&session->ipv4_src_address),
            format_ipv4_address(&session->ipv4_dst_address));

        bgp_session_connect(session, 1);
        ctx->routing_sessions++;

        config = config->next;
    }
    return true;
}

void
bgp_teardown_job(timer_s *timer) {
    bgp_session_t *session = timer->data;
    bbl_ctx_s *ctx = session->interface->ctx;
    if(ctx->routing_sessions) {
        ctx->routing_sessions--;
    }
}

/**
 * bgp_teardown
 * 
 * This function stops all BGP sessions. 
 * 
 * @param ctx global context
 */
void
bgp_teardown(bbl_ctx_s *ctx) {
    bgp_session_t *session  = ctx->bgp_sessions;
    while(session) {
        if(!session->teardown) {
            LOG(BGP, "Teardown BGP session %s %s:%s\n",
                session->interface->name,
                format_ipv4_address(&session->ipv4_src_address),
                format_ipv4_address(&session->ipv4_dst_address));

            session->teardown = true;
            if(!session->error_code) {
                session->error_code = 6; /* Cease */
                session->error_subcode = 2; /* Shutdown */
            }
            bgp_session_close(session);

            timer_add(&ctx->timer_root, &session->teardown_timer, 
                      "BGP TEARDOWN", session->config->teardown_time, 0, session,
                      &bgp_teardown_job);
        }
        session = session->next;
    }
}