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
bgp_raw_update_load(char *file, bool decode_file) {
    bgp_raw_update_t *raw_update = NULL;
    long fsize;
    double fsize_kb;

    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint16_t msg_len;
    uint8_t  msg_type;

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
    raw_update = malloc(sizeof(bgp_raw_update_t));
    raw_update->file = file;
    raw_update->buf = malloc(fsize);
    raw_update->len = fsize;
    if(fread(raw_update->buf, fsize, 1, f) != 1) {
        fclose(f);
        LOG(ERROR, "Failed to read BGP RAW update file %s\n", file);
        goto ERROR;
    }
    fclose(f);

    if(decode_file) {
        /* Decode update stream */
        buf = raw_update->buf;
        len = raw_update->len;
        while(len) {
            if(len < BGP_MIN_MESSAGE_SIZE) {
                goto DECODE_ERROR;
            }
            if(*(uint64_t*)buf != UINT64_MAX) {
                goto DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint64_t));
            if(*(uint64_t*)buf != UINT64_MAX) {
                goto DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint64_t));
            msg_len = be16toh(*(uint16_t*)buf);
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            msg_type = *buf;
            BUMP_BUFFER(buf, len, sizeof(uint8_t));
            if(msg_len < BGP_MIN_MESSAGE_SIZE ||
               msg_len > BGP_MAX_MESSAGE_SIZE) {
                goto DECODE_ERROR;
            }
            if((msg_len - BGP_MIN_MESSAGE_SIZE) > len) {
                goto DECODE_ERROR;
            }
            if(msg_type == BGP_MSG_UPDATE) {
                raw_update->updates++;
            }
            BUMP_BUFFER(buf, len, (msg_len - BGP_MIN_MESSAGE_SIZE));
        }
    }
    LOG(INFO, "Loaded BGP RAW update file %s (%.2f KB, %u updates)\n", 
        file, fsize_kb, raw_update->updates);
    return raw_update;

DECODE_ERROR:
    LOG(ERROR, "Failed to decode BGP RAW update file %s\n", file);
ERROR:
    if(raw_update) {
        if(raw_update->buf) {
            free(raw_update->buf);
        }
        free(raw_update);
    }
    return NULL;
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

        if(config->ipv4_local_address) {
            session->ipv4_local_address = config->ipv4_local_address;
        } else {
            session->ipv4_local_address = network_if->ip.address;
        }
        session->ipv4_peer_address = config->ipv4_peer_address;
        
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
                session->raw_update = bgp_raw_update_load(config->raw_update_file, true);
                if(session->raw_update) {
                    session->raw_update->next = raw_update_root;
                    raw_update_root = session->raw_update;
                } else {
                    return false;
                }
            }
        }

        LOG(BGP, "BGP (%s %s - %s) init session\n",
            session->interface->name,
            format_ipv4_address(&session->ipv4_local_address),
            format_ipv4_address(&session->ipv4_peer_address));

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

            timer_add(&ctx->timer_root, &session->teardown_timer, 
                      "BGP TEARDOWN", session->config->teardown_time, 0, session,
                      &bgp_teardown_job);
        }
        session = session->next;
    }
}