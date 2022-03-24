/*
 * BNG Blaster (BBL) - BGP RAW Update Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

static bgp_raw_update_t *
bgp_raw_update_load_file(const char *file, bool decode_file) {
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
    fsize_kb = fsize/1024.0;
    fseek(f, 0, SEEK_SET);

    /* Load file into memory */
    raw_update = calloc(1, sizeof(bgp_raw_update_t));
    raw_update->file = strdup(file);
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
            BUMP_BUFFER(buf, len, 16);
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
 * bgp_raw_update_load 
 * 
 * @param ctx global context
 * @param file update file
 * @param decode_file decode/parse file content if true
 * @return BGP RAW update structure
 */
bgp_raw_update_t *
bgp_raw_update_load(bbl_ctx_s *ctx, const char *file, bool decode_file) {
    bgp_raw_update_t *raw_update = ctx->bgp_raw_updates;

    /* Check if file is already loaded */
    while(raw_update){
        if (strcmp(file, raw_update->file) == 0) {
            return raw_update;
        }
        raw_update = raw_update->next;
    }
    raw_update = bgp_raw_update_load_file(file, decode_file);
    if(raw_update) {
        raw_update->next = ctx->bgp_raw_updates;
        ctx->bgp_raw_updates = raw_update;
        return raw_update;
    } else {
        return NULL;
    }
}