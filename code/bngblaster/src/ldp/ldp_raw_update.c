/*
 * BNG Blaster (BBL) - LDP RAW Update Functions
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

static ldp_raw_update_s *
ldp_raw_update_load_file(const char *file, bool decode_file)
{
    ldp_raw_update_s *raw_update = NULL;
    long fsize;
    double fsize_kb;

    uint8_t *buf = NULL;
    uint32_t len = 0;

    uint16_t pdu_length;
    uint16_t msg_len;

    /* Open file */
    FILE *f = fopen(file, "rb");
    if(f == NULL) {
        LOG(ERROR, "Failed to open LDP RAW update file %s\n", file);
        return NULL;
    } 

    /* Get file size */
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fsize_kb = fsize/1024.0;
    fseek(f, 0, SEEK_SET);

    /* Load file into memory */
    raw_update = calloc(1, sizeof(ldp_raw_update_s));
    raw_update->file = strdup(file);
    raw_update->buf = malloc(fsize);
    raw_update->len = fsize;
    if(fread(raw_update->buf, fsize, 1, f) != 1) {
        fclose(f);
        LOG(ERROR, "Failed to read LDP RAW update file %s\n", file);
        goto ERROR;
    }
    fclose(f);

    if(decode_file) {
        /* Decode update stream */
        buf = raw_update->buf;
        len = raw_update->len;
        while(len) {
            if(len < LDP_MIN_PDU_LEN) {
                goto DECODE_ERROR;
            }
            raw_update->pdu++;

            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            pdu_length = be16toh(*(uint16_t*)buf);
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            if(pdu_length > len) {
                goto DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, LDP_IDENTIFIER_LEN);
            while(pdu_length > LDP_MIN_MSG_LEN) {
                BUMP_BUFFER(buf, len, sizeof(uint16_t));
                msg_len = be16toh(*(uint16_t*)buf);
                BUMP_BUFFER(buf, len, sizeof(uint16_t));
                pdu_length -= 4;
                if(msg_len > pdu_length) {
                    goto DECODE_ERROR;
                }
                BUMP_BUFFER(buf, len, msg_len);
                pdu_length -= msg_len;
                raw_update->messages++;
            }
        }
    }
    LOG(INFO, "Loaded LDP RAW update file %s (%.2f KB, %u pdu, %u messages)\n", 
        file, fsize_kb, raw_update->pdu, raw_update->messages);
    return raw_update;

DECODE_ERROR:
    LOG(ERROR, "Failed to decode LDP RAW update file %s\n", file);
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
 * ldp_raw_update_load 
 * 
 * @param file update file
 * @param decode_file decode/parse file content if true
 * @return LDP RAW update structure
 */
ldp_raw_update_s *
ldp_raw_update_load(const char *file, bool decode_file)
{
    ldp_raw_update_s *raw_update = g_ctx->ldp_raw_updates;

    /* Check if file is already loaded */
    while(raw_update){
        if(strcmp(file, raw_update->file) == 0) {
            return raw_update;
        }
        raw_update = raw_update->next;
    }
    raw_update = ldp_raw_update_load_file(file, decode_file);
    if(raw_update) {
        raw_update->next = g_ctx->ldp_raw_updates;
        g_ctx->ldp_raw_updates = raw_update;
        return raw_update;
    } else {
        return NULL;
    }
}