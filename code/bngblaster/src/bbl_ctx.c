/*
 * BNG Blaster (BBL) - Global Context
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_pcap.h"

extern volatile bool g_teardown;

int
bbl_compare_key32 (void *key1, void *key2)
{
    const uint32_t a = *(const uint32_t*)key1;
    const uint32_t b = *(const uint32_t*)key2;
    return (a > b) - (a < b);
}

uint32_t
bbl_key32_hash(const void* k)
{
    uint32_t hash = 2166136261U;
    hash ^= *(uint32_t *)k;
    return hash;
}

int
bbl_compare_key64(void *key1, void *key2)
{
    const uint64_t a = *(const uint64_t*)key1;
    const uint64_t b = *(const uint64_t*)key2;
    return (a > b) - (a < b);
}

uint32_t
bbl_key64_hash(const void* k)
{
    uint32_t hash = 2166136261U;

    hash ^= *(uint32_t *)k;
    hash ^= *(uint16_t *)((uint8_t*)k+4) << 12;
    hash ^= *(uint16_t *)((uint8_t*)k+6);

    return hash;
}

/**
 * bbl_ctx_add
 *
 * Allocate global context which is used as top-level data structure.
 *
 * @return global context
 */
bbl_ctx_s *
bbl_ctx_add (void)
{
    bbl_ctx_s *ctx;

    ctx = calloc(1, sizeof(bbl_ctx_s));
        if (!ctx) {
        return NULL;
    }

    /* Allocate scratchpad memory. */
    ctx->sp_rx = malloc(SCRATCHPAD_LEN);
    ctx->sp_tx = malloc(SCRATCHPAD_LEN);

    /* Initialize timer root. */
    timer_init_root(&ctx->timer_root);

    CIRCLEQ_INIT(&ctx->sessions_idle_qhead);
    CIRCLEQ_INIT(&ctx->sessions_teardown_qhead);
    CIRCLEQ_INIT(&ctx->interface_qhead);

    ctx->flow_id = 1;
    ctx->zapping = true;

    /* Initialize hash table dictionaries. */
    ctx->vlan_session_dict = hashtable_dict_new((dict_compare_func)bbl_compare_key64, bbl_key64_hash, BBL_SESSION_HASHTABLE_SIZE);
    ctx->l2tp_session_dict = hashtable_dict_new((dict_compare_func)bbl_compare_key32, bbl_key32_hash, BBL_SESSION_HASHTABLE_SIZE);
    ctx->li_flow_dict = hashtable_dict_new((dict_compare_func)bbl_compare_key32, bbl_key32_hash, BBL_LI_HASHTABLE_SIZE);
    ctx->stream_flow_dict = hashtable_dict_new((dict_compare_func)bbl_compare_key64, bbl_key64_hash, BBL_STREAM_FLOW_HASHTABLE_SIZE);

    return ctx;
}

/**
 * bbl_ctx_del
 *
 * Delete global context and free dynamic memory.
 *
 * @param ctx global context
 */
void
bbl_ctx_del(bbl_ctx_s *ctx) {
    bbl_access_config_s *access_config = ctx->config.access_config;
    void *p = NULL;
    uint32_t i;

    timer_flush_root(&ctx->timer_root);
    
    /* Free access configuration memory. */
    while(access_config) {
        p = access_config;
        access_config = access_config->next;
        free(p);
    }

    if(ctx->sp_rx) {
        free(ctx->sp_rx);
    }
    if(ctx->sp_tx) {
        free(ctx->sp_tx);
    }

    /* Free session memory. */
    for(i = 0; i < ctx->sessions; i++) {
        p = ctx->session_list[i];
        if(p) {
            bbl_session_free(p);
            free(p);
        }
    }
    free(ctx->session_list);
 
    /* Free hash table dictionaries. */
    dict_free(ctx->vlan_session_dict, NULL);
    dict_free(ctx->l2tp_session_dict, NULL);
    dict_free(ctx->li_flow_dict, NULL);
    dict_free(ctx->stream_flow_dict, NULL);

    pcapng_free(ctx);
    free(ctx);
    return;
}