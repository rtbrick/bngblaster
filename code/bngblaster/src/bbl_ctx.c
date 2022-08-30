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
bbl_compare_key32(void *key1, void *key2)
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
 */
bool
bbl_ctx_add()
{
    g_ctx = calloc(1, sizeof(bbl_ctx_s));
    if (!g_ctx) {
        return false;
    }

    /* Allocate scratchpad memory. */
    g_ctx->sp = malloc(SCRATCHPAD_LEN);

    /* Initialize timer root. */
    timer_init_root(&g_ctx->timer_root);

    CIRCLEQ_INIT(&g_ctx->sessions_idle_qhead);
    CIRCLEQ_INIT(&g_ctx->sessions_teardown_qhead);
    CIRCLEQ_INIT(&g_ctx->interface_qhead);
    CIRCLEQ_INIT(&g_ctx->lag_qhead);
    CIRCLEQ_INIT(&g_ctx->access_interface_qhead);
    CIRCLEQ_INIT(&g_ctx->network_interface_qhead);
    CIRCLEQ_INIT(&g_ctx->a10nsp_interface_qhead);

    g_ctx->flow_id = 1;
    g_ctx->multicast_traffic = true;
    g_ctx->zapping = true;

    /* Initialize hash table dictionaries. */
    g_ctx->vlan_session_dict = hashtable_dict_new((dict_compare_func)bbl_compare_key64, bbl_key64_hash, BBL_SESSION_HASHTABLE_SIZE);
    g_ctx->l2tp_session_dict = hashtable_dict_new((dict_compare_func)bbl_compare_key32, bbl_key32_hash, BBL_SESSION_HASHTABLE_SIZE);
    g_ctx->li_flow_dict = hashtable_dict_new((dict_compare_func)bbl_compare_key32, bbl_key32_hash, BBL_LI_HASHTABLE_SIZE);
    g_ctx->stream_flow_dict = hashtable_dict_new((dict_compare_func)bbl_compare_key64, bbl_key64_hash, BBL_STREAM_FLOW_HASHTABLE_SIZE);

    return true;
}

/**
 * bbl_ctx_del
 *
 * Delete global context and free dynamic memory.
 */
void
bbl_ctx_del() {
    bbl_access_config_s *access_config = NULL;
    void *p = NULL;
    uint32_t i;

    if(!g_ctx) return;

    timer_flush_root(&g_ctx->timer_root);
    
    /* Free access configuration memory. */
    access_config = g_ctx->config.access_config;
    while(access_config) {
        p = access_config;
        access_config = access_config->next;
        free(p);
    }

    if(g_ctx->sp) {
        free(g_ctx->sp);
    }

    /* Free session memory. */
    for(i = 0; i < g_ctx->sessions; i++) {
        p = &g_ctx->session_list[i];
        if(p) {
            bbl_session_free(p);
        }
    }
    free(g_ctx->session_list);
 
    /* Free hash table dictionaries. */
    dict_free(g_ctx->vlan_session_dict, NULL);
    dict_free(g_ctx->l2tp_session_dict, NULL);
    dict_free(g_ctx->li_flow_dict, NULL);
    dict_free(g_ctx->stream_flow_dict, NULL);

    pcapng_free();
    free(g_ctx);
    g_ctx = NULL;
    return;
}