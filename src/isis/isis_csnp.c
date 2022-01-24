/*
 * BNG Blaster (BBL) - IS-IS CSNP
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

uint64_t g_csnp_scan = 0;

void
isis_csnp_job (timer_s *timer) {
    isis_adjacency_t *adjacency = timer->data;
    isis_instance_t *instance = adjacency->instance;
    isis_config_t *config = instance->config;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    isis_lsp_t *lsp;
    hb_tree *lsdb;
    hb_itor *itor;
    bool next;

    int entries = 0;

    isis_pdu_t pdu = {0};
    uint8_t level = adjacency->level;
    uint16_t remaining_lifetime;

    isis_tlv_t *tlv;
    isis_lsp_entry_t *entry;

    bbl_ethernet_header_t eth = {0};
    bbl_isis_t isis = {0};

    struct timespec now;
    struct timespec ago;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Build PDU */
    if(level == ISIS_LEVEL_1) {
        isis_pdu_init(&pdu, ISIS_PDU_L1_CSNP);
        if(config->level1_auth && config->level1_key) {
            auth = config->level1_auth;
            key = config->level1_key;
        }
    } else {
        isis_pdu_init(&pdu, ISIS_PDU_L2_CSNP);
        if(config->level2_auth && config->level2_key) {
            auth = config->level2_auth;
            key = config->level2_key;
        }
    }
    isis_pdu_add_u16(&pdu, 0); /* PDU length */
    isis_pdu_add_bytes(&pdu, config->system_id, ISIS_SYSTEM_ID_LEN);
    isis_pdu_add_u8(&pdu, 0x0);
    isis_pdu_add_u64(&pdu, adjacency->csnp_start);
    isis_pdu_add_u64(&pdu, UINT64_MAX);
    /* TLV section */
    isis_pdu_add_tlv_auth(&pdu, auth, key);

    lsdb = adjacency->instance->level[adjacency->level-1].lsdb;
    itor = hb_itor_new(lsdb);
    if(adjacency->csnp_start) {
        next = hb_itor_search_ge(itor, &adjacency->csnp_start);
    } else {
        next = hb_itor_first(itor);
    }
    adjacency->csnp_start = 0;
    tlv = (isis_tlv_t *)PDU_CURSOR(&pdu);
    tlv->type = ISIS_TLV_LSP_ENTRIES;
    tlv->len = 0;
    PDU_BUMP_WRITE_BUFFER(&pdu, sizeof(isis_tlv_t));
    while(next) {
        lsp = *hb_itor_datum(itor);

        /* Calculate remaining lifetime and ignore if already expired. */
        timespec_sub(&ago, &now, &lsp->timestamp);
        if(ago.tv_sec < lsp->lifetime) {
            remaining_lifetime = lsp->lifetime - ago.tv_sec;

            if(tlv->len > UINT8_MAX-ISIS_LSP_ENTRY_LEN) {
                /* Open next LSP entry TLV */
                if(pdu.pdu_len+sizeof(isis_tlv_t)+ISIS_LSP_ENTRY_LEN > ISIS_MAX_PDU_LEN) {
                    adjacency->csnp_start = lsp->id;
                    break;
                }
                tlv = (isis_tlv_t *)PDU_CURSOR(&pdu);
                tlv->type = ISIS_TLV_LSP_ENTRIES;
                tlv->len = 0;
                PDU_BUMP_WRITE_BUFFER(&pdu, sizeof(isis_tlv_t));
            } else {
                if(pdu.pdu_len+ISIS_LSP_ENTRY_LEN > ISIS_MAX_PDU_LEN) {
                    /* All entries do not fit into single CSNP. */
                    adjacency->csnp_start = lsp->id;
                    break;
                }
            }
            tlv->len+=sizeof(isis_lsp_entry_t);
            entry = (isis_lsp_entry_t *)PDU_CURSOR(&pdu);
            entry->lifetime = htobe16(remaining_lifetime);
            entry->lsp_id = htobe64(lsp->id);
            entry->seq = htobe32(lsp->seq);
            entry->checksum = *(uint16_t*)PDU_OFFSET(&lsp->pdu, ISIS_OFFSET_LSP_CHECKSUM);
            PDU_BUMP_WRITE_BUFFER(&pdu, sizeof(isis_lsp_entry_t));
            entries++;
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);
    isis_pdu_update_len(&pdu);
    isis_pdu_update_auth(&pdu, key);

    if(adjacency->csnp_start) {
        /* Seems that not all LSP entries fitted into a single CSNP PDU,
         * therefore remember where we stopped and send next CSNP 
         * fragment in 10ms ... */
        *(uint64_t*)PDU_OFFSET(&pdu, ISIS_OFFSET_CSNP_LSP_END) = htobe64(adjacency->csnp_start++);
        timer_add(&adjacency->interface->ctx->timer_root, 
                  &adjacency->timer_csnp_next, 
                  "ISIS CSNP", 
                   0, 10*MSEC, adjacency,
                   &isis_csnp_job);
    }    

    if(!entries) {
        /* Do not send empty PSNP. */
        return;
    }

    /* Send packet ... */
    eth.type = ISIS_PROTOCOL_IDENTIFIER;
    eth.next = &isis;
    eth.src = adjacency->interface->mac;
    if(adjacency->level == ISIS_LEVEL_1) {
        eth.dst = g_isis_mac_all_l1;
        isis.type = ISIS_PDU_L1_CSNP;
    } else {
        eth.dst = g_isis_mac_all_l2;
        isis.type = ISIS_PDU_L2_CSNP;
    }
    isis.pdu = pdu.pdu;
    isis.pdu_len = pdu.pdu_len;
    if(bbl_send_to_buffer(adjacency->interface, &eth) == BBL_SEND_OK) {
        LOG(DEBUG, "ISIS TX %s on interface %s\n",
            isis_pdu_type_string(isis.type), adjacency->interface->name);
        adjacency->stats.csnp_tx++;
        /* Clear PSNP tree after CSNP was send */
        hb_tree_clear(adjacency->psnp_tree, isis_psnp_free);
        timer_del(adjacency->timer_psnp_next);
        adjacency->timer_psnp_started = false;
    }
    return;
}

void
isis_csnp_handler_rx(bbl_interface_s *interface, isis_pdu_t *pdu, uint8_t level) {

    isis_adjacency_t *adjacency = interface->isis_adjacency[level-1];
    isis_instance_t  *instance  = adjacency->instance;
    isis_config_t    *config    = instance->config;

    uint64_t csnp_scan = ++g_csnp_scan;

    uint64_t lsp_start;
    uint64_t lsp_end;

    isis_lsp_t *lsp;
    hb_tree *lsdb;
    hb_itor *itor;
    bool next;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    if(!adjacency) {
        return;
    }
    adjacency->stats.csnp_rx++;
    
    lsp_start = be64toh(*(uint64_t*)PDU_OFFSET(pdu, ISIS_OFFSET_CSNP_LSP_START));
    lsp_end = be64toh(*(uint64_t*)PDU_OFFSET(pdu, ISIS_OFFSET_CSNP_LSP_END));

    if(level == ISIS_LEVEL_1 && config->level1_auth && config->level1_key) {
        auth = config->level1_auth;
        key = config->level1_key;
    } else if(level == ISIS_LEVEL_2 && config->level2_auth && config->level2_key) {
        auth = config->level2_auth;
        key = config->level2_key;
    }
    if(!isis_pdu_validate_auth(pdu, auth, key)) {
        LOG(ISIS, "ISIS RX %s-CSNP authentication failed on interface %s\n",
            isis_level_string(level), interface->name);
    }

    /* Get LSDB */
    lsdb = adjacency->instance->level[level-1].lsdb;
    isis_lsp_process_entries(adjacency, lsdb, pdu, csnp_scan);
    itor = hb_itor_new(lsdb);
    next = hb_itor_search_ge(itor, &lsp_start);
    while(next) {
        lsp = *hb_itor_datum(itor);
        if(lsp->id > lsp_end) {
            break;
        }
        if(lsp->csnp_scan != csnp_scan) {
            /* Add LSP to flood tree. */
            isis_lsp_flood_adjacency(lsp, adjacency);
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);
    return;
}