/*
 * BNG Blaster (BBL) - IS-IS PSNP
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

void
isis_psnp_job(timer_s *timer)
{
    isis_adjacency_s *adjacency = timer->data;
    isis_instance_s *instance = adjacency->instance;
    isis_config_s *config = instance->config;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    isis_lsp_s *lsp;
    void **search = NULL;

    uint64_t lsp_id_zero = 0;
    int entries = 0;

    isis_pdu_s pdu = {0};
    uint8_t level = adjacency->level;
    uint16_t remaining_lifetime;

    isis_tlv_s *tlv;
    isis_lsp_entry_s *entry;

    bbl_ethernet_header_s eth = {0};
    bbl_isis_s isis = {0};

    struct timespec now;
    struct timespec ago;
    clock_gettime(CLOCK_MONOTONIC, &now);

    adjacency->timer_psnp_started = false;

    /* Build PDU */
    if(level == ISIS_LEVEL_1) {
        isis_pdu_init(&pdu, ISIS_PDU_L1_PSNP);
        if(config->level1_auth_psnp) {
            auth = config->level1_auth;
            key = config->level1_key;
        }
    } else {
        isis_pdu_init(&pdu, ISIS_PDU_L2_PSNP);
        if(config->level2_auth_psnp) {
            auth = config->level2_auth;
            key = config->level2_key;
        }
    }
    isis_pdu_add_u16(&pdu, 0); /* PDU length */
    isis_pdu_add_bytes(&pdu, config->system_id, ISIS_SYSTEM_ID_LEN);
    isis_pdu_add_u8(&pdu, 0x0);
    /* TLV section */
    isis_pdu_add_tlv_auth(&pdu, auth, key);

    tlv = (isis_tlv_s *)ISIS_PDU_CURSOR(&pdu);
    tlv->type = ISIS_TLV_LSP_ENTRIES;
    tlv->len = 0;
    ISIS_PDU_BUMP_WRITE_BUFFER(&pdu, sizeof(isis_tlv_s));

    search = hb_tree_search_gt(adjacency->psnp_tree, &lsp_id_zero);
    while(search) {
        lsp = *search;

        if(lsp->deleted) {
            /* Ignore deleted LSP. */
            assert(lsp->refcount);
            if(lsp->refcount) lsp->refcount--;
            hb_tree_remove(adjacency->psnp_tree, &lsp->id);
            search = hb_tree_search_gt(adjacency->psnp_tree, &lsp_id_zero);
            continue;
        }

        /* Calculate remaining lifetime. */
        timespec_sub(&ago, &now, &lsp->timestamp);
        if(lsp->expired || ago.tv_sec >= lsp->lifetime) {
            /* Expired! */
            remaining_lifetime = 0;
        } else {
            remaining_lifetime = lsp->lifetime - ago.tv_sec;
        }

        if(tlv->len > UINT8_MAX-ISIS_LSP_ENTRY_LEN) {
            /* Open next LSP entry TLV. */
            if(pdu.pdu_len+sizeof(isis_tlv_s)+ISIS_LSP_ENTRY_LEN > ISIS_MAX_PDU_LEN) {
                /* All entries do not fit into single PSNP. */
                adjacency->timer_psnp_started = true;
                timer_add(&g_ctx->timer_root, &adjacency->timer_psnp_next, 
                          "ISIS PSNP", 0, 10*MSEC, adjacency, &isis_psnp_job);
                break;
            }
            tlv = (isis_tlv_s *)ISIS_PDU_CURSOR(&pdu);
            tlv->type = ISIS_TLV_LSP_ENTRIES;
            tlv->len = 0;
            ISIS_PDU_BUMP_WRITE_BUFFER(&pdu, sizeof(isis_tlv_s));
        } else {
            if(pdu.pdu_len+ISIS_LSP_ENTRY_LEN > ISIS_MAX_PDU_LEN) {
                /* All entries do not fit into single PSNP. */
                adjacency->timer_psnp_started = true;
                timer_add(&g_ctx->timer_root, &adjacency->timer_psnp_next, 
                          "ISIS PSNP", 0, 10*MSEC, adjacency, &isis_psnp_job);
                break;
            }
        }
        tlv->len+=sizeof(isis_lsp_entry_s);
        entry = (isis_lsp_entry_s *)ISIS_PDU_CURSOR(&pdu);
        entry->lsp_id = htobe64(lsp->id);
        if(lsp->seq == 0) {
            entry->lifetime = 0;
            entry->seq = 0;
            entry->checksum = 0;
        } else {
            entry->lifetime = htobe16(remaining_lifetime);
            entry->seq = htobe32(lsp->seq);
            entry->checksum = *(uint16_t*)ISIS_PDU_OFFSET(&lsp->pdu, ISIS_OFFSET_LSP_CHECKSUM);
        }
        ISIS_PDU_BUMP_WRITE_BUFFER(&pdu, sizeof(isis_lsp_entry_s));
        entries++;

        assert(lsp->refcount);
        if(lsp->refcount) lsp->refcount--;
        hb_tree_remove(adjacency->psnp_tree, &lsp->id);
        search = hb_tree_search_gt(adjacency->psnp_tree, &lsp_id_zero);
    }
    isis_pdu_update_len(&pdu);
    isis_pdu_update_auth(&pdu, key);

    if(!entries) {
        /* Do not send empty PSNP. */
        return;
    }

    /* Send packet ... */
    eth.type = ISIS_PROTOCOL_IDENTIFIER;
    eth.next = &isis;
    eth.src = adjacency->interface->mac;
    eth.vlan_outer = adjacency->interface->vlan;
    if(adjacency->level == ISIS_LEVEL_1) {
        eth.dst = g_isis_mac_all_l1;
        isis.type = ISIS_PDU_L1_PSNP;
    } else {
        eth.dst = g_isis_mac_all_l2;
        isis.type = ISIS_PDU_L2_PSNP;
    }
    isis.pdu = pdu.pdu;
    isis.pdu_len = pdu.pdu_len;
    if(bbl_txq_to_buffer(adjacency->interface->txq, &eth) == BBL_TXQ_OK) {
        LOG(PACKET, "ISIS TX %s on interface %s\n",
            isis_pdu_type_string(isis.type), adjacency->interface->name);
        adjacency->stats.psnp_tx++;
        adjacency->interface->stats.isis_tx++;
    } else {
        LOG(ERROR, "Failed to send ISIS %s on interface %s\n",
            isis_pdu_type_string(isis.type), adjacency->interface->name);
    }
    return;
}

/**
 * isis_psnp_handler_rx 
 * 
 * @param interface receive interface
 * @param pdu received ISIS PDU
 * @param level ISIS level
 */
void
isis_psnp_handler_rx(bbl_network_interface_s *interface, isis_pdu_s *pdu, uint8_t level) {

    isis_adjacency_s *adjacency = interface->isis_adjacency[level-1];
    isis_instance_s  *instance  = NULL;
    isis_config_s    *config    = NULL;

    hb_tree *lsdb;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    if(!adjacency) {
        return;
    }
    instance = adjacency->instance;
    config = instance->config;

    adjacency->stats.psnp_rx++;
    
    if(level == ISIS_LEVEL_1 && config->level1_auth_psnp) {
        auth = config->level1_auth;
        key = config->level1_key;
    } else if(level == ISIS_LEVEL_2 && config->level2_auth_psnp) {
        auth = config->level2_auth;
        key = config->level2_key;
    }

    if(!isis_pdu_validate_auth(pdu, auth, key)) {
        LOG(ISIS, "ISIS RX %s-PSNP authentication failed on interface %s\n",
            isis_level_string(level), interface->name);
        return;
    }

    /* Get LSDB */
    lsdb = adjacency->instance->level[level-1].lsdb;
    isis_lsp_process_entries(adjacency, lsdb, pdu, 0);
    return;
}


/**
 * isis_psnp_tree_add 
 */
void
isis_psnp_tree_add(isis_adjacency_s *adjacency, isis_lsp_s *lsp)
{
    dict_insert_result result = hb_tree_insert(adjacency->psnp_tree, &lsp->id);
    if(result.inserted) {
        *result.datum_ptr = lsp;
        lsp->refcount++;
        if(!adjacency->timer_psnp_started) {
            adjacency->timer_psnp_started = true;
            timer_add(&g_ctx->timer_root, &adjacency->timer_psnp_next, 
                        "ISIS PSNP", 1, 0, adjacency, &isis_psnp_job);
        }
    }
}
