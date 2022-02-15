/*
 * BNG Blaster (BBL) - IS-IS Functions
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

uint8_t g_isis_mac_p2p_hello[] = {0x09, 0x00, 0x2b, 0x00, 0x00, 0x05};
uint8_t g_isis_mac_all_l1[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x14};
uint8_t g_isis_mac_all_l2[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x15};

int
isis_lsp_id_compare(void *id1, void *id2)
{
    const uint64_t a = *(const uint64_t*)id1;
    const uint64_t b = *(const uint64_t*)id2;
    return (a > b) - (a < b);
}

void
isis_flood_entry_free(void *key, void *ptr) {
    isis_flood_entry_t *entry = ptr;

    UNUSED(key);
    if(entry->lsp->refcount) {
        entry->lsp->refcount--;
    }
    free(entry);
}

void
isis_psnp_free(void *key, void *ptr) {
    isis_lsp_t *lsp = ptr;

    UNUSED(key);
    if(lsp->refcount) {
        lsp->refcount--;
    }
}

/**
 * isis_init
 * 
 * This function inits all IS-IS instances. 
 * 
 * @param ctx global context
 */
bool
isis_init(bbl_ctx_s *ctx) {

    isis_config_t *config = ctx->config.isis_config;
    isis_instance_t *instance = NULL;
    uint8_t level;

    while(config) {
        LOG(ISIS, "Init IS-IS instance %u\n", config->id);
        if(instance) {
            instance->next = calloc(1, sizeof(isis_instance_t));
            instance = instance->next;
        } else {
            instance = calloc(1, sizeof(isis_instance_t));
            ctx->isis_instances = instance;
        }
        instance->ctx = ctx;
        instance->config = config;
        for(int i=0; i<ISIS_LEVELS; i++) {
            level = i+1;
            if(config->level & level) {
                instance->level[i].lsdb = hb_tree_new((dict_compare_func)isis_lsp_id_compare);
                if(!isis_lsp_self_update(instance, level)) {
                    LOG(ISIS, "Failed to generate self originated LSP for IS-IS instance %u\n", config->id);
                    return false;
                }
            }
        }

        if(config->external_lsp_mrt_file) {
            if(!isis_mrt_load(instance, config->external_lsp_mrt_file)) {
                LOG(ISIS, "Failed to load MRT file %s\n", config->external_lsp_mrt_file);
                return false;
            }
        }

        /* Start LSP garbage collection job. */
        timer_add_periodic(&ctx->timer_root, &instance->timer_lsp_gc, 
                           "ISIS LSP GC", ISIS_LSP_GC_INTERVAL, 0, instance,
                           &isis_lsp_gc_job);

        config = config->next;
    }
    return true;
}

/**
 * isis_handler_rx
 *
 * This function handles IS-IS packets received on network interfaces.
 *
 * @param eth pointer to ethernet header structure of received packet
 * @param interface pointer to interface on which packet was received
 */
void
isis_handler_rx(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    protocol_error_t result;
    isis_pdu_t pdu = {0};

    bbl_isis_t *isis = eth->next;

    interface->stats.isis_rx++;
    result = isis_pdu_load(&pdu, isis->pdu, isis->pdu_len);
    if(result != PROTOCOL_SUCCESS) {
        LOG(ISIS, "ISIS RX %s PDU decode error on interface %s\n", 
            isis_pdu_type_string(pdu.pdu_type), interface->name);
        interface->stats.packets_rx_drop_decode_error++;
        return;
    }

    if(!isis_pdu_validate_checksum(&pdu)) {
        LOG(ISIS, "ISIS RX %s PDU checksum error on interface %s\n", 
            isis_pdu_type_string(pdu.pdu_type), interface->name);
        return;
    }

    LOG(DEBUG, "ISIS RX %s on interface %s\n",
        isis_pdu_type_string(pdu.pdu_type), interface->name);

    switch (pdu.pdu_type) {
        case ISIS_PDU_P2P_HELLO:
            return isis_p2p_hello_handler_rx(interface, &pdu);
        case ISIS_PDU_L1_LSP:
            return isis_lsp_handler_rx(interface, &pdu, ISIS_LEVEL_1);
        case ISIS_PDU_L2_LSP:
            return isis_lsp_handler_rx(interface, &pdu, ISIS_LEVEL_2);
        case ISIS_PDU_L1_CSNP:
            return isis_csnp_handler_rx(interface, &pdu, ISIS_LEVEL_1);
        case ISIS_PDU_L2_CSNP:
            return isis_csnp_handler_rx(interface, &pdu, ISIS_LEVEL_2);
        case ISIS_PDU_L1_PSNP:
            return isis_psnp_handler_rx(interface, &pdu, ISIS_LEVEL_1);
        case ISIS_PDU_L2_PSNP:
            return isis_psnp_handler_rx(interface, &pdu, ISIS_LEVEL_2);
        default:
            break;
    }
    return;
}

void
isis_teardown_job(timer_s *timer) {
    isis_instance_t *instance = timer->data;
    isis_adjacency_t *adjacency;
    while(instance) {
        for(int i=0; i<ISIS_LEVELS; i++) {
            adjacency = instance->level[i].adjacency;
            while(adjacency) {
                isis_adjacency_down(adjacency);
                adjacency = adjacency->next;
            }
        }
        instance = instance->next;
    }
}

/**
 * isis_teardown
 * 
 * This function stops all IS-IS instances. 
 * 
 * @param ctx global context
 */
void
isis_teardown(bbl_ctx_s *ctx) {
    isis_instance_t *instance = ctx->isis_instances;
    while(instance) {
        if(!instance->teardown) {
            LOG(ISIS, "Teardown IS-IS instance %u\n", instance->config->id);
            instance->teardown = true;
            for(int i=0; i<ISIS_LEVELS; i++) {
                if(instance->level[i].adjacency) {
                    isis_lsp_self_update(instance, i+1);
                    isis_lsp_purge_external(instance, i+1);
                }
            }

            timer_add(&ctx->timer_root, &instance->timer_teardown, 
                      "ISIS TEARDOWN", instance->config->teardown_time, 0, instance,
                      &isis_teardown_job);
        }
        instance = instance->next;
    }
}