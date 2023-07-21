/*
 * BNG Blaster (BBL) - IS-IS Functions
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
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
isis_flood_entry_free(void *key, void *ptr)
{
    isis_flood_entry_s *entry = ptr;

    UNUSED(key);
    if(entry->lsp->refcount) {
        entry->lsp->refcount--;
    }
    free(entry);
}

void
isis_psnp_free(void *key, void *ptr)
{
    isis_lsp_s *lsp = ptr;

    UNUSED(key);
    assert(lsp->refcount);
    if(lsp->refcount) lsp->refcount--;
}

/**
 * isis_init
 * 
 * This function inits all IS-IS instances. 
 */
bool
isis_init() {
    isis_config_s *config = g_ctx->config.isis_config;
    isis_instance_s *instance = NULL;
    uint8_t level;

    while(config) {
        LOG(ISIS, "Init IS-IS instance %u\n", config->id);
        if(instance) {
            instance->next = calloc(1, sizeof(isis_instance_s));
            instance = instance->next;
        } else {
            instance = calloc(1, sizeof(isis_instance_s));
            g_ctx->isis_instances = instance;
        }
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

        if(config->external_mrt_file) {
            if(!isis_mrt_load(instance, config->external_mrt_file, true)) {
                LOG(ISIS, "Failed to load MRT file %s\n", config->external_mrt_file);
                return false;
            }
        }

        /* Start LSP garbage collection job. */
        timer_add_periodic(&g_ctx->timer_root, &instance->timer_lsp_gc, 
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
 * @param interface pointer to interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 */
void
isis_handler_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth) {
    protocol_error_t result;
    isis_pdu_s pdu = {0};

    bbl_isis_s *isis = eth->next;

    interface->stats.isis_rx++;
    result = isis_pdu_load(&pdu, isis->pdu, isis->pdu_len);
    if(result != PROTOCOL_SUCCESS) {
        LOG(ISIS, "ISIS RX %s PDU decode error on interface %s\n", 
            isis_pdu_type_string(pdu.pdu_type), interface->name);
        interface->stats.isis_rx_error++;
        return;
    }

    if(!isis_pdu_validate_checksum(&pdu)) {
        LOG(ISIS, "ISIS RX %s PDU checksum error on interface %s\n", 
            isis_pdu_type_string(pdu.pdu_type), interface->name);
        interface->stats.isis_rx_error++;
        return;
    }

    LOG(PACKET, "ISIS RX %s on interface %s\n",
        isis_pdu_type_string(pdu.pdu_type), interface->name);

    switch(pdu.pdu_type) {
        case ISIS_PDU_P2P_HELLO:
            isis_p2p_hello_handler_rx(interface, &pdu);
            break;
        case ISIS_PDU_L1_LSP:
            isis_lsp_handler_rx(interface, &pdu, ISIS_LEVEL_1);
            break;
        case ISIS_PDU_L2_LSP:
            isis_lsp_handler_rx(interface, &pdu, ISIS_LEVEL_2);
            break;
        case ISIS_PDU_L1_CSNP:
            isis_csnp_handler_rx(interface, &pdu, ISIS_LEVEL_1);
            break;
        case ISIS_PDU_L2_CSNP:
            isis_csnp_handler_rx(interface, &pdu, ISIS_LEVEL_2);
            break;
        case ISIS_PDU_L1_PSNP:
            isis_psnp_handler_rx(interface, &pdu, ISIS_LEVEL_1);
            break;
        case ISIS_PDU_L2_PSNP:
            isis_psnp_handler_rx(interface, &pdu, ISIS_LEVEL_2);
            break;
        default:
            break;
    }
    return;
}

void
isis_teardown_job(timer_s *timer) {
    isis_instance_s *instance = timer->data;
    isis_adjacency_s *adjacency;
    for(int i=0; i<ISIS_LEVELS; i++) {
        adjacency = instance->level[i].adjacency;
        while(adjacency) {
            isis_adjacency_down(adjacency);
            adjacency = adjacency->next;
        }
    }
}

/**
 * isis_teardown
 * 
 * This function stops all IS-IS instances. 
 */
void
isis_teardown()
{
    isis_instance_s *instance = g_ctx->isis_instances;
    while(instance) {
        if(!instance->teardown) {
            LOG(ISIS, "Teardown IS-IS instance %u\n", instance->config->id);
            instance->teardown = true;
            for(int i=0; i<ISIS_LEVELS; i++) {
                if(instance->level[i].adjacency) {
                    isis_lsp_self_update(instance, i+1);
                    isis_lsp_purge_all_external(instance, i+1);
                }
            }

            timer_add(&g_ctx->timer_root, &instance->timer_teardown, 
                      "ISIS TEARDOWN", instance->config->teardown_time, 0, instance,
                      &isis_teardown_job);
        }
        instance = instance->next;
    }
}