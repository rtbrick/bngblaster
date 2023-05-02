/*
 * BNG Blaster (BBL) - IS-IS LSP
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

/**
 * isis_lsp_flood 
 * 
 * This function adds an LSP to the 
 * given adjacency flood tree. 
 * 
 * @param lsp LSP
 * @param adjacency ISIS adjacency
 */
void
isis_lsp_flood_adjacency(isis_lsp_s *lsp, isis_adjacency_s *adjacency)
{
    void **search = NULL;
    dict_insert_result result; 
    isis_flood_entry_s *flood;

    /* Add to flood tree if not already present. */
    search = hb_tree_search(adjacency->flood_tree, &lsp->id);
    if(search) {
        flood = *search;
        flood->wait_ack = false;
        flood->tx_count = 0;
    } else {
        result = hb_tree_insert(adjacency->flood_tree,  &lsp->id);
        if(result.inserted) {
            flood = calloc(1, sizeof(isis_flood_entry_s));
            flood->lsp = lsp;
            *result.datum_ptr = flood;
            lsp->refcount++;
        } else {
            LOG_NOARG(ISIS, "Failed to add LSP to flood-tree\n");
        }
    }
}

/**
 * isis_lsp_flood 
 * 
 * This function adds an LSP to all
 * flood trees of the same instance
 * where neighbor system-id is different 
 * to source system-id. 
 * 
 * @param lsp LSP
 */
void
isis_lsp_flood(isis_lsp_s *lsp)
{
    isis_adjacency_s *adjacency;

    /* Iterate over all adjacencies of the corresponding 
     * instance and with the same level. */
    adjacency = lsp->instance->level[lsp->level-1].adjacency;
    while(adjacency) {
        if(adjacency->state != ISIS_ADJACENCY_STATE_UP) {
            goto NEXT;
        }
        if(lsp->source.type == ISIS_SOURCE_ADJACENCY) {
            if(lsp->source.adjacency == adjacency) {
                /* Do not flood over the adjacency from where LSP was received. */
                goto NEXT;
            }
            if(memcmp(adjacency->peer->system_id, 
                      lsp->source.adjacency->peer->system_id, 
                      ISIS_SYSTEM_ID_LEN) == 0) {
                /* Do not flood to the neighbor from where LSP was received. */
                goto NEXT;
            }
        }

        isis_lsp_flood_adjacency(lsp, adjacency);
NEXT:
        adjacency = adjacency->next;
    }
}

/**
 * isis_lsp_process_entries 
 * 
 * This function iterate of all LSP entries
 * of the given PDU (CSNP or PSNP) and compares
 * them the LSP database. 
 * 
 * @param adjacency ISIS adjacency
 * @param lsdb ISIS LSP database
 * @param pdu received ISIS PDU
 * @param csnp_scan CSNP scan/job identifier
 */
void
isis_lsp_process_entries(isis_adjacency_s *adjacency, hb_tree *lsdb, isis_pdu_s *pdu, uint64_t csnp_scan)
{
    isis_tlv_s *tlv;
    isis_lsp_s *lsp;
    isis_lsp_entry_s *lsp_entry;

    dict_remove_result removed;
    void **search = NULL;

    uint64_t lsp_id;
    uint32_t seq;
    uint8_t  offset;

    /* Iterate over all LSP entry TLV's. */
    tlv = isis_pdu_first_tlv(pdu);
    while(tlv) {
        if(tlv->type == ISIS_TLV_LSP_ENTRIES) {
            /* Each TLV can contain multiple LSP entries. */
            offset = 0;
            while(offset + ISIS_LSP_ENTRY_LEN <= tlv->len) {
                lsp_entry = (isis_lsp_entry_s *)(tlv->value+offset);
                offset += ISIS_LSP_ENTRY_LEN;
                lsp_id = be64toh(lsp_entry->lsp_id);
                search = hb_tree_search(lsdb, &lsp_id);
                if(search) {
                    lsp = *search;
                    lsp->csnp_scan = csnp_scan;
                    seq = be32toh(lsp_entry->seq);
                    if(seq < lsp->seq) {
                        /* Peer has older version of LSP, let's send
                         * them an update. */
                        isis_lsp_flood_adjacency(lsp, adjacency);
                    } else {
                        /* Ack LSP by removing them from flood tree. */
                        removed = hb_tree_remove(adjacency->flood_tree, &lsp->id);
                        if(removed.removed) {
                            if(lsp->refcount) lsp->refcount--;
                            free(removed.datum);
                        }
                    }
                }
            }
        }
        tlv = isis_pdu_next_tlv(pdu);
    }
}

void
isis_lsp_gc_job(timer_s *timer)
{
    isis_instance_s *instance = timer->data;

    isis_lsp_s *lsp;
    hb_itor *itor;
    bool next;

    dict_remove_result removed;

    for(int i=0; i<ISIS_LEVELS; i++) {
        if(instance->level[i].lsdb) {
            itor = hb_itor_new(instance->level[i].lsdb);
            next = hb_itor_first(itor);
            while(next) {
                lsp = *hb_itor_datum(itor);
                next = hb_itor_next(itor);
                if(lsp && lsp->expired && lsp->refcount == 0) {
                    timer_del(lsp->timer_lifetime);
                    timer_del(lsp->timer_refresh);
                    removed = hb_tree_remove(instance->level[i].lsdb, &lsp->id);
                    if(removed.removed) {
                        free(lsp);
                    }
                }
            }
            hb_itor_free(itor);
        }
    }
}

void
isis_lsp_retry_job(timer_s *timer)
{
    isis_adjacency_s *adjacency = timer->data;

    isis_flood_entry_s *entry;
    hb_itor *itor;
    bool next;

    uint16_t lsp_retry_interval = adjacency->instance->config->lsp_retry_interval;

    struct timespec now;
    struct timespec ago;
    clock_gettime(CLOCK_MONOTONIC, &now);

    itor = hb_itor_new(adjacency->flood_tree);
    next = hb_itor_first(itor);
    while(next) {
        entry = *hb_itor_datum(itor);
        if(entry->wait_ack) {
            timespec_sub(&ago, &now, &entry->tx_timestamp);
            if(ago.tv_sec > lsp_retry_interval) {
                entry->wait_ack = false;
            }
        } else {
            break;
        }
        next = hb_itor_next(itor);
    }
}

void
isis_lsp_purge_job(timer_s *timer)
{
    isis_lsp_s *lsp = timer->data;
    lsp->expired = true;
    lsp->deleted = true;
}

void
isis_lsp_lifetime_job(timer_s *timer)
{
    isis_lsp_s *lsp = timer->data;
    lsp->expired = true;

    LOG(ISIS, "ISIS %s-LSP %s (source %s seq %u) lifetime expired (%us)\n", 
        isis_level_string(lsp->level), 
        isis_lsp_id_to_str(&lsp->id),
        isis_source_string(lsp->source.type),
        lsp->seq, lsp->lifetime);
}

void
isis_lsp_lifetime(isis_lsp_s *lsp)
{
    timer_del(lsp->timer_refresh);
    if(lsp->lifetime > 0) {
        timer_add(&g_ctx->timer_root, 
                  &lsp->timer_lifetime, 
                  "ISIS LIFETIME", lsp->lifetime, 0, lsp,
                  &isis_lsp_lifetime_job);
    } else {
        timer_add(&g_ctx->timer_root, 
                  &lsp->timer_lifetime, 
                  "ISIS PURGE", 60, 0, lsp,
                  &isis_lsp_purge_job);
    }
    timer_no_smear(lsp->timer_lifetime);
}

void
isis_lsp_refresh(isis_lsp_s *lsp)
{
    isis_pdu_s *pdu = &lsp->pdu;

    lsp->seq++;
    lsp->expired = false;

    *(uint32_t*)PDU_OFFSET(&lsp->pdu, ISIS_OFFSET_LSP_SEQ) = htobe32(lsp->seq);
    clock_gettime(CLOCK_MONOTONIC, &lsp->timestamp);
    isis_pdu_update_len(pdu);
    isis_pdu_update_auth(pdu, lsp->auth_key);
    isis_pdu_update_lifetime(pdu, lsp->lifetime);
    isis_pdu_update_checksum(pdu);
    isis_lsp_flood(lsp);
}

void
isis_lsp_refresh_job(timer_s *timer)
{
    isis_lsp_s *lsp = timer->data;
    isis_lsp_refresh(lsp);
}

void
isis_lsp_sx_job(timer_s *timer)
{
    isis_adjacency_s *adjacency = timer->data;
    isis_flood_entry_s *entry;
    isis_lsp_s *lsp;
    hb_itor *itor;
    bool next;
    uint16_t window = adjacency->window_size;

    bbl_ethernet_header_s eth = {0};
    bbl_isis_s isis = {0};

    struct timespec now;
    struct timespec ago;
    uint16_t remaining_lifetime = 0;

    clock_gettime(CLOCK_MONOTONIC, &now);

    eth.type = ISIS_PROTOCOL_IDENTIFIER;
    eth.next = &isis;
    eth.src = adjacency->interface->mac;
    eth.vlan_outer = adjacency->interface->vlan;
    if(adjacency->level == ISIS_LEVEL_1) {
        eth.dst = g_isis_mac_all_l1;
        isis.type = ISIS_PDU_L1_LSP;
    } else {
        eth.dst = g_isis_mac_all_l2;
        isis.type = ISIS_PDU_L2_LSP;
    }
    
    itor = hb_itor_new(adjacency->flood_tree);
    next = hb_itor_first(itor);
    while(next) {
        entry = *hb_itor_datum(itor);
        if(!entry->wait_ack) {
            lsp = entry->lsp;

            LOG(PACKET, "ISIS TX %s-LSP %s (seq %u) on interface %s\n", 
                isis_level_string(adjacency->level), 
                isis_lsp_id_to_str(&lsp->id), 
                lsp->seq,
                adjacency->interface->name);

            /* Update lifetime */
            timespec_sub(&ago, &now, &lsp->timestamp);
            if(ago.tv_sec < lsp->lifetime) {
                remaining_lifetime = lsp->lifetime - ago.tv_sec;
            }
            isis_pdu_update_lifetime(&lsp->pdu, remaining_lifetime);

            isis.pdu = lsp->pdu.pdu;
            isis.pdu_len = lsp->pdu.pdu_len;
            if(bbl_txq_to_buffer(adjacency->interface->txq, &eth) != BBL_TXQ_OK) {
                break;
            }
            entry->wait_ack = true;
            entry->tx_count++;
            entry->tx_timestamp.tv_sec = now.tv_sec;
            entry->tx_timestamp.tv_nsec = now.tv_nsec;
            adjacency->stats.lsp_tx++;
            adjacency->interface->stats.isis_tx++;
            if(window) window--;
            if(window == 0) break;
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);
}

isis_lsp_s *
isis_lsp_new(uint64_t id, uint8_t level, isis_instance_s *instance)
{
    isis_lsp_s *lsp = calloc(1, sizeof(isis_lsp_s));
    lsp->id = id;
    lsp->level = level;
    lsp->instance = instance;
    return lsp;
}

static void
isis_lsp_final(isis_lsp_s *lsp)
{
    isis_pdu_s *pdu = &lsp->pdu;
    isis_pdu_update_len(pdu);
    isis_pdu_update_auth(pdu, lsp->auth_key);
    isis_pdu_update_lifetime(pdu, lsp->lifetime);
    if(lsp->lifetime > 0) {
        isis_pdu_update_checksum(pdu);
    }
}

static isis_lsp_s *
isis_lsp_fragment(isis_instance_s *instance, uint8_t level, uint8_t fragment, bool purge)
{
    isis_config_s *config = instance->config;

    isis_lsp_s *lsp = NULL;
    isis_pdu_s *pdu = NULL;

    uint64_t lsp_id = htobe64(fragment);
    uint16_t refresh_interval = 0;

    hb_tree *lsdb;
    void **search = NULL;
    dict_insert_result result;

    isis_auth_type auth_type = ISIS_AUTH_NONE;

    /* Create LSP-ID */
    memcpy(&lsp_id, &config->system_id, ISIS_SYSTEM_ID_LEN);
    lsp_id = be64toh(lsp_id);

    /* Get LSDB */
    lsdb = instance->level[level-1].lsdb;
    search = hb_tree_search(lsdb, &lsp_id);
    if(search) {
        /* Update existing LSP. */
        lsp = *search;
    } else {
        /* Create new LSP. */
        lsp = isis_lsp_new(lsp_id, level, instance);
        result = hb_tree_insert(lsdb,  &lsp->id);
        if(result.inserted) {
            *result.datum_ptr = lsp;
        } else {
            LOG_NOARG(ISIS, "Failed to add LSP to LSDB\n");
            return NULL;
        }
    }

    lsp->level = level;
    lsp->source.type = ISIS_SOURCE_SELF;
    lsp->seq++;
    lsp->instance = instance;

    clock_gettime(CLOCK_MONOTONIC, &lsp->timestamp);
    if(purge || instance->teardown) {
        lsp->lifetime = 0;
        isis_lsp_lifetime(lsp);
    } else {
        lsp->lifetime = config->lsp_lifetime;
        refresh_interval = lsp->lifetime - 300;
        if(config->lsp_refresh_interval < refresh_interval) {
            refresh_interval = config->lsp_refresh_interval;
        }
        timer_del(lsp->timer_lifetime);
        timer_add_periodic(&g_ctx->timer_root, &lsp->timer_refresh, 
                           "ISIS LSP REFRESH", refresh_interval, 3, lsp, 
                           &isis_lsp_refresh_job);
    }

    /* Build PDU */
    pdu = &lsp->pdu;
    if(level == ISIS_LEVEL_1) {
        isis_pdu_init(pdu, ISIS_PDU_L1_LSP);
        auth_type = config->level1_auth;
        lsp->auth_key = config->level1_key;
    } else {
        isis_pdu_init(pdu, ISIS_PDU_L2_LSP);
        auth_type = config->level2_auth;
        lsp->auth_key = config->level2_key;
    }
    
    /* PDU header */
    isis_pdu_add_u16(pdu, 0);
    isis_pdu_add_u16(pdu, 0);
    isis_pdu_add_u64(pdu, lsp_id);
    isis_pdu_add_u32(pdu, lsp->seq);
    isis_pdu_add_u16(pdu, 0);
    isis_pdu_add_u8(pdu, 0x03); 

    /* Add authentication TLV */
    isis_pdu_add_tlv_auth(pdu, auth_type, lsp->auth_key);

    return lsp;
}

/**
 * This function adds/updates 
 * the self originated LSP entries. 
 *
 * @param instance  ISIS instance
 * @param level ISIS level
 * @return true (success) / false (error)
 */
bool
isis_lsp_self_update(isis_instance_s *instance, uint8_t level)
{
    isis_config_s    *config    = instance->config;
    isis_adjacency_s *adjacency = NULL;

    isis_lsp_s *lsp;
    isis_pdu_s *pdu;

    uint8_t  fragment = 0;
    
    ipv4_prefix loopback_prefix;

    isis_external_connection_s *external_connection = NULL;

    lsp = isis_lsp_fragment(instance, level, fragment, false);
    if(!lsp) return false;
    pdu = &lsp->pdu;

    /* TLV section */
    isis_pdu_add_tlv_area(pdu, config->area, config->area_count);
    isis_pdu_add_tlv_protocols(pdu, config->protocol_ipv4, config->protocol_ipv6);
    isis_pdu_add_tlv_hostname(pdu, (char*)config->hostname);
    isis_pdu_add_tlv_ipv4_int_address(pdu, config->router_id);
    isis_pdu_add_tlv_te_router_id(pdu, config->router_id);

    loopback_prefix.address = config->router_id;
    loopback_prefix.len = 32;
    if(config->sr_node_sid) {
        /* Add Prefix-SID sub-TLV */
        isis_sub_tlv_t stlv = {0};
        uint8_t prefix_sid[6] = {0};
        stlv.type = 3;
        stlv.len = 6;
        stlv.value = prefix_sid;
        prefix_sid[0] = 64; /* N-Flag */
        prefix_sid[1] = 0;  /* SPF */
        *(uint32_t*)&prefix_sid[2] = htobe32(config->sr_node_sid);
        isis_pdu_add_tlv_ext_ipv4_reachability(pdu, &loopback_prefix, 0, &stlv);
    } else {
        isis_pdu_add_tlv_ext_ipv4_reachability(pdu, &loopback_prefix, 0, NULL);
    }

    if(config->sr_base && config->sr_range) {
        isis_pdu_add_tlv_router_cap(pdu, config->router_id, 
            config->protocol_ipv4, config->protocol_ipv6, 
            config->sr_base, config->sr_range);
    }

    /* Add link networks */
    adjacency = instance->level[level-1].adjacency;
    while(adjacency) {
        if(adjacency->state != ISIS_ADJACENCY_STATE_UP) {
            goto NEXT;
        }

        if(PDU_REMAINING(pdu) < 48) {
            isis_lsp_final(lsp);
            isis_lsp_flood(lsp);
            if(fragment == UINT8_MAX) return false;
            lsp = isis_lsp_fragment(instance, level, ++fragment, false);
            if(!lsp) return false;
            pdu = &lsp->pdu;
        }

        if(config->protocol_ipv4 && adjacency->interface->ip.len) {
            isis_pdu_add_tlv_ext_ipv4_reachability(pdu, 
                &adjacency->interface->ip, 
                adjacency->metric, NULL);
        }
        if(config->protocol_ipv6 && adjacency->interface->ip6.len) {
            isis_pdu_add_tlv_ipv6_reachability(pdu, 
                &adjacency->interface->ip6, 
                adjacency->metric);
        }
        isis_pdu_add_tlv_ext_reachability(pdu, 
            adjacency->peer->system_id, 
            adjacency->metric);
NEXT:
        adjacency = adjacency->next;
    }
    
    external_connection = config->external_connection;
    while(external_connection) {
        if(PDU_REMAINING(pdu) < 16) {
            isis_lsp_final(lsp);
            isis_lsp_flood(lsp);
            if(fragment == UINT8_MAX) return false;
            lsp = isis_lsp_fragment(instance, level, ++fragment, false);
            if(!lsp) return false;
            pdu = &lsp->pdu;
        }

        isis_pdu_add_tlv_ext_reachability(pdu, 
            external_connection->system_id, 
            external_connection->level[level-1].metric);
        external_connection = external_connection->next;
    }

    isis_lsp_final(lsp);
    isis_lsp_flood(lsp);

    /* Purge remaining fragments if number of fragments has reduced. */
    while(fragment < instance->level[level-1].self_lsp_fragment) {
        lsp = isis_lsp_fragment(instance, level, ++fragment, true);
        isis_lsp_final(lsp);
        isis_lsp_flood(lsp);
    }
    instance->level[level-1].self_lsp_fragment = fragment;
    return true;
}

/**
 * isis_lsp_handler_rx 
 * 
 * @param interface receive interface
 * @param pdu received ISIS PDU
 * @param level ISIS level
 */
void
isis_lsp_handler_rx(bbl_network_interface_s *interface, isis_pdu_s *pdu, uint8_t level) {

    isis_adjacency_s *adjacency = interface->isis_adjacency[level-1];
    isis_instance_s  *instance  = NULL;
    isis_config_s    *config    = NULL;

    isis_lsp_s *lsp = NULL;
    uint64_t    lsp_id;
    uint32_t    seq;

    hb_tree *lsdb;
    void **search = NULL;
    dict_insert_result result;

    isis_auth_type auth = ISIS_AUTH_NONE;
    char *key = NULL;

    if(!adjacency) {
        return;
    }
    instance = adjacency->instance;
    config = instance->config;

    adjacency->stats.lsp_rx++;

    lsp_id = be64toh(*(uint64_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_ID));
    seq = be32toh(*(uint32_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_SEQ));

    LOG(PACKET, "ISIS RX %s-LSP %s (seq %u) on interface %s\n", 
        isis_level_string(level), 
        isis_lsp_id_to_str(&lsp_id), 
        seq, interface->name);

    if(level == ISIS_LEVEL_1 && config->level1_auth) {
        auth = config->level1_auth;
        key = config->level1_key;
    } else if(level == ISIS_LEVEL_2 && config->level2_auth) {
        auth = config->level2_auth;
        key = config->level2_key;
    }

    if(!isis_pdu_validate_auth(pdu, auth, key)) {
        LOG(ISIS, "ISIS RX %s-LSP %s (seq %u) authentication failed on interface %s\n",
        isis_level_string(level), 
        isis_lsp_id_to_str(&lsp_id), 
        seq, interface->name);
        return;
    }

    /* Get LSDB */
    lsdb = adjacency->instance->level[level-1].lsdb;
    search = hb_tree_search(lsdb, &lsp_id);
    if(search) {
        /* Update existing LSP. */
        lsp = *search;
        if(lsp->seq >= seq) {
            goto ACK;
        }
        if(lsp->source.type == ISIS_SOURCE_EXTERNAL) {
            /* Per default we will not overwrite 
             * external LSP. */
            if(config->external_auto_refresh) {
                /* With external-auto-refresh enabled, 
                 * the sequence number will be increased. */
                lsp->seq = seq;
                isis_lsp_refresh(lsp);
            }
            goto ACK;
        }
        if(lsp->source.type == ISIS_SOURCE_SELF) {
            /* We received a newer version of our own
             * self originated LSP. Therfore re-generate 
             * them with a sequence number higher than 
             * the received one. */
            lsp->seq = seq;
            isis_lsp_self_update(adjacency->instance, adjacency->level);
            goto ACK;
        }
    } else {
        /* Create new LSP. */
        lsp = isis_lsp_new(lsp_id, level, adjacency->instance);
        result = hb_tree_insert(lsdb,  &lsp->id);
        if(result.inserted) {
            *result.datum_ptr = lsp;
        } else {
            LOG_NOARG(ISIS, "Failed to add LSP to LSDB\n");
            return;
        }
    }

    lsp->level = level;
    lsp->source.type = ISIS_SOURCE_ADJACENCY;
    lsp->source.adjacency = adjacency;
    lsp->seq = seq;
    lsp->lifetime = be16toh(*(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME));
    lsp->expired = false;
    lsp->instance = adjacency->instance;
    clock_gettime(CLOCK_MONOTONIC, &lsp->timestamp);

    PDU_CURSOR_RST(pdu);
    memcpy(&lsp->pdu, pdu, sizeof(isis_pdu_s));

    isis_lsp_lifetime(lsp);
    isis_lsp_flood(lsp);

ACK:
    /* Add LSP to adjacency PSNP tree for acknowledgement. */
    result = hb_tree_insert(adjacency->psnp_tree,  &lsp->id);
    if(result.inserted) {
        *result.datum_ptr = lsp;
        lsp->refcount++;
        if(!adjacency->timer_psnp_started) {
            adjacency->timer_psnp_started = true;
            timer_add(&g_ctx->timer_root, &adjacency->timer_psnp_next, 
                      "ISIS PSNP", 1, 0, adjacency, &isis_psnp_job);
        }
    }
    return;
}

/**
 * isis_lsp_purge_external 
 * 
 * @param instance  ISIS instance
 * @param level ISIS level
 */
void
isis_lsp_purge_external(isis_instance_s *instance, uint8_t level)
{
    isis_config_s *config = instance->config;
    hb_tree *lsdb = instance->level[level-1].lsdb;

    isis_lsp_s *lsp;
    hb_itor *itor;
    bool next;

    isis_pdu_s *pdu;
    isis_auth_type auth_type = ISIS_AUTH_NONE;

    struct timespec now;

    if(!lsdb) {
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);

    itor = hb_itor_new(lsdb);
    next = hb_itor_first(itor);

    while(next) {
        lsp = *hb_itor_datum(itor);
        if(lsp && lsp->source.type == ISIS_SOURCE_EXTERNAL) {
            lsp->seq++;
            lsp->timestamp.tv_sec = now.tv_sec;
            lsp->timestamp.tv_nsec = now.tv_nsec;

            lsp->lifetime = 0;
            lsp->expired = true;
            isis_lsp_lifetime(lsp);

            /* Build PDU */
            pdu = &lsp->pdu;
            if(level == ISIS_LEVEL_1) {
                isis_pdu_init(pdu, ISIS_PDU_L1_LSP);
                auth_type = config->level1_auth;
                lsp->auth_key = config->level1_key;
            } else {
                isis_pdu_init(pdu, ISIS_PDU_L2_LSP);
                auth_type = config->level2_auth;
                lsp->auth_key = config->level2_key;
            }
        
            /* PDU header. */
            isis_pdu_add_u16(pdu, 0);
            isis_pdu_add_u16(pdu, 0);
            isis_pdu_add_u64(pdu, lsp->id);
            isis_pdu_add_u32(pdu, lsp->seq);
            isis_pdu_add_u16(pdu, 0);
            isis_pdu_add_u8(pdu, 0x03); 

            /* TLV section. */
            isis_pdu_add_tlv_auth(pdu, auth_type, lsp->auth_key);

            /* Update length and authentication. */
            isis_pdu_update_len(pdu);
            isis_pdu_update_auth(pdu, lsp->auth_key);

            /* Set checksum and lifetime to zero. */
            *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME) = 0;
            *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_CHECKSUM) = 0;

            isis_lsp_flood(lsp);
        }
        next = hb_itor_next(itor);
    }
}

/**
 * isis_lsp_update_external 
 * 
 * @param instance ISIS instance
 * @param pdu received ISIS PDU
 */
bool
isis_lsp_update_external(isis_instance_s *instance, isis_pdu_s *pdu)
{
    uint8_t level;

    isis_lsp_s *lsp = NULL;
    uint64_t lsp_id;
    uint32_t seq;
    uint16_t refresh_interval = 0;

    hb_tree *lsdb;
    void **search = NULL;
    dict_insert_result result;

    if(pdu->pdu_type == ISIS_PDU_L1_LSP) {
        level = ISIS_LEVEL_1;
    } else if(pdu->pdu_type == ISIS_PDU_L2_LSP) {
        level = ISIS_LEVEL_2;
    } else {
        return false;
    }

    lsp_id = be64toh(*(uint64_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_ID));
    seq = be32toh(*(uint32_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_SEQ));

    LOG(ISIS, "ISIS UPDATE %s-LSP %s (seq %u) from command\n", 
        isis_level_string(level), 
        isis_lsp_id_to_str(&lsp_id), 
        seq);

    lsdb = instance->level[level-1].lsdb;
    search = hb_tree_search(lsdb, &lsp_id);

    if(search) {
        /* Update existing LSP. */
        lsp = *search;
    } else {
        /* Create new LSP. */
        lsp = isis_lsp_new(lsp_id, level, instance);
        result = hb_tree_insert(lsdb,  &lsp->id);
        if(result.inserted) {
            *result.datum_ptr = lsp;
        } else {
            LOG_NOARG(ISIS, "Failed to add LSP to LSDB\n");
            return false;
        }
    }

    lsp->level = level;
    lsp->source.type = ISIS_SOURCE_EXTERNAL;
    lsp->source.adjacency = NULL;
    lsp->seq = seq;
    lsp->lifetime = be16toh(*(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME));
    lsp->expired = false;
    lsp->instance = instance;
    clock_gettime(CLOCK_MONOTONIC, &lsp->timestamp);

    PDU_CURSOR_RST(pdu);
    memcpy(&lsp->pdu, pdu, sizeof(isis_pdu_s));

    if(lsp->lifetime > 0 && instance->config->external_auto_refresh) {
        if(level == ISIS_LEVEL_1) {
            lsp->auth_key = instance->config->level1_key;
        } else {
            lsp->auth_key = instance->config->level2_key;
        }
        if(lsp->lifetime < ISIS_DEFAULT_LSP_LIFETIME_MIN) {
            /* Increase ISIS lifetime. */
            lsp->lifetime = ISIS_DEFAULT_LSP_LIFETIME_MIN;
            isis_lsp_refresh(lsp); 
        }
        refresh_interval = lsp->lifetime - 300;
        timer_add_periodic(&g_ctx->timer_root, &lsp->timer_refresh, 
                            "ISIS LSP REFRESH", refresh_interval, 3, lsp, 
                            &isis_lsp_refresh_job);
    } else {
        isis_lsp_lifetime(lsp);
    }

    isis_lsp_flood(lsp);
    return true;
}