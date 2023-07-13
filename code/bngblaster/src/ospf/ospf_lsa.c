/*
 * BNG Blaster (BBL) - OSPF LSA
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

void
ospf_lsa_gc_job(timer_s *timer)
{
    ospf_instance_s *ospf_instance = timer->data;
    ospf_lsa_s *lsa;
    hb_itor *itor;
    bool next;

    dict_remove_result removed;

    if(!ospf_instance->lsdb) return;

    itor = hb_itor_new(ospf_instance->lsdb);
    next = hb_itor_first(itor);
    while(next) {
        lsa = *hb_itor_datum(itor);
        next = hb_itor_next(itor);
        if(lsa && lsa->deleted && lsa->refcount == 0) {
            timer_del(lsa->timer_lifetime);
            timer_del(lsa->timer_refresh);
            removed = hb_tree_remove(ospf_instance->lsdb, &lsa->key);
            if(removed.removed) {
                free(lsa);
            }
        }
    }
    hb_itor_free(itor);
}

void
ospf_lsa_update_age(ospf_lsa_s *lsa, struct timespec *now)
{
    struct timespec ago;
    uint16_t age;

    timespec_sub(&ago, now, &lsa->timestamp);
    age = lsa->age + ago.tv_sec;
    if(lsa->expired || age >= OSPF_LSA_MAX_AGE) {
        /* Expired! */
        age = OSPF_LSA_MAX_AGE;
    }
    *(uint16_t*)lsa->lsa = htobe16(age);
}

/**
 * ospf_lsa_flood_neighbor 
 * 
 * This function adds an LSA to the 
 * given neighbor flood tree. 
 * 
 * @param lsa lsa
 * @param neighbor OSPF neighbor
 */
void
ospf_lsa_flood_neighbor(ospf_lsa_s *lsa, ospf_neighbor_s *neighbor)
{
    void **search = NULL;
    dict_insert_result result; 
    ospf_flood_entry_s *flood;

    /* Add to flood tree if not already present. */
    search = hb_tree_search(neighbor->flood_tree, &lsa->key);
    if(search) {
        flood = *search;
        flood->wait_ack = false;
        flood->tx_count = 0;
    } else {
        result = hb_tree_insert(neighbor->flood_tree, &lsa->key);
        if(result.inserted) {
            flood = calloc(1, sizeof(ospf_flood_entry_s));
            flood->lsa = lsa;
            *result.datum_ptr = flood;
            lsa->refcount++;
        } else {
            LOG_NOARG(OSPF, "Failed to add LSA to flood-tree\n");
        }
    }
}

/**
 * ospf_lsa_flood 
 * 
 * This function adds an lsa to all
 * flood trees of the same instance
 * where neighbor router-id is different 
 * to source router-id. 
 * 
 * @param lsa lsa
 */
void
ospf_lsa_flood(ospf_lsa_s *lsa)
{
    ospf_interface_s *interface;
    ospf_neighbor_s *neighbor;

    /* Iterate over all adjacencies of the corresponding 
     * instance and with the same level. */
    interface = lsa->instance->interfaces;
    while(interface) {
        neighbor = interface->neighbors;

        while(neighbor) {
            if(neighbor->state < OSPF_NBSTATE_EXCHANGE) {
                goto NEXT;
            }
            if(lsa->source.router_id == neighbor->router_id) {
                /* Do not flood over the neighbor from where LSA was received. */
                goto NEXT;
            }
            ospf_lsa_flood_neighbor(lsa, neighbor);
NEXT:
            neighbor = neighbor->next;
        }
    }
}

ospf_lsa_s *
ospf_lsa_new(ospf_lsa_key_s *key, ospf_instance_s *ospf_instance)
{
    ospf_lsa_s *lsa = calloc(1, sizeof(ospf_lsa_s));
    lsa->instance = ospf_instance;
    memcpy(&lsa->key, key, sizeof(ospf_lsa_key_s));
    return lsa;
}

static bool
ospf_lsa_add_interface(ospf_lsa_s *lsa, ospf_interface_s *ospf_interface)
{
    ospf_neighbor_s *neighbor = ospf_interface->neighbors;
    ospf_lsa_link_s *link = (ospf_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
    if(ospf_interface->type == OSPF_INTERFACE_P2P) {
        if(!(neighbor && neighbor->state == OSPF_NBSTATE_FULL)) {
            return false;
        }
        link->link_id = neighbor->router_id;
        link->link_data = ospf_interface->interface->ip.address;
        link->type = OSPF_LSA_LINK_P2P;
    } else if(ospf_interface->type == OSPF_INTERFACE_BROADCAST) {
        while(neighbor) {
            if(neighbor->state == OSPF_NBSTATE_FULL && 
               (ospf_interface->state == OSPF_IFSTATE_DR || 
                ospf_interface->dr == neighbor->router_id)) {
                break;
            }
            neighbor = neighbor->next;
        }
        if(neighbor) {
            link->link_id = ospf_interface->dr;
            link->link_data = ospf_interface->interface->ip.address;
            link->type = OSPF_LSA_LINK_TRANSIT;
        } else {
            link->link_id = ospf_interface->interface->ip.address & ipv4_len_to_mask(ospf_interface->interface->ip.len);
            link->link_data = ipv4_len_to_mask(ospf_interface->interface->ip.len);
            link->type = OSPF_LSA_LINK_STUB;
        }
    } else {
        return false;
    }
    link->tos = 0;
    link->metric = htobe16(ospf_interface->metric);
    lsa->lsa_len += sizeof(ospf_lsa_link_s);
    return true;
}

/**
 * This function adds/updates 
 * the self originated Type 1 Router. 
 *
 * @param ospf_instance  OSPF instance
 * @return true (success) / false (error)
 */
bool
ospf_lsa_self_update(ospf_instance_s *ospf_instance)
{
    ospf_interface_s *ospf_interface = ospf_instance->interfaces;

    void **search = NULL;
    dict_insert_result result;

    uint8_t options = 0;
    uint16_t *links;

    ospf_lsa_s *lsa;
    ospf_lsa_header_s *hdr;
    ospf_lsa_link_s *link;

    ospf_lsa_key_s key = { 
        .type = OSPF_LSA_TYPE_1, 
        .id = ospf_instance->config->router_id, 
        .router = ospf_instance->config->router_id
    };

    search = hb_tree_search(ospf_instance->lsdb, &key);
    if(search) {
        /* Update existing LSA. */
        lsa = *search;
    } else {
        /* Create new LSA. */
        lsa = ospf_lsa_new(&key, ospf_instance);
        result = hb_tree_insert(ospf_instance->lsdb, &key);
        if(result.inserted) {
            *result.datum_ptr = lsa;
        } else {
            LOG_NOARG(OSPF, "Failed to add LSA to LSDB\n");
            return NULL;
        }
    }

    if(lsa->lsa_buf_len < OSPF_MAX_SELF_LSA_LEN) {
        if(lsa->lsa) free(lsa->lsa);
        lsa->lsa = malloc(OSPF_MAX_SELF_LSA_LEN);
        lsa->lsa_len = 0;
        lsa->lsa_buf_len = OSPF_MAX_SELF_LSA_LEN;
    }

    clock_gettime(CLOCK_MONOTONIC, &lsa->timestamp);
    if(ospf_instance->teardown) {
        lsa->age = OSPF_LSA_MAX_AGE;
    }

    hdr = (ospf_lsa_header_s*)lsa->lsa;
    hdr->age = htobe16(lsa->age);
    hdr->options = options;
    hdr->type = OSPF_LSA_TYPE_1;
    hdr->id = ospf_instance->config->router_id;
    hdr->router = ospf_instance->config->router_id;
    hdr->seq = htobe32(lsa->seq);
    hdr->checksum = 0;
    hdr->length = 0;
    lsa->lsa_len = OSPF_LSA_HDR_LEN;

    *(lsa->lsa+lsa->lsa_len++) = OSPF_LSA_BORDER_ROUTER|OSPF_LSA_EXTERNAL_ROUTER;
    *(lsa->lsa+lsa->lsa_len++) = 0;
    links = (uint16_t*)(lsa->lsa+lsa->lsa_len);

    /* Add loopback */
    link = (ospf_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
    lsa->lsa_len += sizeof(ospf_lsa_link_s);
    link->link_id = ospf_instance->config->router_id;
    link->link_data = 0xffffffff;
    link->type = OSPF_LSA_LINK_STUB;
    link->tos = 0;
    link->metric = 0;
    links++;

    while(ospf_interface && lsa->lsa_len+sizeof(ospf_lsa_link_s)<=lsa->lsa_buf_len) {
        if(ospf_lsa_add_interface(lsa, ospf_interface)) {
            links++;
        }
        ospf_interface = ospf_interface->next;
    }
    return true;
}

#if 0
/**
 * ospf_lsa_process_entries 
 * 
 * This function iterate of all LSA entries
 * of the given LS request and compares
 * them with the LSA database. 
 * 
 * @param neighbor OSPF neighbor
 * @param lsdb OSPF LSA database
 * @param pdu received OSPF PDU
 * @param csnp_scan CSNP scan/job identifier
 */
void
ospf_lsa_process_request(ospf_neighbor_s *neighbor, ospf_pdu_s *pdu, uint64_t csnp_scan)
{
    ospf_lsa_header_s *hdr;
    ospf_lsa_s *lsa;
    ospf_lsa_entry_s *lsa_entry;

    dict_remove_result removed;
    void **search = NULL;

    uint64_t lsa_id;
    uint32_t seq;
    uint8_t  offset;

    /* Iterate over all lsa entry TLV's. */
    hdr = isis_pdu_first_lsa_header(pdu);
    while(hdr) {
        if(tlv->type == ospf_TLV_lsa_ENTRIES) {
            /* Each TLV can contain multiple lsa entries. */
            offset = 0;
            while(offset + ospf_lsa_ENTRY_LEN <= tlv->len) {
                lsa_entry = (ospf_lsa_entry_s *)(tlv->value+offset);
                offset += ospf_lsa_ENTRY_LEN;
                lsa_id = be64toh(lsa_entry->lsa_id);
                search = hb_tree_search(lsdb, &lsa_id);
                if(search) {
                    lsa = *search;
                    lsa->csnp_scan = csnp_scan;
                    seq = be32toh(lsa_entry->seq);
                    if(seq < lsa->seq) {
                        /* Peer has older version of lsa, let's send
                         * them an update. */
                        ospf_lsa_flood_neighbor(lsa, neighbor);
                    } else {
                        /* Ack lsa by removing them from flood tree. */
                        removed = hb_tree_remove(neighbor->flood_tree, &lsa->id);
                        if(removed.removed) {
                            if(lsa->refcount) lsa->refcount--;
                            free(removed.datum);
                        }
                    }
                }
            }
        }
        tlv = ospf_pdu_next_tlv(pdu);
    }
}

void
ospf_lsa_retry_job(timer_s *timer)
{
    ospf_neighbor_s *neighbor = timer->data;

    ospf_flood_entry_s *entry;
    hb_itor *itor;
    bool next;

    uint16_t lsa_retry_interval = neighbor->instance->config->lsa_retry_interval;

    struct timespec now;
    struct timespec ago;
    clock_gettime(CLOCK_MONOTONIC, &now);

    itor = hb_itor_new(neighbor->flood_tree);
    next = hb_itor_first(itor);
    while(next) {
        entry = *hb_itor_datum(itor);
        if(entry->wait_ack) {
            timespec_sub(&ago, &now, &entry->tx_timestamp);
            if(ago.tv_sec > lsa_retry_interval) {
                entry->wait_ack = false;
            }
        } else {
            break;
        }
        next = hb_itor_next(itor);
    }
}

void
ospf_lsa_purge_job(timer_s *timer)
{
    ospf_lsa_s *lsa = timer->data;
    if(lsa->expired) {
        lsa->deleted = true;
    }
}

void
ospf_lsa_lifetime_job(timer_s *timer)
{
    ospf_lsa_s *lsa = timer->data;

    LOG(OSPF, "ISIS %s-lsa %s (source %s seq %u) lifetime expired (%us)\n", 
        ospf_level_string(lsa->level), 
        ospf_lsa_id_to_str(&lsa->id),
        ospf_source_string(lsa->source.type),
        lsa->seq, lsa->lifetime);

    lsa->expired = true;
    timer_add(&g_ctx->timer_root, 
              &lsa->timer_lifetime, 
              "ISIS PURGE", 30, 0, lsa,
              &ospf_lsa_purge_job);
    timer_no_smear(lsa->timer_lifetime);
}

void
ospf_lsa_lifetime(ospf_lsa_s *lsa)
{
    timer_del(lsa->timer_refresh);
    if(lsa->lifetime > 0) {
        timer_add(&g_ctx->timer_root, 
                  &lsa->timer_lifetime, 
                  "ISIS LIFETIME", lsa->lifetime, 0, lsa,
                  &ospf_lsa_lifetime_job);
    } else {
        lsa->expired = true;
        timer_add(&g_ctx->timer_root, 
                  &lsa->timer_lifetime, 
                  "ISIS PURGE", 30, 0, lsa,
                  &ospf_lsa_purge_job);
    }
    timer_no_smear(lsa->timer_lifetime);
}

void
ospf_lsa_refresh(ospf_lsa_s *lsa)
{
    ospf_pdu_s *pdu = &lsa->pdu;

    lsa->seq++;
    lsa->expired = false;
    lsa->deleted = false;

    *(uint32_t*)ospf_PDU_OFFSET(&lsa->pdu, ospf_OFFSET_lsa_SEQ) = htobe32(lsa->seq);
    clock_gettime(CLOCK_MONOTONIC, &lsa->timestamp);
    ospf_pdu_update_len(pdu);
    ospf_pdu_update_auth(pdu, lsa->auth_key);
    ospf_pdu_update_lifetime(pdu, lsa->lifetime);
    ospf_pdu_update_checksum(pdu);
    ospf_lsa_flood(lsa);
}

void
ospf_lsa_refresh_job(timer_s *timer)
{
    ospf_lsa_s *lsa = timer->data;
    ospf_lsa_refresh(lsa);
}

void
ospf_lsa_tx_job(timer_s *timer)
{
    ospf_neighbor_s *neighbor = timer->data;
    ospf_flood_entry_s *entry;
    ospf_lsa_s *lsa;
    hb_itor *itor;
    bool next;
    uint16_t window = neighbor->window_size;

    bbl_ethernet_header_s eth = {0};
    bbl_ospf_s isis = {0};

    struct timespec now;
    struct timespec ago;
    uint16_t remaining_lifetime = 0;

    clock_gettime(CLOCK_MONOTONIC, &now);

    eth.type = ospf_PROTOCOL_IDENTIFIER;
    eth.next = &isis;
    eth.src = neighbor->interface->mac;
    eth.vlan_outer = neighbor->interface->vlan;
    if(neighbor->level == ospf_LEVEL_1) {
        eth.dst = g_ospf_mac_all_l1;
        isis.type = ospf_PDU_L1_lsa;
    } else {
        eth.dst = g_ospf_mac_all_l2;
        isis.type = ospf_PDU_L2_lsa;
    }
    
    itor = hb_itor_new(neighbor->flood_tree);
    next = hb_itor_first(itor);
    while(next) {
        entry = *hb_itor_datum(itor);
        if(!entry->wait_ack) {
            lsa = entry->lsa;

            LOG(PACKET, "ISIS TX %s-lsa %s (seq %u) on interface %s\n", 
                ospf_level_string(neighbor->level), 
                ospf_lsa_id_to_str(&lsa->id), 
                lsa->seq,
                neighbor->interface->name);

            /* Update lifetime */
            timespec_sub(&ago, &now, &lsa->timestamp);
            if(ago.tv_sec < lsa->lifetime) {
                remaining_lifetime = lsa->lifetime - ago.tv_sec;
            }
            ospf_pdu_update_lifetime(&lsa->pdu, remaining_lifetime);

            isis.pdu = lsa->pdu.pdu;
            isis.pdu_len = lsa->pdu.pdu_len;
            if(bbl_txq_to_buffer(neighbor->interface->txq, &eth) != BBL_TXQ_OK) {
                break;
            }
            entry->wait_ack = true;
            entry->tx_count++;
            entry->tx_timestamp.tv_sec = now.tv_sec;
            entry->tx_timestamp.tv_nsec = now.tv_nsec;
            neighbor->stats.lsa_tx++;
            neighbor->interface->stats.ospf_tx++;
            if(window) window--;
            if(window == 0) break;
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);
}

ospf_lsa_s *
ospf_lsa_new(uint64_t id, uint8_t level, ospf_instance_s *instance)
{
    ospf_lsa_s *lsa = calloc(1, sizeof(ospf_lsa_s));
    lsa->id = id;
    lsa->level = level;
    lsa->instance = instance;
    return lsa;
}

static void
ospf_lsa_final(ospf_lsa_s *lsa)
{
    ospf_pdu_s *pdu = &lsa->pdu;
    ospf_pdu_update_len(pdu);
    ospf_pdu_update_auth(pdu, lsa->auth_key);
    ospf_pdu_update_lifetime(pdu, lsa->lifetime);
    if(lsa->lifetime > 0) {
        ospf_pdu_update_checksum(pdu);
    }
}

static ospf_lsa_s *
ospf_lsa_fragment(ospf_instance_s *instance, uint8_t level, uint8_t fragment, bool purge)
{
    ospf_config_s *config = instance->config;

    ospf_lsa_s *lsa = NULL;
    ospf_pdu_s *pdu = NULL;

    uint64_t lsa_id = htobe64(fragment);
    uint16_t refresh_interval = 0;

    hb_tree *lsdb;
    void **search = NULL;
    dict_insert_result result;

    ospf_auth_type auth_type = ospf_AUTH_NONE;

    /* Create lsa-ID */
    memcpy(&lsa_id, &config->system_id, ospf_SYSTEM_ID_LEN);
    lsa_id = be64toh(lsa_id);

    /* Get LSDB */
    lsdb = instance->level[level-1].lsdb;
    search = hb_tree_search(lsdb, &lsa_id);
    if(search) {
        /* Update existing lsa. */
        lsa = *search;
    } else {
        /* Create new lsa. */
        lsa = ospf_lsa_new(lsa_id, level, instance);
        result = hb_tree_insert(lsdb,  &lsa->id);
        if(result.inserted) {
            *result.datum_ptr = lsa;
        } else {
            LOG_NOARG(OSPF, "Failed to add lsa to LSDB\n");
            return NULL;
        }
    }

    lsa->level = level;
    lsa->source.type = ospf_SOURCE_SELF;
    lsa->seq++;
    lsa->instance = instance;

    clock_gettime(CLOCK_MONOTONIC, &lsa->timestamp);
    if(purge || instance->teardown) {
        lsa->lifetime = 0;
        ospf_lsa_lifetime(lsa);
    } else {
        lsa->lifetime = config->lsa_lifetime;
        refresh_interval = lsa->lifetime - 300;
        if(config->lsa_refresh_interval < refresh_interval) {
            refresh_interval = config->lsa_refresh_interval;
        }
        timer_del(lsa->timer_lifetime);
        timer_add_periodic(&g_ctx->timer_root, &lsa->timer_refresh, 
                           "ISIS lsa REFRESH", refresh_interval, 3, lsa, 
                           &ospf_lsa_refresh_job);
    }

    /* Build PDU */
    pdu = &lsa->pdu;
    if(level == ospf_LEVEL_1) {
        ospf_pdu_init(pdu, ospf_PDU_L1_lsa);
        auth_type = config->level1_auth;
        lsa->auth_key = config->level1_key;
    } else {
        ospf_pdu_init(pdu, ospf_PDU_L2_lsa);
        auth_type = config->level2_auth;
        lsa->auth_key = config->level2_key;
    }
    
    /* PDU header */
    ospf_pdu_add_u16(pdu, 0);
    ospf_pdu_add_u16(pdu, 0);
    ospf_pdu_add_u64(pdu, lsa_id);
    ospf_pdu_add_u32(pdu, lsa->seq);
    ospf_pdu_add_u16(pdu, 0);
    ospf_pdu_add_u8(pdu, 0x03); 

    /* Add authentication TLV */
    ospf_pdu_add_tlv_auth(pdu, auth_type, lsa->auth_key);

    return lsa;
}

/**
 * This function adds/updates 
 * the self originated lsa entries. 
 *
 * @param instance  ISIS instance
 * @param level ISIS level
 * @return true (success) / false (error)
 */
bool
ospf_lsa_self_update(ospf_instance_s *instance, uint8_t level)
{
    ospf_config_s    *config    = instance->config;
    ospf_neighbor_s *neighbor = NULL;

    ospf_lsa_s *lsa;
    ospf_pdu_s *pdu;

    uint8_t  fragment = 0;
    
    ipv4_prefix loopback_prefix;

    ospf_external_connection_s *external_connection = NULL;

    lsa = ospf_lsa_fragment(instance, level, fragment, false);
    if(!lsa) return false;
    pdu = &lsa->pdu;

    /* TLV section */
    ospf_pdu_add_tlv_area(pdu, config->area, config->area_count);
    ospf_pdu_add_tlv_protocols(pdu, config->protocol_ipv4, config->protocol_ipv6);
    ospf_pdu_add_tlv_hostname(pdu, (char*)config->hostname);
    ospf_pdu_add_tlv_ipv4_int_address(pdu, config->router_id);
    ospf_pdu_add_tlv_te_router_id(pdu, config->router_id);

    loopback_prefix.address = config->router_id;
    loopback_prefix.len = 32;
    if(config->sr_node_sid) {
        /* Add Prefix-SID sub-TLV */
        ospf_sub_tlv_t stlv = {0};
        uint8_t prefix_sid[6] = {0};
        stlv.type = 3;
        stlv.len = 6;
        stlv.value = prefix_sid;
        prefix_sid[0] = 64; /* N-Flag */
        prefix_sid[1] = 0;  /* SPF */
        *(uint32_t*)&prefix_sid[2] = htobe32(config->sr_node_sid);
        ospf_pdu_add_tlv_ext_ipv4_reachability(pdu, &loopback_prefix, 0, &stlv);
    } else {
        ospf_pdu_add_tlv_ext_ipv4_reachability(pdu, &loopback_prefix, 0, NULL);
    }

    if(config->sr_base && config->sr_range) {
        ospf_pdu_add_tlv_router_cap(pdu, config->router_id, 
            config->protocol_ipv4, config->protocol_ipv6, 
            config->sr_base, config->sr_range);
    }

    /* Add link networks */
    neighbor = instance->level[level-1].neighbor;
    while(neighbor) {
        if(neighbor->state != ospf_ADJACENCY_STATE_UP) {
            goto NEXT;
        }

        if(ospf_PDU_REMAINING(pdu) < 48) {
            ospf_lsa_final(lsa);
            ospf_lsa_flood(lsa);
            if(fragment == UINT8_MAX) return false;
            lsa = ospf_lsa_fragment(instance, level, ++fragment, false);
            if(!lsa) return false;
            pdu = &lsa->pdu;
        }

        if(config->protocol_ipv4 && neighbor->interface->ip.len) {
            ospf_pdu_add_tlv_ext_ipv4_reachability(pdu, 
                &neighbor->interface->ip, 
                neighbor->metric, NULL);
        }
        if(config->protocol_ipv6 && neighbor->interface->ip6.len) {
            ospf_pdu_add_tlv_ipv6_reachability(pdu, 
                &neighbor->interface->ip6, 
                neighbor->metric);
        }
        ospf_pdu_add_tlv_ext_reachability(pdu, 
            neighbor->peer->system_id, 
            neighbor->metric);
NEXT:
        neighbor = neighbor->next;
    }
    
    external_connection = config->external_connection;
    while(external_connection) {
        if(ospf_PDU_REMAINING(pdu) < 16) {
            ospf_lsa_final(lsa);
            ospf_lsa_flood(lsa);
            if(fragment == UINT8_MAX) return false;
            lsa = ospf_lsa_fragment(instance, level, ++fragment, false);
            if(!lsa) return false;
            pdu = &lsa->pdu;
        }

        ospf_pdu_add_tlv_ext_reachability(pdu, 
            external_connection->system_id, 
            external_connection->level[level-1].metric);
        external_connection = external_connection->next;
    }

    ospf_lsa_final(lsa);
    ospf_lsa_flood(lsa);

    /* Purge remaining fragments if number of fragments has reduced. */
    while(fragment < instance->level[level-1].self_lsa_fragment) {
        lsa = ospf_lsa_fragment(instance, level, ++fragment, true);
        ospf_lsa_final(lsa);
        ospf_lsa_flood(lsa);
    }
    instance->level[level-1].self_lsa_fragment = fragment;
    return true;
}

/**
 * ospf_lsa_handler_rx 
 * 
 * @param interface receive interface
 * @param pdu received ISIS PDU
 * @param level ISIS level
 */
void
ospf_lsa_handler_rx(bbl_network_interface_s *interface, ospf_pdu_s *pdu, uint8_t level) {

    ospf_neighbor_s *neighbor = interface->ospf_neighbor[level-1];
    ospf_instance_s  *instance  = NULL;
    ospf_config_s    *config    = NULL;

    ospf_lsa_s *lsa = NULL;
    uint64_t    lsa_id;
    uint32_t    seq;

    hb_tree *lsdb;
    void **search = NULL;
    dict_insert_result result;

    ospf_auth_type auth = ospf_AUTH_NONE;
    char *key = NULL;

    if(!neighbor) {
        return;
    }
    instance = neighbor->instance;
    config = instance->config;

    neighbor->stats.lsa_rx++;

    lsa_id = be64toh(*(uint64_t*)ospf_PDU_OFFSET(pdu, ospf_OFFSET_lsa_ID));
    seq = be32toh(*(uint32_t*)ospf_PDU_OFFSET(pdu, ospf_OFFSET_lsa_SEQ));

    LOG(PACKET, "ISIS RX %s-lsa %s (seq %u) on interface %s\n", 
        ospf_level_string(level), 
        ospf_lsa_id_to_str(&lsa_id), 
        seq, interface->name);

    if(level == ospf_LEVEL_1 && config->level1_auth) {
        auth = config->level1_auth;
        key = config->level1_key;
    } else if(level == ospf_LEVEL_2 && config->level2_auth) {
        auth = config->level2_auth;
        key = config->level2_key;
    }

    if(!ospf_pdu_validate_auth(pdu, auth, key)) {
        LOG(OSPF, "ISIS RX %s-lsa %s (seq %u) authentication failed on interface %s\n",
        ospf_level_string(level), 
        ospf_lsa_id_to_str(&lsa_id), 
        seq, interface->name);
        return;
    }

    /* Get LSDB */
    lsdb = neighbor->instance->level[level-1].lsdb;
    search = hb_tree_search(lsdb, &lsa_id);
    if(search) {
        /* Update existing lsa. */
        lsa = *search;
        if(lsa->seq >= seq) {
            goto ACK;
        }
        if(lsa->source.type == ospf_SOURCE_EXTERNAL) {
            if(config->external_auto_refresh) {
                /* With external-auto-refresh enabled, 
                 * the sequence number will be increased. */
                lsa->seq = seq;
                ospf_lsa_refresh(lsa);
                goto ACK;
            }
        }
        if(lsa->source.type == ospf_SOURCE_SELF) {
            /* We received a newer version of our own
             * self originated lsa. Therfore re-generate 
             * them with a sequence number higher than 
             * the received one. */
            lsa->seq = seq;
            ospf_lsa_self_update(neighbor->instance, neighbor->level);
            goto ACK;
        }
    } else {
        /* Create new lsa. */
        lsa = ospf_lsa_new(lsa_id, level, neighbor->instance);
        result = hb_tree_insert(lsdb,  &lsa->id);
        if(result.inserted) {
            *result.datum_ptr = lsa;
        } else {
            LOG_NOARG(OSPF, "Failed to add lsa to LSDB\n");
            return;
        }
    }

    lsa->level = level;
    lsa->source.type = ospf_SOURCE_ADJACENCY;
    lsa->source.neighbor = neighbor;
    lsa->seq = seq;
    lsa->lifetime = be16toh(*(uint16_t*)ospf_PDU_OFFSET(pdu, ospf_OFFSET_lsa_LIFETIME));
    lsa->expired = false;
    lsa->deleted = false;
    lsa->instance = neighbor->instance;
    clock_gettime(CLOCK_MONOTONIC, &lsa->timestamp);

    ospf_PDU_CURSOR_RST(pdu);
    memcpy(&lsa->pdu, pdu, sizeof(ospf_pdu_s));

    ospf_lsa_lifetime(lsa);
    ospf_lsa_flood(lsa);

ACK:
    /* Add lsa to neighbor PSNP tree for acknowledgement. */
    result = hb_tree_insert(neighbor->psnp_tree,  &lsa->id);
    if(result.inserted) {
        *result.datum_ptr = lsa;
        lsa->refcount++;
        if(!neighbor->timer_psnp_started) {
            neighbor->timer_psnp_started = true;
            timer_add(&g_ctx->timer_root, &neighbor->timer_psnp_next, 
                      "ISIS PSNP", 1, 0, neighbor, &ospf_psnp_job);
        }
    }
    return;
}

/**
 * ospf_lsa_purge
 * 
 * @param lsa  ISIS lsa
 */
void
ospf_lsa_purge(ospf_lsa_s *lsa)
{
    ospf_pdu_s *pdu;
    ospf_auth_type auth_type = ospf_AUTH_NONE;

    ospf_config_s *config = lsa->instance->config;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    lsa->seq++;
    lsa->timestamp.tv_sec = now.tv_sec;
    lsa->timestamp.tv_nsec = now.tv_nsec;

    lsa->lifetime = 0;
    ospf_lsa_lifetime(lsa);

    /* Build PDU */
    pdu = &lsa->pdu;
    if(lsa->level == ospf_LEVEL_1) {
        ospf_pdu_init(pdu, ospf_PDU_L1_lsa);
        auth_type = config->level1_auth;
        lsa->auth_key = config->level1_key;
    } else {
        ospf_pdu_init(pdu, ospf_PDU_L2_lsa);
        auth_type = config->level2_auth;
        lsa->auth_key = config->level2_key;
    }

    /* PDU header. */
    ospf_pdu_add_u16(pdu, 0);
    ospf_pdu_add_u16(pdu, 0);
    ospf_pdu_add_u64(pdu, lsa->id);
    ospf_pdu_add_u32(pdu, lsa->seq);
    ospf_pdu_add_u16(pdu, 0);
    ospf_pdu_add_u8(pdu, 0x03); 

    /* TLV section. */
    ospf_pdu_add_tlv_auth(pdu, auth_type, lsa->auth_key);

    /* Update length and authentication. */
    ospf_pdu_update_len(pdu);
    ospf_pdu_update_auth(pdu, lsa->auth_key);

    /* Set checksum and lifetime to zero. */
    *(uint16_t*)ospf_PDU_OFFSET(pdu, ospf_OFFSET_lsa_LIFETIME) = 0;
    *(uint16_t*)ospf_PDU_OFFSET(pdu, ospf_OFFSET_lsa_CHECKSUM) = 0;

    ospf_lsa_flood(lsa);
}

/**
 * ospf_lsa_purge_all_external 
 * 
 * @param instance  ISIS instance
 * @param level ISIS level
 */
void
ospf_lsa_purge_all_external(ospf_instance_s *instance, uint8_t level)
{
    hb_tree *lsdb = instance->level[level-1].lsdb;

    ospf_lsa_s *lsa;
    hb_itor *itor;
    bool next;

    if(!lsdb) {
        return;
    }

    itor = hb_itor_new(lsdb);
    next = hb_itor_first(itor);

    while(next) {
        lsa = *hb_itor_datum(itor);
        if(lsa && lsa->source.type == ospf_SOURCE_EXTERNAL) {
            ospf_lsa_purge(lsa);
        }
        next = hb_itor_next(itor);
    }
}

/**
 * ospf_lsa_update_external 
 * 
 * @param instance ISIS instance
 * @param pdu received ISIS PDU
 * @param refresh automatically refresh lsa
 */
bool
ospf_lsa_update_external(ospf_instance_s *instance, ospf_pdu_s *pdu, bool refresh)
{
    uint8_t level;

    ospf_lsa_s *lsa = NULL;
    uint64_t lsa_id;
    uint32_t seq;
    uint16_t refresh_interval = 0;

    hb_tree *lsdb;
    void **search = NULL;
    dict_insert_result result;

    if(pdu->pdu_type == ospf_PDU_L1_lsa) {
        level = ospf_LEVEL_1;
    } else if(pdu->pdu_type == ospf_PDU_L2_lsa) {
        level = ospf_LEVEL_2;
    } else {
        return false;
    }

    lsa_id = be64toh(*(uint64_t*)ospf_PDU_OFFSET(pdu, ospf_OFFSET_lsa_ID));
    seq = be32toh(*(uint32_t*)ospf_PDU_OFFSET(pdu, ospf_OFFSET_lsa_SEQ));

    LOG(OSPF, "ISIS UPDATE EXTERNAL %s-lsa %s (seq %u)\n", 
        ospf_level_string(level), 
        ospf_lsa_id_to_str(&lsa_id), 
        seq);

    lsdb = instance->level[level-1].lsdb;
    search = hb_tree_search(lsdb, &lsa_id);

    if(search) {
        /* Update existing lsa. */
        lsa = *search;
        if(lsa->seq >= seq) {
            return false;
        }
    } else {
        /* Create new lsa. */
        lsa = ospf_lsa_new(lsa_id, level, instance);
        result = hb_tree_insert(lsdb,  &lsa->id);
        if(result.inserted) {
            *result.datum_ptr = lsa;
        } else {
            LOG_NOARG(ERROR, "Failed to add ISIS lsa to LSDB\n");
            return false;
        }
    }

    lsa->level = level;
    lsa->source.type = ospf_SOURCE_EXTERNAL;
    lsa->source.neighbor = NULL;
    lsa->seq = seq;
    lsa->lifetime = be16toh(*(uint16_t*)ospf_PDU_OFFSET(pdu, ospf_OFFSET_lsa_LIFETIME));
    lsa->expired = false;
    lsa->deleted = false;
    lsa->instance = instance;
    clock_gettime(CLOCK_MONOTONIC, &lsa->timestamp);

    ospf_PDU_CURSOR_RST(pdu);
    memcpy(&lsa->pdu, pdu, sizeof(ospf_pdu_s));

    if(lsa->lifetime > 0 && instance->config->external_auto_refresh) {
        if(level == ospf_LEVEL_1) {
            lsa->auth_key = instance->config->level1_key;
        } else {
            lsa->auth_key = instance->config->level2_key;
        }
        if(lsa->lifetime < ospf_DEFAULT_lsa_LIFETIME_MIN) {
            /* Increase ISIS lifetime. */
            lsa->lifetime = ospf_DEFAULT_lsa_LIFETIME_MIN;
            ospf_lsa_refresh(lsa);
            refresh = false;
        }
        refresh_interval = lsa->lifetime - 300;
        timer_add_periodic(&g_ctx->timer_root, &lsa->timer_refresh, 
                            "ISIS lsa REFRESH", refresh_interval, 3, lsa, 
                            &ospf_lsa_refresh_job);
    } else {
        ospf_lsa_lifetime(lsa);
    }

    if(refresh) {
        ospf_lsa_refresh(lsa); 
    } else { 
        ospf_lsa_flood(lsa);
    }
    return true;
}

void
ospf_lsa_flap_job(timer_s *timer)
{
    ospf_lsa_flap_s *flap = timer->data;
    uint32_t seq;

    if(flap) {
        seq = be32toh(*(uint32_t*)ospf_PDU_OFFSET(&flap->pdu, ospf_OFFSET_lsa_SEQ));
        seq += 2;
        *(uint32_t*)ospf_PDU_OFFSET(&flap->pdu, ospf_OFFSET_lsa_SEQ) = htobe32(seq);

        if(!ospf_lsa_update_external(flap->instance, &flap->pdu, true)) {
            LOG(OSPF, "Failed to flap ISIS lsa %s\n", ospf_lsa_id_to_str(&flap->id));
        }
        flap->free = true;
    }
}

/**
 * ospf_lsa_flap 
 * 
 * This function flaps (purge, wait, add) 
 * the given lsa.
 * 
 * @param lsa lsa
 * @param timer flap timer in seconds
 */
bool
ospf_lsa_flap(ospf_lsa_s *lsa, time_t timer)
{
    static ospf_lsa_flap_s *ospf_lsa_flap = NULL;

    ospf_lsa_flap_s *flap = ospf_lsa_flap;

    if(lsa->lifetime == 0 || 
       lsa->expired ||
       lsa->deleted) {
        return false;
    }

    LOG(OSPF, "ISIS FLAP %s-lsa %s in %lus\n", 
        ospf_level_string(lsa->level), 
        ospf_lsa_id_to_str(&lsa->id),
        timer);

    while(flap) {
        if(flap->free) {
            break;
        }
        flap = flap->next;
    }
    if(!flap) {
        flap = calloc(1, sizeof(ospf_lsa_flap_s));
        flap->next = ospf_lsa_flap;
        ospf_lsa_flap = flap;
    }

    flap->free = false;
    flap->timer = NULL;
    flap->id = lsa->id;
    flap->instance = lsa->instance;
    memcpy(&flap->pdu, &lsa->pdu, sizeof(ospf_pdu_s));

    timer_add(&g_ctx->timer_root, &flap->timer, "ISIS FLAP", timer, 0, flap, &ospf_lsa_flap_job);
    ospf_lsa_purge(lsa);

    return true;
}

#endif