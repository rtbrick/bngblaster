/*
 * BNG Blaster (BBL) - OSPF LSA
 *
 * Christian Giese, July 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

uint8_t g_pdu_buf[OSPF_GLOBAL_PDU_BUF_LEN] = {0};
ospf_lsa_key_s g_lsa_key_zero = {0};

int
ospf_lsa_id_compare(void *id1, void *id2)
{
    const uint8_t  t1 = *(const uint8_t*)id1;
    const uint8_t  t2 = *(const uint8_t*)id2;
    const uint64_t k1 = *(const uint64_t*)((uint8_t*)id1+1);
    const uint64_t k2 = *(const uint64_t*)((uint8_t*)id2+1);

    if(t1 == t2) {
        return (k1 > k2) - (k1 < k2);
    } else {
        return (t1 > t2) - (t1 < t2);
    }
}

void
ospf_lsa_tree_entry_free(ospf_lsa_tree_entry_s *entry)
{
    if(entry) {
        if(entry->lsa && entry->lsa->refcount) {
            entry->lsa->refcount--;
        }
        free(entry);
    }
}

void
ospf_lsa_tree_entry_clear(void *key, void *ptr)
{
    UNUSED(key);
    ospf_lsa_tree_entry_free(ptr);
}

ospf_lsa_tree_entry_s *
ospf_lsa_tree_add(ospf_lsa_s *lsa, ospf_lsa_header_s *hdr, hb_tree *tree)
{
    ospf_lsa_tree_entry_s *entry;
    dict_insert_result result; 

    entry = calloc(1, sizeof(ospf_lsa_tree_entry_s));
    if(entry) {
        if (hdr) {
            memcpy(&entry->hdr, hdr, sizeof(ospf_lsa_header_s));
        } else if(lsa) {
            memcpy(&entry->hdr, lsa->lsa, sizeof(ospf_lsa_header_s));
        } else {
            free(entry);
            return NULL;
        }
        result = hb_tree_insert(tree, &entry->hdr);
        if(result.inserted) {
            if(lsa) {
                entry->lsa = lsa; lsa->refcount++;
            }
            *result.datum_ptr = entry;
        } else {
            free(entry);
            if(result.datum_ptr && *result.datum_ptr) {
                entry = *result.datum_ptr;
                if(entry) {
                    if(hdr) {
                        memcpy(&entry->hdr, hdr, sizeof(ospf_lsa_header_s));
                    }
                    if(!entry->lsa && lsa) {
                        entry->lsa = lsa; lsa->refcount++;
                    }
                }
            } else {
                entry = NULL;
            }
        }
    }
    return entry;
}

/** 
 * Determining which LSA is newer as 
 * described in RFC2328 section 13.1.
 * 
 * @param hdr_a LSA A header (network byte order)
 * @param hdr_b LSA B header (network byte order)
 * @return  1 if A is more recent
 * @return  0 if A and B are identical
 * @return -1 if B is more recent
 */
int
ospf_lsa_compare(ospf_lsa_header_s *hdr_a, ospf_lsa_header_s *hdr_b)
{
    uint32_t a;
    uint32_t b;

    /* Compare sequence number. */
    a = be32toh(hdr_a->seq);
    b = be32toh(hdr_b->seq);
    if(a > b) return 1;
    if(b > a) return -1;

    /* Compare checksum. */
    a = be16toh(hdr_a->checksum);
    b = be16toh(hdr_b->checksum);
    if(a > b) return 1;
    if(b > a) return -1;

    /* Compare age. */
    a = be16toh(hdr_a->age);
    b = be16toh(hdr_b->age);
    if(a > OSPF_LSA_MAX_AGE) a = OSPF_LSA_MAX_AGE;
    if(b > OSPF_LSA_MAX_AGE) b = OSPF_LSA_MAX_AGE;
    if(a == b) return 0;
    if(a == OSPF_LSA_MAX_AGE) return 1;
    if(b == OSPF_LSA_MAX_AGE) return -1;
    if(a > b + OSPF_LSA_MAX_AGE_DIFF) return 1;
    if(b > a + OSPF_LSA_MAX_AGE_DIFF) return -1;
    return 0;
}

/**
 * ospf_lsa_gc_job 
 * 
 * OSPF LSDB/LSA garbage collection job.
 * 
 * @param timer time
 */
void
ospf_lsa_gc_job(timer_s *timer)
{
    ospf_instance_s *ospf_instance = timer->data;
    ospf_lsa_s *lsa;
    hb_itor *itor;
    bool next;

    /* Deleting objects from a tree while iterating is unsafe, 
     * so instead, a list of objects is created during the iteration 
     * process to mark them for deletion. Once the iteration is complete, 
     * the objects in the delete list can be safely removed from the tree. */
    ospf_lsa_s *delete_list[OSPF_LSA_GC_DELETE_MAX];
    size_t delete_list_len = 0;

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
            delete_list[delete_list_len++] = lsa;
            if(delete_list_len == OSPF_LSA_GC_DELETE_MAX) {
                next = NULL;
            }
        }
    }
    hb_itor_free(itor);

    /* Finally delete from LSDB! */
    for(size_t i=0; i < delete_list_len; i++) {
        removed = hb_tree_remove(ospf_instance->lsdb, &delete_list[i]->key);
        if(removed.removed) {
            free(removed.datum);
        }
    }
}

/**
 * ospf_lsa_retry_stop: 
 * 
 * Remove LSA from neighbor retransmission tree.
 * 
 * @param lsa OSPF LSA
 * @param neighbor OSPF neihjbor
 * @return true if LSA was removed from neighbor retry tree
 */
static bool
ospf_lsa_retry_stop(ospf_lsa_s *lsa, ospf_neighbor_s *neighbor)
{
    dict_remove_result removed; 
    removed = hb_tree_remove(neighbor->lsa_retry_tree, &lsa->key);
    if(removed.removed) {
        ospf_lsa_tree_entry_free(removed.datum);
        return true;
    }
    return false;
}

/**
 * ospf_lsa_flood 
 * 
 * This function adds an LSA to all
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
    ospf_lsa_tree_entry_s *entry;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    assert(lsa);
    assert(lsa->lsa);
    assert(lsa->lsa_len >= sizeof(ospf_lsa_header_s));
    assert(lsa->lsa_buf_len >= lsa->lsa_len);

    interface = lsa->instance->interfaces;
    while(interface) {
        /* Add to interface flood tree. */
        ospf_lsa_tree_add(lsa, NULL, interface->lsa_flood_tree);

        /* Add to neighbors retry list. */
        neighbor = interface->neighbors;
        while(neighbor) {
            if(neighbor->state < OSPF_NBSTATE_EXCHANGE) {
                goto NEXT;
            }
            if(lsa->source.router_id == neighbor->router_id) {
                /* Do not flood over the neighbor from where LSA was received. */
                goto NEXT;
            }
            entry = ospf_lsa_tree_add(lsa, NULL, neighbor->lsa_retry_tree);
            if(entry) {
                entry->timestamp.tv_sec = now.tv_sec;
                entry->timestamp.tv_nsec = now.tv_nsec;
            }
NEXT:
            neighbor = neighbor->next;
        }
    }
}

void
ospf_lsa_update_age(ospf_lsa_s *lsa, struct timespec *now)
{
    struct timespec ago;
    uint16_t age;

    timespec_sub(&ago, now, &lsa->timestamp);
    lsa->timestamp.tv_sec = now->tv_sec;
    lsa->timestamp.tv_nsec = now->tv_nsec;

    age = lsa->age + ago.tv_sec;
    if(lsa->expired || age >= OSPF_LSA_MAX_AGE) {
        /* Expired! */
        age = OSPF_LSA_MAX_AGE;
        lsa->expired = true;
    }
    lsa->age = age;
    /* First two bytes of LSA HDR is age which is also exlcuded 
     * from checksum. Therefore updating age is that simple! */
    *(uint16_t*)lsa->lsa = htobe16(age);
}

static void
ospf_lsa_update_hdr(ospf_lsa_s *lsa)
{
    ospf_lsa_header_s *hdr;

    assert(lsa->lsa_len >= sizeof(ospf_lsa_header_s));
    if(lsa->lsa_len < sizeof(ospf_lsa_header_s)) {
        return;
    }

    hdr = (ospf_lsa_header_s*)lsa->lsa;
    hdr->age = htobe16(lsa->age);
    hdr->seq = htobe32(lsa->seq);
    hdr->checksum = 0;
    hdr->checksum = bbl_checksum(lsa->lsa+OSPF_LSA_AGE_LEN, lsa->lsa_len-OSPF_LSA_AGE_LEN);
}

static void
ospf_lsa_refresh(ospf_lsa_s *lsa)
{
    clock_gettime(CLOCK_MONOTONIC, &lsa->timestamp);
    
    lsa->seq++;
    lsa->deleted = false;
    if(lsa->instance->teardown) {
        lsa->age = OSPF_LSA_MAX_AGE;
        lsa->expired = true;
    } else {
        lsa->age = 0;
        lsa->expired = false;
    }
    ospf_lsa_update_hdr(lsa);
    ospf_lsa_flood(lsa);
}

void
ospf_lsa_refresh_job(timer_s *timer)
{
    ospf_lsa_s *lsa = timer->data;
    ospf_lsa_refresh(lsa);
}

static ospf_lsa_s *
ospf_lsa_new(ospf_lsa_key_s *key, ospf_instance_s *ospf_instance)
{
    ospf_lsa_s *lsa = calloc(1, sizeof(ospf_lsa_s));
    lsa->instance = ospf_instance;
    memcpy(&lsa->key, key, sizeof(ospf_lsa_key_s));
    return lsa;
}

/**
 * ospf_lsa_purge
 * 
 * @param lsa  OSPF LSA
 */
static void
ospf_lsa_purge(ospf_lsa_s *lsa)
{
    lsa->seq++;
    lsa->age = OSPF_LSA_MAX_AGE;
    lsa->expired = true;
    ospf_lsa_update_hdr(lsa);
    ospf_lsa_flood(lsa);
}

/**
 * ospf_lsa_purge_all_external 
 * 
 * @param instance  OSPF instance
 */
void
ospf_lsa_purge_all_external(ospf_instance_s *instance)
{
    hb_tree *lsdb = instance->lsdb;

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
        if(lsa && lsa->source.type == OSPF_SOURCE_EXTERNAL) {
            ospf_lsa_purge(lsa);
        }
        next = hb_itor_next(itor);
    }
}

static bool
ospf_lsa_add_interface(ospf_lsa_s *lsa, ospf_interface_s *ospf_interface)
{
    ospf_neighbor_s *neighbor = ospf_interface->neighbors;
    ospf_lsa_link_s *link;
 
    if(lsa->lsa_len + sizeof(ospf_lsa_link_s) > lsa->lsa_buf_len) {
        return false;
    }
    link = (ospf_lsa_link_s*)(lsa->lsa+lsa->lsa_len);

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
 * the self originated Type 1 Router LSA. 
 *
 * @param ospf_instance  OSPF instance
 * @return true (success) / false (error)
 */
bool
ospf_lsa_self_update(ospf_instance_s *ospf_instance)
{
    ospf_interface_s *ospf_interface = ospf_instance->interfaces;
    ospf_config_s *config = ospf_instance->config;

    void **search = NULL;
    dict_insert_result result;

    uint8_t options = 0;
    uint16_t *links;

    ospf_lsa_s *lsa;
    ospf_lsa_header_s *hdr;
    ospf_lsa_link_s *link;

    ospf_external_connection_s *external_connection = NULL;

    ospf_lsa_key_s key = { 
        .type = OSPF_LSA_TYPE_1, 
        .id = config->router_id, 
        .router = config->router_id
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

    lsa->source.type = OSPF_SOURCE_SELF;
    lsa->seq++;
    lsa->instance = ospf_instance;
    lsa->deleted = false;
    
    hdr = (ospf_lsa_header_s*)lsa->lsa;
    hdr->age = htobe16(lsa->age);
    hdr->options = options;
    hdr->type = OSPF_LSA_TYPE_1;
    hdr->id = config->router_id;
    hdr->router = config->router_id;
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
    link->link_id = config->router_id;
    link->link_data = 0xffffffff;
    link->type = OSPF_LSA_LINK_STUB;
    link->tos = 0;
    link->metric = 0;
    links++;

    /* Add OSPF neighbor interfaces */
    while(ospf_interface && lsa->lsa_len + sizeof(ospf_lsa_link_s) <= lsa->lsa_buf_len) {
        if(ospf_lsa_add_interface(lsa, ospf_interface)) {
            links++;
        }
        ospf_interface = ospf_interface->next;
    }

    /* Add external connections */
    external_connection = config->external_connection;
    while(external_connection && lsa->lsa_len + sizeof(ospf_lsa_link_s) <= lsa->lsa_buf_len) {
        link = (ospf_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
        lsa->lsa_len += sizeof(ospf_lsa_link_s);
        link->link_id = external_connection->router_id;
        link->link_data = external_connection->ipv4.address;
        link->type = OSPF_LSA_LINK_P2P;
        link->tos = 0;
        link->metric = external_connection->metric;
        links++;

        external_connection = external_connection->next;
    }

    hdr->length = htobe16(lsa->lsa_len);
    ospf_lsa_refresh(lsa);
    return true;
}

protocol_error_t
ospf_lsa_update_tx(ospf_interface_s *ospf_interface, 
                   ospf_neighbor_s *ospf_neighbor, 
                   bool retry)
{
    ospf_instance_s *ospf_instance = ospf_interface->instance;
    bbl_network_interface_s *interface = ospf_interface->interface;

    ospf_lsa_tree_entry_s *entry;
    ospf_lsa_s *lsa;
    hb_tree *tree;
    hb_itor *itor;
    bool next;
    void **search = NULL;
    uint16_t l3_hdr_len;
    uint16_t lsa_count = 0;
    uint16_t lsa_retry_interval;

    struct timespec now;
    struct timespec ago;
    clock_gettime(CLOCK_MONOTONIC, &now);

    ospf_pdu_s pdu;
    ospf_pdu_init(&pdu, OSPF_PDU_LS_UPDATE, ospf_interface->version);
    pdu.pdu = g_pdu_buf;
    pdu.pdu_buf_len = OSPF_GLOBAL_PDU_BUF_LEN;

    /* OSPF header */
    ospf_pdu_add_u8(&pdu, ospf_interface->version);
    ospf_pdu_add_u8(&pdu, pdu.pdu_type);
    ospf_pdu_add_u16(&pdu, 0); /* skip length */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->router_id); /* Router ID */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->area); /* Area ID */
    ospf_pdu_add_u16(&pdu, 0); /* skip checksum */
    if(ospf_interface->version == OSPF_VERSION_2) {
        l3_hdr_len = 20;
        /* Authentication */
        ospf_pdu_add_u16(&pdu, OSPF_AUTH_NONE);
        ospf_pdu_zero_bytes(&pdu, OSPFV2_AUTH_DATA_LEN);
    } else {
        l3_hdr_len = 40;
        ospf_pdu_add_u16(&pdu, 0);
    }
    ospf_pdu_add_u32(&pdu, 0); /* skip lsa_count */

    if(ospf_neighbor && retry) {
        /* Retry. */
        lsa_retry_interval = ospf_instance->config->lsa_retry_interval;

        tree = ospf_neighbor->lsa_retry_tree;
        itor = hb_itor_new(tree);
        next = hb_itor_first(itor);
        while(next) {
            entry = *hb_itor_datum(itor);
            next = hb_itor_next(itor);
            timespec_sub(&ago, &now, &entry->timestamp);
            if(ago.tv_sec < lsa_retry_interval) {
                continue;
            }
            lsa = entry->lsa;
            if(lsa && lsa->lsa_len >= OSPF_LSA_HDR_LEN) {
                if(lsa_count > 0 && (l3_hdr_len + pdu.pdu_len + lsa->lsa_len) > interface->mtu) {
                    next = NULL;
                }
                ospf_lsa_update_age(entry->lsa, &now);
                ospf_pdu_add_bytes(&pdu, lsa->lsa, lsa->lsa_len);
                entry->timestamp.tv_sec = now.tv_sec;
                entry->timestamp.tv_nsec = now.tv_nsec;
                lsa_count++;
            }
        }
        hb_itor_free(itor);
    } else {
        /* Flooding and direct updates. */
        if(ospf_neighbor) {
            tree = ospf_neighbor->lsa_update_tree;
        } else {
            tree = ospf_interface->lsa_flood_tree;
        }
        search = hb_tree_search_gt(tree, &g_lsa_key_zero);
        while(search) {
            entry = *search;
            lsa = entry->lsa;
            if(lsa && lsa->lsa_len >= OSPF_LSA_HDR_LEN) {
                if(lsa_count > 0 && (l3_hdr_len + pdu.pdu_len + lsa->lsa_len) > interface->mtu) {
                    break;
                }
                ospf_lsa_update_age(entry->lsa, &now);
                ospf_pdu_add_bytes(&pdu, lsa->lsa, lsa->lsa_len);
                lsa_count++;
            }
            hb_tree_remove(tree, &lsa->key);
            ospf_lsa_tree_entry_free(entry);
            search = hb_tree_search_gt(tree, &g_lsa_key_zero);
        }
    }
    if(lsa_count == 0) {
        return EMPTY;
    }

    /* Update LSA count */
    if(ospf_interface->version == OSPF_VERSION_2) {
        *(uint32_t*)OSPF_PDU_OFFSET(&pdu, OSPFV2_OFFSET_LS_UPDATE_COUNT) = htobe32(lsa_count);
    } else {
        *(uint32_t*)OSPF_PDU_OFFSET(&pdu, OSPFV3_OFFSET_LS_UPDATE_COUNT) = htobe32(lsa_count);
    }

    /* Update length and checksum. */
    ospf_pdu_update_len(&pdu);
    ospf_pdu_update_checksum(&pdu);

    if(ospf_pdu_tx(&pdu, ospf_interface, ospf_neighbor) == PROTOCOL_SUCCESS) {
        ospf_interface->stats.ls_upd_tx++;
        return PROTOCOL_SUCCESS;
    } else {
        return SEND_ERROR;
    }
}

protocol_error_t
ospf_lsa_req_tx(ospf_interface_s *ospf_interface, ospf_neighbor_s *ospf_neighbor)
{
    ospf_instance_s *ospf_instance = ospf_interface->instance;
    bbl_network_interface_s *interface = ospf_interface->interface;

    ospf_lsa_tree_entry_s *entry;
    hb_tree *tree;
    void **search = NULL;
    uint16_t l3_hdr_len;
    uint16_t lsa_count = 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    ospf_pdu_s pdu;
    ospf_pdu_init(&pdu, OSPF_PDU_LS_REQUEST, ospf_interface->version);
    pdu.pdu = g_pdu_buf;
    pdu.pdu_buf_len = OSPF_GLOBAL_PDU_BUF_LEN;

    /* OSPF header */
    ospf_pdu_add_u8(&pdu, ospf_interface->version);
    ospf_pdu_add_u8(&pdu, pdu.pdu_type);
    ospf_pdu_add_u16(&pdu, 0); /* skip length */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->router_id); /* Router ID */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->area); /* Area ID */
    ospf_pdu_add_u16(&pdu, 0); /* skip checksum */
    if(ospf_interface->version == OSPF_VERSION_2) {
        l3_hdr_len = 20;
        /* Authentication */
        ospf_pdu_add_u16(&pdu, OSPF_AUTH_NONE);
        ospf_pdu_zero_bytes(&pdu, OSPFV2_AUTH_DATA_LEN);
    } else {
        l3_hdr_len = 40;
        ospf_pdu_add_u32(&pdu, 0);
    }
    tree = ospf_neighbor->lsa_request_tree;
    search = hb_tree_search_gt(tree, &g_lsa_key_zero);
    while(search) {
        entry = *search;
        ospf_pdu_add_bytes(&pdu, (uint8_t*)&entry->hdr, OSPF_LSA_HDR_LEN);
        lsa_count++;
        if((l3_hdr_len + pdu.pdu_len + OSPF_LSA_HDR_LEN) > interface->mtu) {
            break;
        }
        search = hb_tree_search_gt(tree, &g_lsa_key_zero);
    }
    if(lsa_count == 0) {
        return EMPTY;
    }

    /* Update length and checksum */
    ospf_pdu_update_len(&pdu);
    ospf_pdu_update_checksum(&pdu);

    if(ospf_pdu_tx(&pdu, ospf_interface, ospf_neighbor) == PROTOCOL_SUCCESS) {
        ospf_interface->stats.ls_req_tx++;
        return PROTOCOL_SUCCESS;
    } else {
        return SEND_ERROR;
    }
}


protocol_error_t
ospf_lsa_ack_tx(ospf_interface_s *ospf_interface, ospf_neighbor_s *ospf_neighbor)
{
    ospf_instance_s *ospf_instance = ospf_interface->instance;
    bbl_network_interface_s *interface = ospf_interface->interface;

    ospf_lsa_tree_entry_s *entry;
    ospf_lsa_s *lsa;
    hb_tree *tree;
    void **search = NULL;
    uint16_t l3_hdr_len;
    uint16_t lsa_count = 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    ospf_pdu_s pdu;
    ospf_pdu_init(&pdu, OSPF_PDU_LS_ACK, ospf_interface->version);
    pdu.pdu = g_pdu_buf;
    pdu.pdu_buf_len = OSPF_GLOBAL_PDU_BUF_LEN;

    /* OSPF header */
    ospf_pdu_add_u8(&pdu, ospf_interface->version);
    ospf_pdu_add_u8(&pdu, pdu.pdu_type);
    ospf_pdu_add_u16(&pdu, 0); /* skip length */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->router_id); /* Router ID */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->area); /* Area ID */
    ospf_pdu_add_u16(&pdu, 0); /* skip checksum */
    if(ospf_interface->version == OSPF_VERSION_2) {
        l3_hdr_len = 20;
        /* Authentication */
        ospf_pdu_add_u16(&pdu, OSPF_AUTH_NONE);
        ospf_pdu_zero_bytes(&pdu, OSPFV2_AUTH_DATA_LEN);
    } else {
        l3_hdr_len = 40;
        ospf_pdu_add_u16(&pdu, 0);
    }
    if(ospf_neighbor) {
        /* Direct LS ack */
        tree = ospf_neighbor->lsa_ack_tree;
    } else {
        /* Delayed LS ack */
        tree = ospf_interface->lsa_ack_tree;
    }
    search = hb_tree_search_gt(tree, &g_lsa_key_zero);
    while(search) {
        entry = *search;
        lsa = entry->lsa;
        if(lsa && lsa->lsa_len >= OSPF_LSA_HDR_LEN) {
            ospf_lsa_update_age(entry->lsa, &now);
            ospf_pdu_add_bytes(&pdu, lsa->lsa, OSPF_LSA_HDR_LEN);
        } else {
            ospf_pdu_add_bytes(&pdu, (uint8_t*)&entry->hdr, OSPF_LSA_HDR_LEN);
        }
        lsa_count++;
        hb_tree_remove(tree, &entry->hdr.type);
        ospf_lsa_tree_entry_free(entry);
        if((l3_hdr_len + pdu.pdu_len + OSPF_LSA_HDR_LEN) > interface->mtu) {
            break;
        }
        search = hb_tree_search_gt(tree, &g_lsa_key_zero);
    }
    if(lsa_count == 0) {
        return EMPTY;
    }

    /* Update length and checksum */
    ospf_pdu_update_len(&pdu);
    ospf_pdu_update_checksum(&pdu);

    if(ospf_pdu_tx(&pdu, ospf_interface, ospf_neighbor) == PROTOCOL_SUCCESS) {
        ospf_interface->stats.ls_ack_tx++;
        return PROTOCOL_SUCCESS;
    } else {
        return SEND_ERROR;
    }
}

/**
 * ospf_lsa_update_handler_rx
 *
 * @param ospf_interface receive interface
 * @param ospf_neighbor receive OSPF neighbor
 * @param pdu received OSPF PDU
 */
void
ospf_lsa_update_handler_rx(ospf_interface_s *ospf_interface, 
                           ospf_neighbor_s *ospf_neighbor, 
                           ospf_pdu_s *pdu)
{
    bbl_network_interface_s *interface = ospf_interface->interface;
    ospf_instance_s *ospf_instance = ospf_interface->instance;

    ospf_lsa_tree_entry_s *entry;
    ospf_lsa_header_s *hdr;
    ospf_lsa_key_s *key;
    ospf_lsa_s *lsa;

    dict_remove_result removed; 
    void **search = NULL;

    uint32_t lsa_count;
    uint16_t lsa_len;

    struct timespec now;

    ospf_interface->stats.ls_upd_rx++;

    if(!ospf_neighbor) {
        ospf_rx_error(interface, pdu, "no neighbor");
        return;
    }
    if(ospf_neighbor->state < OSPF_NBSTATE_EXSTART) {
        ospf_rx_error(interface, pdu, "wrong state");
        return;
    }

    if(ospf_interface->version == OSPF_VERSION_2) {
        if(pdu->pdu_len < OSPFV2_LS_UPDATE_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        lsa_count = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_LS_UPDATE_COUNT));
        OSPF_PDU_CURSOR_SET(pdu, OSPFV2_OFFSET_LS_UPDATE_LSA);
    } else {
        if(pdu->pdu_len < OSPFV3_LS_UPDATE_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        lsa_count = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_LS_UPDATE_COUNT));
        OSPF_PDU_CURSOR_SET(pdu, OSPFV3_OFFSET_LS_UPDATE_LSA);
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    while(OSPF_PDU_CURSOR_LEN(pdu) >= OSPF_LSA_HDR_LEN && lsa_count) {
        hdr = (ospf_lsa_header_s*)OSPF_PDU_CURSOR(pdu);
        key = (ospf_lsa_key_s*)&hdr->type;
        lsa_len = be16toh(hdr->length);
        if(lsa->lsa_len > OSPF_PDU_CURSOR_LEN(pdu)) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        OSPF_PDU_CURSOR_INC(pdu, lsa_len);
        lsa_count--;

        search = hb_tree_search(ospf_neighbor->lsa_request_tree, key);
        if(search) {
            entry = *search;
            if(ospf_lsa_compare((ospf_lsa_header_s*)&entry->hdr, hdr) != 1) {
                removed = hb_tree_remove(ospf_neighbor->lsa_request_tree, &lsa->key);
                if(removed.removed) {
                    ospf_lsa_tree_entry_free(removed.datum);
                }
            }
        }

        search = hb_tree_search(ospf_instance->lsdb, key);
        if(search) {
            lsa = *search;
            ospf_lsa_update_age(lsa, &now);
            switch(ospf_lsa_compare((ospf_lsa_header_s*)lsa->lsa, hdr)) {
                case  1: /* LOCAL IS NEWER */
                    if(!(lsa->seq == OSPF_LSA_SEQ_MAX && lsa->age >= OSPF_LSA_MAX_AGE)) {
                        /* Send direct LSA update. */
                        ospf_lsa_tree_add(lsa, NULL, ospf_neighbor->lsa_update_tree);
                    }
                    continue;
                case  0: /* EQUAL */
                    if(ospf_lsa_retry_stop(lsa, ospf_neighbor)) {
                        /* Implied acknowledgment (see RFC2328 section 13, step 7a). */
                        if(ospf_interface->state == OSPF_IFSTATE_BACKUP && 
                           ospf_interface->dr == pdu->router_id) {
                            /* Send delayed LSA ack. */
                            ospf_lsa_tree_add(lsa, NULL, ospf_interface->lsa_ack_tree);
                        }
                    } else {
                        /* Send direct LSA ack. */
                        ospf_lsa_tree_add(lsa, NULL, ospf_neighbor->lsa_ack_tree);
                    }
                    continue;
                case -1: /* RECEIVED IS NEWER */
                    break;
            }            
        } else {
            lsa = ospf_lsa_new(key, ospf_instance);
        }
        
        if(lsa->lsa_buf_len < lsa_len) {
            if(lsa->lsa) free(lsa->lsa);
            lsa->lsa = malloc(lsa_len);
        }
        memcpy(lsa->lsa, hdr, lsa_len);
        lsa->lsa_len = lsa_len;

        lsa->source.type = OSPF_SOURCE_ADJACENCY;
        lsa->source.router_id = ospf_neighbor->router_id;
        lsa->seq = be32toh(hdr->seq);
        lsa->age = be16toh(hdr->age)+1;
        lsa->timestamp.tv_sec = now.tv_sec;
        lsa->timestamp.tv_nsec = now.tv_sec;
        ospf_lsa_update_age(lsa, &now);
        ospf_lsa_flood(lsa);
    }
    if(hb_tree_count(ospf_neighbor->lsa_ack_tree) > 0) {
        ospf_lsa_ack_tx(ospf_interface, ospf_neighbor);
    }
    if(hb_tree_count(ospf_neighbor->lsa_update_tree) > 0) {
        ospf_lsa_update_tx(ospf_interface, ospf_neighbor, false);
    }
}

/**
 * ospf_lsa_req_handler_rx
 *
 * @param ospf_interface receive interface
 * @param ospf_neighbor receive OSPF neighbor
 * @param pdu received OSPF PDU
 */
void
ospf_lsa_req_handler_rx(ospf_interface_s *ospf_interface, 
                        ospf_neighbor_s *ospf_neighbor, 
                        ospf_pdu_s *pdu)
{
    bbl_network_interface_s *interface = ospf_interface->interface;
    ospf_instance_s *ospf_instance = ospf_interface->instance;

    ospf_lsa_key_s *key;
    ospf_lsa_s *lsa;

    void **search = NULL;

    ospf_interface->stats.ls_req_rx++;

    if(!ospf_neighbor) {
        ospf_rx_error(interface, pdu, "no neighbor");
        return;
    }
    if(ospf_neighbor->state < OSPF_NBSTATE_EXSTART) {
        ospf_rx_error(interface, pdu, "wrong state");
        return;
    }

    if(ospf_interface->version == OSPF_VERSION_2) {
        if(pdu->pdu_len < OSPFV2_LS_REQ_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        OSPF_PDU_CURSOR_SET(pdu, OSPFV2_OFFSET_LS_REQ_LSA);
    } else {
        if(pdu->pdu_len < OSPFV3_LS_REQ_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        OSPF_PDU_CURSOR_SET(pdu, OSPFV3_OFFSET_LS_REQ_LSA);
    }

    while(OSPF_PDU_CURSOR_LEN(pdu)) {
        if(ospf_interface->version == OSPF_VERSION_2) {
            if(OSPF_PDU_CURSOR_LEN(pdu) < OSPFV2_LSA_REQ_HDR_LEN) {
                break;
            }
            OSPF_PDU_CURSOR_INC(pdu, 3);
        } else {
            if(OSPF_PDU_CURSOR_LEN(pdu) < OSPFV3_LSA_REQ_HDR_LEN) {
                break;
            }
            OSPF_PDU_CURSOR_INC(pdu, 1);
        }
        key = (ospf_lsa_key_s*)OSPF_PDU_CURSOR(pdu);
        OSPF_PDU_CURSOR_INC(pdu, sizeof(ospf_lsa_key_s));

        search = hb_tree_search(ospf_instance->lsdb, key);
        if(search) {
            lsa = *search;
            if(!(lsa->seq == OSPF_LSA_SEQ_MAX && lsa->age >= OSPF_LSA_MAX_AGE)) {
                /* Send direct LSA update. */
                ospf_lsa_tree_add(lsa, NULL, ospf_neighbor->lsa_update_tree);
            }
        } 
    }
}

/**
 * ospf_lsa_ack_handler_rx
 *
 * @param ospf_interface receive interface
 * @param ospf_neighbor receive OSPF neighbor
 * @param pdu received OSPF PDU
 */
void
ospf_lsa_ack_handler_rx(ospf_interface_s *ospf_interface, 
                        ospf_neighbor_s *ospf_neighbor, 
                        ospf_pdu_s *pdu)
{
    bbl_network_interface_s *interface = ospf_interface->interface;

    ospf_lsa_tree_entry_s *entry;
    ospf_lsa_header_s *hdr_a;
    ospf_lsa_header_s *hdr_b;

    ospf_lsa_key_s *key;
    ospf_lsa_s *lsa;

    void **search = NULL;

    struct timespec now;

    ospf_interface->stats.ls_ack_rx++;

    if(!ospf_neighbor) {
        ospf_rx_error(interface, pdu, "no neighbor");
        return;
    }
    if(ospf_neighbor->state < OSPF_NBSTATE_EXSTART) {
        ospf_rx_error(interface, pdu, "wrong state");
        return;
    }

    if(ospf_interface->version == OSPF_VERSION_2) {
        if(pdu->pdu_len < OSPFV2_LS_ACK_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        OSPF_PDU_CURSOR_SET(pdu, OSPFV2_OFFSET_LS_ACK_LSA);
    } else {
        if(pdu->pdu_len < OSPFV3_LS_ACK_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        OSPF_PDU_CURSOR_SET(pdu, OSPFV3_OFFSET_LS_ACK_LSA);
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    while(OSPF_PDU_CURSOR_LEN(pdu) >= OSPF_LSA_HDR_LEN) {
        hdr_a = (ospf_lsa_header_s*)OSPF_PDU_CURSOR(pdu);
        key = (ospf_lsa_key_s*)&hdr_a->type;
        OSPF_PDU_CURSOR_INC(pdu, OSPF_LSA_HDR_LEN);
        search = hb_tree_search(ospf_neighbor->lsa_retry_tree, key);
        if(search) {
            entry = *search;
            if(entry->lsa) {
                lsa = entry->lsa;
                ospf_lsa_update_age(lsa, &now);
                hdr_b = (ospf_lsa_header_s*)lsa->lsa;
            } else {
                hdr_b = &entry->hdr;
            }
            if(ospf_lsa_compare(hdr_a, hdr_b) != -1) {
                hb_tree_remove(ospf_neighbor->lsa_retry_tree, key);
                ospf_lsa_tree_entry_free(entry);
            }
        } 
    }
}