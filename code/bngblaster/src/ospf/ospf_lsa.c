/*
 * BNG Blaster (BBL) - OSPF LSA
 *
 * Christian Giese, July 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

extern ospf_lsa_key_s g_lsa_key_zero;

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
 * ospf_lsa_key_compare: 
 * 
 * libdict tree key compare function
 */
int
ospf_lsa_key_compare(void *id1, void *id2)
{
    const uint64_t a = *(const uint64_t*)id1;
    const uint64_t b = *(const uint64_t*)id2;
    return (a > b) - (a < b);
}

/**
 * ospf_lsa_tree_entry_free: 
 * 
 * Free LSA tree entry memory and update 
 * corresponding LSA reference count. 
 */
static void
ospf_lsa_tree_entry_free(ospf_lsa_tree_entry_s *entry)
{
    ospf_lsa_s *lsa;
    if(entry) {
        lsa = entry->lsa;
        if(lsa) {
            assert(lsa->refcount);
            if(lsa->refcount) lsa->refcount--;
        }
        free(entry);
    }
}

/**
 * ospf_lsa_tree_entry_clear: 
 * 
 * libdict tree clear function 
 */
void
ospf_lsa_tree_entry_clear(void *key, void *ptr)
{
    UNUSED(key);
    ospf_lsa_tree_entry_free(ptr);
}

/**
 * ospf_lsa_tree_add: 
 * 
 * The presence of either the parameter LSA or LSA header 
 * is obligatory, with at least one of them being required.
 *
 * @param lsa OSPF LSA
 * @param hdr OSPF LSA header
 * @param tree target LSA tree 
 * @return LSA tree entry (ospf_lsa_tree_entry_s)
 */
ospf_lsa_tree_entry_s *
ospf_lsa_tree_add(ospf_lsa_s *lsa, ospf_lsa_header_s *hdr, hb_tree *tree)
{
    ospf_lsa_tree_entry_s *entry;
    dict_insert_result result; 

    assert(tree && (lsa || hdr));

    entry = calloc(1, sizeof(ospf_lsa_tree_entry_s));
    if(entry) {
        if(hdr) {
            memcpy(&entry->hdr, hdr, sizeof(ospf_lsa_header_s));
        } else if(lsa) {
            memcpy(&entry->hdr, lsa->lsa, sizeof(ospf_lsa_header_s));
        }
        entry->key.id = entry->hdr.id;
        entry->key.router = entry->hdr.router;
        result = hb_tree_insert(tree, &entry->key);
        if(result.inserted) {
            if(lsa) {
                entry->lsa = lsa; 
                lsa->refcount++;
            }
            *result.datum_ptr = entry;
        } else {
            free(entry);
            if(result.datum_ptr && *result.datum_ptr) {
                entry = *result.datum_ptr;
                if(entry) {
                    if(hdr && ospf_lsa_compare(&entry->hdr, hdr) == -1) {
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
 * ospf_lsa_tree_remove: 
 * 
 * Remove LSA from tree.
 * 
 * @param lsa OSPF LSA key
 * @param tree target LSA tree 
 * @return true if entry was removed from tree
 */
static bool
ospf_lsa_tree_remove(ospf_lsa_key_s *key, hb_tree *tree)
{
    dict_remove_result removed;
    removed = hb_tree_remove(tree, key);
    if(removed.removed) {
        ospf_lsa_tree_entry_free(removed.datum);
        return true;
    }
    return false;
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
    return ospf_lsa_tree_remove(&lsa->key, neighbor->lsa_retry_tree[lsa->type]);
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
    uint8_t type;

    /* Deleting objects from a tree while iterating is unsafe, 
     * so instead, a list of objects is created during the iteration 
     * process to mark them for deletion. Once the iteration is complete, 
     * the objects in the delete list can be safely removed from the tree. */
    ospf_lsa_s *delete_list[OSPF_LSA_GC_DELETE_MAX];
    size_t delete_list_len;
    size_t i;

    dict_remove_result removed;

    for(type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
        delete_list_len = 0;
        itor = hb_itor_new(ospf_instance->lsdb[type]);
        next = hb_itor_first(itor);
        while(next) {
            lsa = *hb_itor_datum(itor);
            next = hb_itor_next(itor);
            if(lsa && lsa->deleted && lsa->refcount == 0) {
                delete_list[delete_list_len++] = lsa;
                if(delete_list_len == OSPF_LSA_GC_DELETE_MAX) {
                    next = NULL;
                }
            }
        }
        hb_itor_free(itor);

        /* Finally delete from LSDB! */
        for(i=0; i < delete_list_len; i++) {
            removed = hb_tree_remove(ospf_instance->lsdb[type], &delete_list[i]->key);
            if(removed.removed) {
                lsa = removed.datum;
                timer_del(lsa->timer_lifetime);
                timer_del(lsa->timer_refresh);
                if(lsa->lsa) {
                    free(lsa->lsa);
                }
                free(lsa);
            }
        }
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
    uint32_t lsa_id = lsa->key.id;
    uint32_t lsa_router = lsa->key.router;

    LOG(OSPF, "OSPF RX TYPE-%u-LSA %s (seq %u router %s) lifetime expired (max age)\n",
        lsa->type, format_ipv4_address(&lsa_id), lsa->seq, format_ipv4_address(&lsa_router));

    lsa->expired = true;
    timer_add(&g_ctx->timer_root, &lsa->timer_lifetime, 
              "OSPF PURGE", 30, 0, 
              lsa, &ospf_lsa_purge_job);
    timer_no_smear(lsa->timer_lifetime);
}

void
ospf_lsa_lifetime(ospf_lsa_s *lsa)
{
    timer_del(lsa->timer_refresh);
    if(lsa->age < OSPF_LSA_MAX_AGE) {
        timer_add(&g_ctx->timer_root, &lsa->timer_lifetime, 
                  "OSPF LIFETIME", OSPF_LSA_MAX_AGE-lsa->age, 0, 
                  lsa, &ospf_lsa_lifetime_job);
    } else {
        lsa->expired = true;
        timer_add(&g_ctx->timer_root, &lsa->timer_lifetime, 
                "OSPF PURGE", 30, 0, 
                lsa, &ospf_lsa_purge_job);
    }
    timer_no_smear(lsa->timer_lifetime);
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
    ospf_interface_s *ospf_interface;
    ospf_neighbor_s *ospf_neighbor;
    ospf_lsa_tree_entry_s *entry;

    bool flood_interface;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    ospf_interface = lsa->instance->interfaces;
    while(ospf_interface) {
        flood_interface = false;
        /* Add to neighbors retry list. */
        ospf_neighbor = ospf_interface->neighbors;
        while(ospf_neighbor) {
            if(ospf_neighbor->state > OSPF_NBSTATE_EXSTART && lsa->source.router_id != ospf_neighbor->router_id) {
                flood_interface = true;
                entry = ospf_lsa_tree_add(lsa, NULL, ospf_neighbor->lsa_retry_tree[lsa->type]);
                if(entry) {
                    entry->timestamp.tv_sec = now.tv_sec;
                    entry->timestamp.tv_nsec = now.tv_nsec;
                }
            }
            ospf_neighbor = ospf_neighbor->next;
        }

        /* Add to interface flood tree if placed on at least one neighbors retry list. */
        if(flood_interface) {
            ospf_lsa_tree_add(lsa, NULL, ospf_interface->lsa_flood_tree[lsa->type]);
        }
        ospf_interface = ospf_interface->next;
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
    uint16_t checksum = 0;

    assert(lsa->lsa_len >= sizeof(ospf_lsa_header_s));
    if(lsa->lsa_len < sizeof(ospf_lsa_header_s)) {
        return;
    }

    hdr = (ospf_lsa_header_s*)lsa->lsa;
    hdr->age = htobe16(lsa->age);
    hdr->seq = htobe32(lsa->seq);
    checksum = bbl_checksum_fletcher16(lsa->lsa+OSPF_LSA_AGE_LEN, lsa->lsa_len-OSPF_LSA_AGE_LEN, 14);
    hdr->checksum = checksum;
}

static bool
ospf_lsa_verify_checksum(ospf_lsa_header_s *hdr)
{
    uint16_t checksum = 0;
    uint16_t checksum_orig = hdr->checksum;
    uint16_t len = be16toh(hdr->length);
 
    if(len < sizeof(ospf_lsa_header_s)) return false;

    checksum = bbl_checksum_fletcher16(&hdr->options, len-OSPF_LSA_AGE_LEN, 14);
    hdr->checksum = checksum_orig;

    if(checksum == checksum_orig) {
        return true;
    } else {
        return false;
    }
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

ospf_lsa_s *
ospf_lsa_new(uint8_t type, ospf_lsa_key_s *key, ospf_instance_s *ospf_instance)
{
    ospf_lsa_s *lsa = calloc(1, sizeof(ospf_lsa_s));
    memcpy(&lsa->key, key, sizeof(ospf_lsa_key_s));
    lsa->type = type;
    lsa->instance = ospf_instance;
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
    ospf_lsa_lifetime(lsa);
    ospf_lsa_update_hdr(lsa);
    ospf_lsa_flood(lsa);
}

/**
 * ospf_lsa_purge_all_external 
 * 
 * @param instance  OSPF instance
 */
void
ospf_lsa_purge_all_external(ospf_instance_s *ospf_instance)
{
    ospf_lsa_s *lsa;
    hb_itor *itor;
    bool next;
    uint8_t type;

    for(type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
        if(!ospf_instance->lsdb[type]) continue;
        itor = hb_itor_new(ospf_instance->lsdb[type]);
        next = hb_itor_first(itor);
        while(next) {
            lsa = *hb_itor_datum(itor);
            if(lsa && lsa->source.type == OSPF_SOURCE_EXTERNAL) {
                ospf_lsa_purge(lsa);
            }
            next = hb_itor_next(itor);
        }
        hb_itor_free(itor);
    }
}

static uint16_t 
ospf_lsa_add_interface_v2(ospf_lsa_s *lsa, ospf_interface_s *ospf_interface)
{
    ospf_neighbor_s *ospf_neighbor = ospf_interface->neighbors;
    ospfv2_lsa_link_s *link;
    uint16_t links = 0;

    /* We need space for up to 2 links per interface! */
    if(lsa->lsa_len + (sizeof(ospfv2_lsa_link_s)*2) > lsa->lsa_buf_len) {
        return 0;
    }

    switch(ospf_interface->state) {
        case OSPF_IFSTATE_P2P:
            if(ospf_interface->neighbors_full) {
                link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
                link->link_id = ospf_neighbor->router_id;
                link->link_data = ospf_interface->interface->ip.address;
                link->type = OSPF_LSA_LINK_P2P;
                link->tos = 0;
                link->metric = htobe16(ospf_interface->metric);
                lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
                links++;
            }
            link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
            link->link_id = ospf_interface->interface->ip.address & ipv4_len_to_mask(ospf_interface->interface->ip.len);
            link->link_data = ipv4_len_to_mask(ospf_interface->interface->ip.len);
            link->type = OSPF_LSA_LINK_STUB;
            link->tos = 0;
            link->metric = htobe16(ospf_interface->metric);
            lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
            links++;
            break;
        case OSPF_IFSTATE_WAITING:
            link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
            link->link_id = ospf_interface->interface->ip.address & ipv4_len_to_mask(ospf_interface->interface->ip.len);
            link->link_data = ipv4_len_to_mask(ospf_interface->interface->ip.len);
            link->type = OSPF_LSA_LINK_STUB;
            link->tos = 0;
            link->metric = htobe16(ospf_interface->metric);
            lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
            links++;
            break;
        case OSPF_IFSTATE_DR:
            if(ospf_interface->neighbors_full) {
                link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
                link->link_id = ospf_interface->interface->ip.address;
                link->link_data = ospf_interface->interface->ip.address;
                link->type = OSPF_LSA_LINK_TRANSIT;
                link->tos = 0;
                link->metric = htobe16(ospf_interface->metric);
                lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
                links++;
            } else {
                link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
                link->link_id = ospf_interface->interface->ip.address & ipv4_len_to_mask(ospf_interface->interface->ip.len);
                link->link_data = ipv4_len_to_mask(ospf_interface->interface->ip.len);
                link->type = OSPF_LSA_LINK_STUB;
                link->tos = 0;
                link->metric = htobe16(ospf_interface->metric);
                lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
                links++;
            }
            if(lsa->lsa_len + sizeof(ospfv2_lsa_link_s) > lsa->lsa_buf_len) {
                return links;
            }
            break;
        case OSPF_IFSTATE_BACKUP:
        case OSPF_IFSTATE_DR_OTHER:
            while(ospf_neighbor) {
                if(ospf_neighbor->state == OSPF_NBSTATE_FULL && 
                   ospf_neighbor->ipv4 == ospf_interface->dr) {
                    link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
                    link->link_id = ospf_neighbor->ipv4;
                    link->link_data = ospf_interface->interface->ip.address;
                    link->type = OSPF_LSA_LINK_TRANSIT;
                    lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
                    links++;
                    break;
                }
                ospf_neighbor = ospf_neighbor->next;
            }
            link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
            link->link_id = ospf_interface->interface->ip.address & ipv4_len_to_mask(ospf_interface->interface->ip.len);
            link->link_data = ipv4_len_to_mask(ospf_interface->interface->ip.len);
            link->type = OSPF_LSA_LINK_STUB;
            link->tos = 0;
            link->metric = htobe16(ospf_interface->metric);
            lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
            links++;
            break;
        default:
            break;
    }
    return links;
}

static uint16_t 
ospf_lsa_add_interface_v3(ospf_lsa_s *lsa, ospf_interface_s *ospf_interface)
{
    ospf_neighbor_s *ospf_neighbor = ospf_interface->neighbors;
    ospfv3_lsa_link_s *link;
    uint16_t links = 0;

    /* We need space for up to 2 neighbors per interface! */
    if(lsa->lsa_len + (sizeof(ospfv3_lsa_link_s)*2) > lsa->lsa_buf_len) {
        return 0;
    }

    switch(ospf_interface->state) {
        case OSPF_IFSTATE_P2P:
            if(ospf_interface->neighbors_full) {
                link = (ospfv3_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
                link->type = OSPF_LSA_LINK_P2P;
                link->reserved = 0;
                link->metric = htobe16(ospf_interface->metric);
                link->interface_id = ospf_interface->id;
                link->neighbor_interface_id = ospf_neighbor->id;
                link->neighbor_router_id = ospf_neighbor->router_id;
                lsa->lsa_len += sizeof(ospfv3_lsa_link_s);
                links++;
            }
            break;
        default:
            break;
    }
    return links;
}

static void
ospf_lsa_prefix_v3(ospf_instance_s *ospf_instance)
{
    /* Generate Intra-Area-Prefix LSA */
    ospf_interface_s *ospf_interface = ospf_instance->interfaces;
    ospf_config_s *config = ospf_instance->config;

    ospf_external_connection_s *external_connection = NULL;

    void **search = NULL;
    dict_insert_result result;

    ospfv3_lsa_iap_s *iap;
    ospfv3_lsa_iap_prefix_s *prefix;
    uint16_t prefixes = 0;

    ospf_lsa_s *lsa;
    ospf_lsa_header_s *hdr;
    ospf_lsa_key_s key = { 
        .id = config->router_id,
        .router = config->router_id
    };
    search = hb_tree_search(ospf_instance->lsdb[OSPF_LSA_TYPE_9], &key);
    if(search) {
        /* Update existing LSA. */
        lsa = *search;
        if(lsa->lsa && lsa->lsa_buf_len && 
           lsa->lsa_buf_len < OSPF_MAX_SELF_LSA_LEN) {
            free(lsa->lsa);
            lsa->lsa = malloc(OSPF_MAX_SELF_LSA_LEN);
            lsa->lsa_buf_len = OSPF_MAX_SELF_LSA_LEN;
        }
    } else {
        /* Create new LSA. */
        lsa = ospf_lsa_new(OSPF_LSA_TYPE_9, &key, ospf_instance);
        lsa->seq = OSPF_LSA_SEQ_INIT;
        lsa->lsa = malloc(OSPF_MAX_SELF_LSA_LEN);
        lsa->lsa_buf_len = OSPF_MAX_SELF_LSA_LEN;
        result = hb_tree_insert(ospf_instance->lsdb[OSPF_LSA_TYPE_9], &lsa->key);
        assert(result.inserted);
        if(result.inserted) {
            *result.datum_ptr = lsa;
        } else {
            LOG_NOARG(OSPF, "Failed to add self generated OSPF Type 9 LSA to LSDB\n");
            return;
        }
    }
    lsa->source.type = OSPF_SOURCE_SELF;
    lsa->source.router_id = config->router_id;
    lsa->lsa_len = OSPF_LSA_HDR_LEN;
    lsa->expired = false;
    lsa->deleted = false;    
    hdr = (ospf_lsa_header_s*)lsa->lsa;
    hdr->options = OSPFV3_FSCOPE_AREA;
    hdr->type = OSPF_LSA_TYPE_9;
    hdr->id = key.id;
    hdr->router = key.router;
    hdr->seq = htobe32(lsa->seq);

    iap = (ospfv3_lsa_iap_s*)(lsa->lsa+lsa->lsa_len);
    lsa->lsa_len += sizeof(ospfv3_lsa_iap_s);
    iap->prefix_count = 0;
    iap->ref_type = htobe16(0x2001); /* referenced to router LSA */
    iap->ref_router = config->router_id;

    while(ospf_interface) {
        prefix = (ospfv3_lsa_iap_prefix_s*)(lsa->lsa+lsa->lsa_len);
        prefix->prefix_len = ospf_interface->interface->ip6.len;
        prefix->prefix_options = 0;
        prefix->metric = htobe16(ospf_interface->metric);
        memcpy(prefix->prefix, ospf_interface->interface->ip6.address, sizeof(ipv6addr_t));
        lsa->lsa_len += (sizeof(ospfv3_lsa_iap_prefix_s) - (sizeof(ipv6addr_t)-BITS_TO_BYTES(prefix->prefix_len)));
        prefixes++;
        ospf_interface = ospf_interface->next;
    }
    
    /* Add external connections */
    external_connection = config->external_connection;
    while(external_connection && lsa->lsa_len + sizeof(ospfv3_lsa_iap_prefix_s) <= lsa->lsa_buf_len) {
        prefix = (ospfv3_lsa_iap_prefix_s*)(lsa->lsa+lsa->lsa_len);
        prefix->prefix_len = external_connection->ipv6.len;
        prefix->prefix_options = 0;
        prefix->metric = htobe16(external_connection->metric);
        memcpy(prefix->prefix, external_connection->ipv6.address, sizeof(ipv6addr_t));
        lsa->lsa_len += (sizeof(ospfv3_lsa_iap_prefix_s) - (sizeof(ipv6addr_t)-BITS_TO_BYTES(prefix->prefix_len)));
        prefixes++;
        external_connection = external_connection->next;
    }

    iap->prefix_count = htobe16(prefixes);
    hdr->length = htobe16(lsa->lsa_len);
    ospf_lsa_refresh(lsa);
}

static void
ospf_lsa_links_v3(ospf_lsa_s *lsa)
{
    ospf_instance_s *ospf_instance = lsa->instance;
    ospf_interface_s *ospf_interface = ospf_instance->interfaces;
    ospf_config_s *config = ospf_instance->config;

    ospf_external_connection_s *external_connection = NULL;

    ospfv3_lsa_link_s *link;

    /* Options */
    *(uint16_t*)(lsa->lsa+lsa->lsa_len) = 0; 
    lsa->lsa_len += sizeof(uint16_t);

    /* Add OSPF neighbor interfaces */
    while(ospf_interface) {
        if(lsa->lsa_len + sizeof(ospfv3_lsa_link_s) <= lsa->lsa_buf_len) {
            ospf_lsa_add_interface_v3(lsa, ospf_interface);
        }
        ospf_interface = ospf_interface->next;
    }

    /* Add external connections */
    external_connection = config->external_connection;
    while(external_connection && lsa->lsa_len + sizeof(ospfv3_lsa_link_s) <= lsa->lsa_buf_len) {
        link = (ospfv3_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
        link->type = OSPF_LSA_LINK_P2P;
        link->reserved = 0;
        link->metric = htobe16(external_connection->metric);
        link->interface_id = external_connection->interface_id;
        link->neighbor_interface_id = external_connection->router_id;
        link->neighbor_router_id = external_connection->router_id;
        lsa->lsa_len += sizeof(ospfv3_lsa_link_s);
        external_connection = external_connection->next;
    }
}

static void
ospf_lsa_del_network_v2(ospf_interface_s *ospf_interface)
{
    ospf_instance_s *ospf_instance = ospf_interface->instance;
    ospf_config_s *config = ospf_instance->config;

    void **search = NULL;

    ospf_lsa_s *lsa;
    ospf_lsa_key_s key = { 
        .id = ospf_interface->interface->ip.address,
        .router = config->router_id
    };
    search = hb_tree_search(ospf_instance->lsdb[OSPF_LSA_TYPE_2], &key);
    if(search) {
        /* Update existing LSA. */
        lsa = *search;
        if(lsa->source.type == OSPF_SOURCE_SELF) {
            ospf_lsa_purge(lsa);
        }
    }
}

static void
ospf_lsa_add_network_v2(ospf_interface_s *ospf_interface)
{
    ospf_instance_s *ospf_instance = ospf_interface->instance;
    ospf_neighbor_s *ospf_neighbor;
    ospf_config_s *config = ospf_instance->config;

    void **search = NULL;
    dict_insert_result result;

    ospf_lsa_s *lsa;
    ospf_lsa_header_s *hdr;
    ospf_lsa_key_s key = { 
        .id = ospf_interface->interface->ip.address,
        .router = config->router_id
    };

    search = hb_tree_search(ospf_instance->lsdb[OSPF_LSA_TYPE_2], &key);
    if(search) {
        /* Update existing LSA. */
        lsa = *search;
        if(lsa->lsa && lsa->lsa_buf_len && 
           lsa->lsa_buf_len < OSPF_MAX_SELF_LSA_LEN) {
            free(lsa->lsa);
            lsa->lsa = malloc(OSPF_MAX_SELF_LSA_LEN);
            lsa->lsa_buf_len = OSPF_MAX_SELF_LSA_LEN;
        }
    } else {
        /* Create new LSA. */
        lsa = ospf_lsa_new(OSPF_LSA_TYPE_2, &key, ospf_instance);
        lsa->seq = OSPF_LSA_SEQ_INIT;
        lsa->lsa = malloc(OSPF_MAX_SELF_LSA_LEN);
        lsa->lsa_buf_len = OSPF_MAX_SELF_LSA_LEN;
        result = hb_tree_insert(ospf_instance->lsdb[OSPF_LSA_TYPE_2], &lsa->key);
        assert(result.inserted);
        if(result.inserted) {
            *result.datum_ptr = lsa;
        } else {
            LOG_NOARG(OSPF, "Failed to add self generated OSPF Type 2 LSA to LSDB\n");
            return;
        }
    }
    lsa->source.type = OSPF_SOURCE_SELF;
    lsa->source.router_id = config->router_id;
    lsa->lsa_len = OSPF_LSA_HDR_LEN;
    lsa->expired = false;
    lsa->deleted = false;    
    hdr = (ospf_lsa_header_s*)lsa->lsa;
    hdr->options = OSPF_OPTION_E_BIT;
    hdr->type = OSPF_LSA_TYPE_2;
    hdr->id = key.id;
    hdr->router = key.router;
    hdr->seq = htobe32(lsa->seq);

    *(uint32_t*)(lsa->lsa+lsa->lsa_len) = ipv4_len_to_mask(ospf_interface->interface->ip.len);
    lsa->lsa_len += sizeof(uint32_t);

    *(uint32_t*)(lsa->lsa+lsa->lsa_len) = key.router;
    lsa->lsa_len += sizeof(uint32_t);

    ospf_neighbor = ospf_interface->neighbors;
    while(ospf_neighbor) {
        if(ospf_neighbor->state == OSPF_NBSTATE_FULL) {
           *(uint32_t*)(lsa->lsa+lsa->lsa_len) = ospf_neighbor->router_id;
           lsa->lsa_len += sizeof(uint32_t);
        }
        ospf_neighbor = ospf_neighbor->next;
    }
    hdr->length = htobe16(lsa->lsa_len);
    ospf_lsa_refresh(lsa);
}

/**
 * This function updates the self originated Type 2 network LSA.
 *
 * @param ospf_interface OSPF interface
 */
static void
ospf_lsa_network_v2(ospf_interface_s *ospf_interface)
{
    if(ospf_interface->state == OSPF_IFSTATE_DR && 
       ospf_interface->neighbors_full) {
        ospf_lsa_add_network_v2(ospf_interface);
    } else {
        ospf_lsa_del_network_v2(ospf_interface);
    }
}

static void
ospf_lsa_links_v2(ospf_lsa_s *lsa)
{
    ospf_instance_s *ospf_instance = lsa->instance;
    ospf_interface_s *ospf_interface = ospf_instance->interfaces;
    ospf_config_s *config = ospf_instance->config;

    ospf_external_connection_s *external_connection = NULL;

    ospfv2_lsa_link_s *link;
    uint16_t links = 0;
    uint16_t links_cur = 0;

    /* # links */
    links_cur = lsa->lsa_len;
    lsa->lsa_len += sizeof(uint16_t);

    /* Add loopback */
    link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
    link->link_id = config->router_id;
    link->link_data = 0xffffffff;
    link->type = OSPF_LSA_LINK_STUB;
    link->tos = 0;
    link->metric = 0;
    lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
    links++;

    /* Add OSPF neighbor interfaces */
    while(ospf_interface) {
        if(ospf_interface->type == OSPF_INTERFACE_BROADCAST) {
            ospf_lsa_network_v2(ospf_interface);
        }
        if(lsa->lsa_len + sizeof(ospfv2_lsa_link_s) <= lsa->lsa_buf_len) {
            links += ospf_lsa_add_interface_v2(lsa, ospf_interface);
        }
        ospf_interface = ospf_interface->next;
    }

    /* Add external connections */
    external_connection = config->external_connection;
    while(external_connection && lsa->lsa_len + sizeof(ospfv2_lsa_link_s) <= lsa->lsa_buf_len) {
        link = (ospfv2_lsa_link_s*)(lsa->lsa+lsa->lsa_len);
        link->link_id = external_connection->router_id;
        link->link_data = external_connection->ipv4.address;
        link->type = OSPF_LSA_LINK_P2P;
        link->tos = 0;
        link->metric = htobe16(external_connection->metric);
        lsa->lsa_len += sizeof(ospfv2_lsa_link_s);
        links++;
        external_connection = external_connection->next;
    }

    *(uint16_t*)(lsa->lsa+links_cur) = htobe16(links); 
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
    ospf_config_s *config = ospf_instance->config;

    void **search = NULL;
    dict_insert_result result;

    uint8_t options;

    ospf_lsa_s *lsa;
    ospf_lsa_header_s *hdr;

    ospf_lsa_key_s key = { 
        .id = config->router_id, 
        .router = config->router_id
    };

    search = hb_tree_search(ospf_instance->lsdb[OSPF_LSA_TYPE_1], &key);
    if(search) {
        /* Update existing LSA. */
        lsa = *search;
        if(lsa->lsa && lsa->lsa_buf_len && 
           lsa->lsa_buf_len < OSPF_MAX_SELF_LSA_LEN) {
            free(lsa->lsa);
            lsa->lsa = malloc(OSPF_MAX_SELF_LSA_LEN);
            lsa->lsa_buf_len = OSPF_MAX_SELF_LSA_LEN;
        }
    } else {
        /* Create new LSA. */
        lsa = ospf_lsa_new(OSPF_LSA_TYPE_1, &key, ospf_instance);
        lsa->seq = OSPF_LSA_SEQ_INIT;
        lsa->lsa = malloc(OSPF_MAX_SELF_LSA_LEN);
        lsa->lsa_buf_len = OSPF_MAX_SELF_LSA_LEN;
        result = hb_tree_insert(ospf_instance->lsdb[OSPF_LSA_TYPE_1], &lsa->key);
        assert(result.inserted);
        if(result.inserted) {
            *result.datum_ptr = lsa;
        } else {
            LOG_NOARG(OSPF, "Failed to add self generated OSPF Type 1 LSA to LSDB\n");
            return false;
        }
    }

    lsa->source.type = OSPF_SOURCE_SELF;
    lsa->source.router_id = config->router_id;
    lsa->lsa_len = OSPF_LSA_HDR_LEN;
    lsa->expired = false;
    lsa->deleted = false;
    hdr = (ospf_lsa_header_s*)lsa->lsa;
    hdr->type = OSPF_LSA_TYPE_1;
    hdr->id = key.id;
    hdr->router = key.router;
    hdr->seq = htobe32(lsa->seq);

    /* Set external and border router bits. */
    *(lsa->lsa+lsa->lsa_len++) = OSPF_LSA_BORDER_ROUTER|OSPF_LSA_EXTERNAL_ROUTER;
    /* Reserved */
    *(lsa->lsa+lsa->lsa_len++) = 0;

    if(config->version == OSPF_VERSION_2) {
        options = OSPF_OPTION_E_BIT;
        hdr->options = options;
        ospf_lsa_links_v2(lsa);
    } else {
        options = OSPFV3_FSCOPE_AREA;
        hdr->options = options;
        ospf_lsa_links_v3(lsa);
        ospf_lsa_prefix_v3(ospf_instance);
    }

    hdr->length = htobe16(lsa->lsa_len);
    ospf_lsa_refresh(lsa);

    timer_add_periodic(&g_ctx->timer_root, &lsa->timer_refresh, 
                       "OSPF LSA REFRESH", OSPF_LSA_REFRESH_TIME, 3, lsa, 
                       &ospf_lsa_refresh_job);
    return true;
}

void
ospf_lsa_self_update_job(timer_s *timer)
{
    ospf_instance_s *ospf_instance = timer->data;
    ospf_lsa_self_update(ospf_instance);
    ospf_instance->lsa_self_requested = false;
}

void
ospf_lsa_self_update_request(ospf_instance_s *ospf_instance)
{
    if(!ospf_instance->lsa_self_requested) {
        ospf_instance->lsa_self_requested = true;
        timer_add(&g_ctx->timer_root, &ospf_instance->timer_lsa_self, 
                  "OSPF LSA GC", 0, 10 * MSEC, ospf_instance,
                  &ospf_lsa_self_update_job);
    }
}

static protocol_error_t
ospf_lsa_update_pdu_tx(ospf_pdu_s *pdu, uint16_t lsa_count,
                       ospf_interface_s *ospf_interface, 
                       ospf_neighbor_s *ospf_neighbor)
{
    ospf_instance_s *ospf_instance = ospf_interface->instance;
    ospf_config_s *config = ospf_instance->config;

    if(lsa_count == 0) {
        return EMPTY;
    }

    /* Update LSA count */
    if(pdu->pdu_version == OSPF_VERSION_2) {
        *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_LS_UPDATE_COUNT) = htobe32(lsa_count);
    } else {
        *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_LS_UPDATE_COUNT) = htobe32(lsa_count);
    }

    /* Update length, auth, checksum and send... */
    ospf_pdu_update_len(pdu);
    ospf_pdu_update_auth(pdu, config->auth_type, config->auth_key);
    ospf_pdu_update_checksum(pdu);
    if(ospf_pdu_tx(pdu, ospf_interface, ospf_neighbor) == PROTOCOL_SUCCESS) {
        ospf_interface->stats.ls_upd_tx++;
        return PROTOCOL_SUCCESS;
    } else {
        return SEND_ERROR;
    }
}

protocol_error_t
ospf_lsa_update_tx(ospf_interface_s *ospf_interface, 
                   ospf_neighbor_s *ospf_neighbor, 
                   bool retry)
{
    ospf_instance_s *ospf_instance = ospf_interface->instance;
    ospf_config_s *config = ospf_instance->config;
    ospf_lsa_tree_entry_s *entry;
    ospf_lsa_s *lsa;

    bbl_network_interface_s *interface = ospf_interface->interface;

    hb_tree *tree;
    hb_itor *itor;
    bool next;
    void **search = NULL;

    uint16_t overhead;
    uint16_t lsa_count = 0;
    uint8_t type;
    struct timespec now;
    struct timespec ago;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint16_t lsa_start_cur;
    uint16_t lsa_start_len;

    ospf_pdu_s pdu;
    ospf_pdu_init(&pdu, OSPF_PDU_LS_UPDATE, ospf_interface->version);

    /* OSPF header */
    ospf_pdu_add_u8(&pdu, ospf_interface->version);
    ospf_pdu_add_u8(&pdu, pdu.pdu_type);
    ospf_pdu_add_u16(&pdu, 0); /* skip length */
    ospf_pdu_add_ipv4(&pdu, config->router_id); /* Router ID */
    ospf_pdu_add_ipv4(&pdu, config->area); /* Area ID */
    ospf_pdu_add_u16(&pdu, 0); /* skip checksum */
    if(ospf_interface->version == OSPF_VERSION_2) {
        overhead = 20; /* IPv4 header length */
        if(config->auth_type == OSPF_AUTH_MD5) {
            overhead += OSPF_MD5_DIGEST_LEN;
        }
        ospf_pdu_zero_bytes(&pdu, OSPFV2_AUTH_TYPE_LEN+OSPFV2_AUTH_DATA_LEN);
    } else {
        overhead = 40; /* IPv6 header length */
        ospf_pdu_add_u16(&pdu, 0);
    }
    ospf_pdu_add_u32(&pdu, 0); /* skip lsa_count */

    lsa_start_cur = pdu.cur;
    lsa_start_len = pdu.pdu_len;
    for(type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
        if(ospf_neighbor && retry) {
            /* Retry. */
            tree = ospf_neighbor->lsa_retry_tree[type];
            itor = hb_itor_new(tree);
            next = hb_itor_first(itor);
            while(next) {
                entry = *hb_itor_datum(itor);
                next = hb_itor_next(itor);
                timespec_sub(&ago, &now, &entry->timestamp);
                if(ago.tv_sec < config->lsa_retry_interval) {
                    continue;
                }
                lsa = entry->lsa;
                if(lsa && lsa->lsa_len >= OSPF_LSA_HDR_LEN) {
                    if(lsa_count > 0 && (overhead + pdu.pdu_len + lsa->lsa_len) > interface->mtu) {
                        ospf_lsa_update_pdu_tx(&pdu, lsa_count, ospf_interface, ospf_neighbor);
                        pdu.cur = lsa_start_cur;
                        pdu.pdu_len = lsa_start_len;
                        lsa_count = 0;
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
                tree = ospf_neighbor->lsa_update_tree[type];
            } else {
                tree = ospf_interface->lsa_flood_tree[type];
            }
            search = hb_tree_search_gt(tree, &g_lsa_key_zero);
            while(search) {
                entry = *search;
                lsa = entry->lsa;
                if(lsa && lsa->lsa_len >= OSPF_LSA_HDR_LEN) {
                    if(lsa_count > 0 && (overhead + pdu.pdu_len + lsa->lsa_len) > interface->mtu) {
                        ospf_lsa_update_pdu_tx(&pdu, lsa_count, ospf_interface, ospf_neighbor);
                        pdu.cur = lsa_start_cur;
                        pdu.pdu_len = lsa_start_cur;
                        lsa_count = 0;
                    }
                    ospf_lsa_update_age(entry->lsa, &now);
                    ospf_pdu_add_bytes(&pdu, lsa->lsa, lsa->lsa_len);
                    lsa_count++;
                }
                ospf_lsa_tree_remove(&entry->key, tree);
                search = hb_tree_search_gt(tree, &g_lsa_key_zero);
            }
        }
    }

    return ospf_lsa_update_pdu_tx(&pdu, lsa_count, ospf_interface, ospf_neighbor);
}


protocol_error_t
ospf_lsa_req_tx(ospf_interface_s *ospf_interface, ospf_neighbor_s *ospf_neighbor)
{
    ospf_instance_s *ospf_instance = ospf_interface->instance;
    ospf_config_s *config = ospf_instance->config;
    ospf_lsa_tree_entry_s *entry;

    bbl_network_interface_s *interface = ospf_interface->interface;

    hb_tree *tree;
    hb_itor *itor;
    bool next;

    uint8_t type;
    uint16_t overhead;
    uint16_t lsa_count = 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    ospf_pdu_s pdu;
    ospf_pdu_init(&pdu, OSPF_PDU_LS_REQUEST, ospf_interface->version);

    /* OSPF header */
    ospf_pdu_add_u8(&pdu, ospf_interface->version);
    ospf_pdu_add_u8(&pdu, pdu.pdu_type);
    ospf_pdu_add_u16(&pdu, 0); /* skip length */
    ospf_pdu_add_ipv4(&pdu, config->router_id); /* Router ID */
    ospf_pdu_add_ipv4(&pdu, config->area); /* Area ID */
    ospf_pdu_add_u16(&pdu, 0); /* skip checksum */
    if(ospf_interface->version == OSPF_VERSION_2) {
        overhead = 20; /* IPv4 header length */
        if(config->auth_type == OSPF_AUTH_MD5) {
            overhead += OSPF_MD5_DIGEST_LEN;
        }
        ospf_pdu_zero_bytes(&pdu, OSPFV2_AUTH_TYPE_LEN+OSPFV2_AUTH_DATA_LEN);
    } else {
        overhead = 40; /* IPv6 header length */
        ospf_pdu_add_u16(&pdu, 0);
    }
    for(type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
        tree = ospf_neighbor->lsa_request_tree[type];
        itor = hb_itor_new(tree);
        next = hb_itor_first(itor);
        while(next) {
            entry = *hb_itor_datum(itor);
            next = hb_itor_next(itor);
            if(lsa_count > 0 && (overhead + pdu.pdu_len + OSPF_LSA_HDR_LEN) > interface->mtu) {
                break;
            }
            if(ospf_interface->version == OSPF_VERSION_2) {
                ospf_pdu_add_u32(&pdu, entry->hdr.type);
            } else {
                ospf_pdu_add_u16(&pdu, 0);
                ospf_pdu_add_u8(&pdu, entry->hdr.options);
                ospf_pdu_add_u8(&pdu, entry->hdr.type);
            }
            ospf_pdu_add_ipv4(&pdu, entry->hdr.id);
            ospf_pdu_add_ipv4(&pdu, entry->hdr.router);
            lsa_count++;
        }
        hb_itor_free(itor);
    }
    if(lsa_count == 0) {
        return EMPTY;
    }

    /* Update length, auth, checksum and send... */
    ospf_pdu_update_len(&pdu);
    ospf_pdu_update_auth(&pdu, config->auth_type, config->auth_key);
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
    ospf_config_s *config = ospf_instance->config;
    ospf_lsa_tree_entry_s *entry;
    ospf_lsa_s *lsa;

    bbl_network_interface_s *interface = ospf_interface->interface;

    hb_tree *tree;
    void **search = NULL;

    uint8_t type;
    uint16_t overhead;
    uint16_t lsa_count = 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    ospf_pdu_s pdu;
    ospf_pdu_init(&pdu, OSPF_PDU_LS_ACK, ospf_interface->version);

    /* OSPF header */
    ospf_pdu_add_u8(&pdu, ospf_interface->version);
    ospf_pdu_add_u8(&pdu, pdu.pdu_type);
    ospf_pdu_add_u16(&pdu, 0); /* skip length */
    ospf_pdu_add_ipv4(&pdu, ospf_instance->config->router_id); /* Router ID */
    ospf_pdu_add_ipv4(&pdu, ospf_instance->config->area); /* Area ID */
    ospf_pdu_add_u16(&pdu, 0); /* skip checksum */
    if(ospf_interface->version == OSPF_VERSION_2) {
        overhead = 20; /* IPv4 header length */
        if(config->auth_type == OSPF_AUTH_MD5) {
            overhead += OSPF_MD5_DIGEST_LEN;
        }
        ospf_pdu_zero_bytes(&pdu, OSPFV2_AUTH_TYPE_LEN+OSPFV2_AUTH_DATA_LEN);
    } else {
        overhead = 40; /* IPv6 header length */
        ospf_pdu_add_u16(&pdu, 0);
    }

    for(type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
        if(ospf_neighbor) {
            /* Direct LS ack */
            tree = ospf_neighbor->lsa_ack_tree[type];
        } else {
            /* Delayed LS ack */
            tree = ospf_interface->lsa_ack_tree[type];
        }
        search = hb_tree_search_gt(tree, &g_lsa_key_zero);
        while(search) {
            entry = *search;
            lsa = entry->lsa;
            if(lsa && lsa->lsa_len >= OSPF_LSA_HDR_LEN) {
                ospf_lsa_update_age(lsa, &now);
                ospf_pdu_add_bytes(&pdu, lsa->lsa, OSPF_LSA_HDR_LEN);
            } else {
                ospf_pdu_add_bytes(&pdu, (uint8_t*)&entry->hdr, OSPF_LSA_HDR_LEN);
            }
            lsa_count++;
            ospf_lsa_tree_remove((ospf_lsa_key_s*)&entry->key, tree);
            if((overhead + pdu.pdu_len + OSPF_LSA_HDR_LEN) > interface->mtu) {
                break;
            }
            search = hb_tree_search_gt(tree, &g_lsa_key_zero);
        }
    }
    if(lsa_count == 0) {
        return EMPTY;
    }

    /* Update length, auth, checksum and send... */
    ospf_pdu_update_len(&pdu);
    ospf_pdu_update_auth(&pdu, config->auth_type, config->auth_key);
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

    void **search = NULL;
    dict_insert_result result;

    uint32_t lsa_id;
    uint32_t lsa_router;
    uint32_t lsa_count;
    uint16_t lsa_len;
    uint8_t  lsa_type;

    int lsa_compare;
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
    while(OSPF_PDU_CURSOR_PLEN(pdu) >= OSPF_LSA_HDR_LEN && lsa_count) {
        hdr = (ospf_lsa_header_s*)OSPF_PDU_CURSOR(pdu);
        key = (ospf_lsa_key_s*)&hdr->id;

        lsa_type = hdr->type;
        lsa_id = hdr->id;
        lsa_router = hdr->router;

        if(lsa_type < OSPF_LSA_TYPE_1 || lsa_type > OSPF_LSA_TYPE_11) {
            ospf_rx_error(interface, pdu, "decode (invalid LSA type)");
            return;
        }
        lsa_len = be16toh(hdr->length);
        if(lsa_len > OSPF_PDU_CURSOR_PLEN(pdu)) {
            ospf_rx_error(interface, pdu, "decode (invalid LSA len)");
            return;
        }
        if(!ospf_lsa_verify_checksum(hdr)) {
            ospf_rx_error(interface, pdu, "decode (invalid LSA checksum)");
            return;
        }

        OSPF_PDU_CURSOR_INC(pdu, lsa_len);
        lsa_count--;

        search = hb_tree_search(ospf_neighbor->lsa_request_tree[lsa_type], key);
        if(search) {
            entry = *search;
            if(ospf_lsa_compare((ospf_lsa_header_s*)&entry->hdr, hdr) != 1) {
                ospf_lsa_tree_remove(&entry->key, ospf_neighbor->lsa_request_tree[lsa_type]);
            }
        }

        search = hb_tree_search(ospf_instance->lsdb[lsa_type], key);
        if(search) {
            lsa = *search;
            ospf_lsa_update_age(lsa, &now);
            lsa_compare = ospf_lsa_compare((ospf_lsa_header_s*)lsa->lsa, hdr);
            if(lsa_compare == 1) {
                /* LOCAL LSA IS NEWER */
                if(!(lsa->seq == OSPF_LSA_SEQ_MAX && lsa->age >= OSPF_LSA_MAX_AGE)) {
                    /* Send direct LSA update. */
                    ospf_lsa_tree_add(lsa, NULL, ospf_neighbor->lsa_update_tree[lsa_type]);
                }
                /* Next LSA from update ... */
                continue;
            } else if(lsa_compare == 0) {
                /* EQUAL */
                if(ospf_lsa_retry_stop(lsa, ospf_neighbor)) {
                    /* Implied acknowledgment (see RFC2328 section 13, step 7a). */
                    if(ospf_interface->state == OSPF_IFSTATE_BACKUP && 
                        ospf_interface->dr == pdu->router_id) {
                        /* Send delayed LSA ack. */
                        ospf_lsa_tree_add(lsa, NULL, ospf_interface->lsa_ack_tree[lsa_type]);
                    }
                } else {
                    /* Send direct LSA ack. */
                    ospf_lsa_tree_add(lsa, NULL, ospf_neighbor->lsa_ack_tree[lsa_type]);
                }
                /* Next LSA from update ... */
                continue;
            }
            /* RECEIVED LSA IS NEWER ... */
            if(lsa->source.type == OSPF_SOURCE_EXTERNAL) {
                LOG(OSPF, "OSPF RX TYPE-%u-LSA %s (seq %u router %s) overwrite external LSA with seq %u\n",
                    lsa_type, format_ipv4_address(&lsa_id), be32toh(hdr->seq), 
                    format_ipv4_address(&lsa_router), lsa->seq);
            } else if(lsa_type == OSPF_LSA_TYPE_1 && lsa->source.type == OSPF_SOURCE_SELF) {
                lsa->seq = be32toh(hdr->seq);
                ospf_lsa_self_update(ospf_instance);
                continue;
            }
        } else {
            /* NEW LSA */
            lsa = ospf_lsa_new(lsa_type, key, ospf_instance);
            result = hb_tree_insert(ospf_instance->lsdb[lsa_type], &lsa->key);
            assert(result.inserted);
            if(result.inserted) {
                *result.datum_ptr = lsa;
            } else {
                LOG_NOARG(OSPF, "Failed to add received OSPF LSA to LSDB\n");
                return;
            }
        }

        if(lsa->lsa_buf_len < lsa_len) {
            if(lsa->lsa) free(lsa->lsa);
            lsa->lsa = malloc(lsa_len);
            lsa->lsa_buf_len = lsa_len;
        }
        memcpy(lsa->lsa, hdr, lsa_len);
        lsa->lsa_len = lsa_len;
        lsa->source.type = OSPF_SOURCE_ADJACENCY;
        lsa->source.router_id = ospf_neighbor->router_id;
        lsa->seq = be32toh(hdr->seq);
        lsa->age = be16toh(hdr->age)+1;
        lsa->timestamp.tv_sec = now.tv_sec;
        lsa->timestamp.tv_nsec = now.tv_sec;
        lsa->expired = false;
        ospf_lsa_update_age(lsa, &now);
        ospf_lsa_flood(lsa);
        ospf_lsa_tree_add(lsa, NULL, ospf_interface->lsa_ack_tree[lsa->type]);
        ospf_lsa_lifetime(lsa);
    }

    /* Send direct LSA ack. */
    ospf_lsa_ack_tx(ospf_interface, ospf_neighbor);
    /* Send direct LSA update. */
    ospf_lsa_update_tx(ospf_interface, ospf_neighbor, false);
    /* Check if state can updated from loading to full. */
    ospf_neighbor_full(ospf_neighbor);
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

    uint32_t lsa_type;
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

    while(OSPF_PDU_CURSOR_PLEN(pdu)) {
        if(ospf_interface->version == OSPF_VERSION_2) {
            if(OSPF_PDU_CURSOR_PLEN(pdu) < OSPFV2_LSA_REQ_HDR_LEN) {
                break;
            }
            lsa_type = be32toh(*(uint32_t*)OSPF_PDU_CURSOR(pdu));
            OSPF_PDU_CURSOR_INC(pdu, 4);
        } else {
            if(OSPF_PDU_CURSOR_PLEN(pdu) < OSPFV3_LSA_REQ_HDR_LEN) {
                break;
            }
            OSPF_PDU_CURSOR_INC(pdu, 3);
            lsa_type = *OSPF_PDU_CURSOR(pdu);
            OSPF_PDU_CURSOR_INC(pdu, 1);
        }
        if(lsa_type < OSPF_LSA_TYPE_1 || lsa_type > OSPF_LSA_TYPE_11) {
            ospf_rx_error(interface, pdu, "decode (invalid LSA type)");
            break;
        }

        key = (ospf_lsa_key_s*)OSPF_PDU_CURSOR(pdu);
        OSPF_PDU_CURSOR_INC(pdu, sizeof(ospf_lsa_key_s));

        search = hb_tree_search(ospf_instance->lsdb[lsa_type], key);
        if(search) {
            lsa = *search;
            if(!(lsa->seq == OSPF_LSA_SEQ_MAX && lsa->age >= OSPF_LSA_MAX_AGE)) {
                /* Send direct LSA update. */
                ospf_lsa_tree_add(lsa, NULL, ospf_neighbor->lsa_update_tree[lsa_type]);
            }
        } else {
            /* See RFC2328 BadLSReq */
            ospf_rx_error(interface, pdu, "BadLSReq");
            ospf_neighbor_update_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
        }
    }
    /* Send direct LSA update. */
    ospf_lsa_update_tx(ospf_interface, ospf_neighbor, false);
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
    while(OSPF_PDU_CURSOR_PLEN(pdu) >= OSPF_LSA_HDR_LEN) {
        hdr_a = (ospf_lsa_header_s*)OSPF_PDU_CURSOR(pdu);
        key = (ospf_lsa_key_s*)&hdr_a->id;
        OSPF_PDU_CURSOR_INC(pdu, OSPF_LSA_HDR_LEN);

        if(hdr_a->type < OSPF_LSA_TYPE_1 || hdr_a->type > OSPF_LSA_TYPE_11) {
            ospf_rx_error(interface, pdu, "invalid LSA type");
            return;
        }

        search = hb_tree_search(ospf_neighbor->lsa_retry_tree[hdr_a->type], key);
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
                ospf_lsa_tree_remove(key, ospf_neighbor->lsa_retry_tree[hdr_a->type]);
            }
        } 
    }
}

bool
ospf_lsa_load_external(ospf_instance_s *ospf_instance, uint16_t lsa_count, uint8_t *buf, uint16_t len)
{
    ospf_lsa_header_s *hdr;
    ospf_lsa_key_s *key;
    ospf_lsa_s *lsa;

    void **search = NULL;
    dict_insert_result result;
    uint16_t lsa_len;
    uint8_t  lsa_type;

     struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    while(len >= OSPF_LSA_HDR_LEN && lsa_count) {
        hdr = (ospf_lsa_header_s*)buf;
        key = (ospf_lsa_key_s*)&hdr->id;

        lsa_type = hdr->type;
        if(lsa_type < OSPF_LSA_TYPE_1 || lsa_type > OSPF_LSA_TYPE_11) {
            LOG_NOARG(ERROR, "Failed to decode external OSPF LSA (invalid LSA type)\n");
            return false;
        }
        lsa_len = be16toh(hdr->length);
        if(lsa_len > len) {
            LOG_NOARG(ERROR, "Failed to decode external OSPF LSA (invalid LSA len)\n");
            return false;
        }

        len -= lsa_len;
        buf += lsa_len;
        lsa_count--;

        if(!ospf_lsa_verify_checksum(hdr)) {
            LOG_NOARG(ERROR, "Failed to decode external OSPF LSA (invalid LSA checksum)\n"); 
            return false;
        }

        search = hb_tree_search(ospf_instance->lsdb[lsa_type], key);
        if(search) {
            lsa = *search;
        } else {
            /* NEW LSA */
            lsa = ospf_lsa_new(lsa_type, key, ospf_instance);
            result = hb_tree_insert(ospf_instance->lsdb[lsa_type], &lsa->key);
            assert(result.inserted);
            if(result.inserted) {
                *result.datum_ptr = lsa;
            } else {
                LOG_NOARG(OSPF, "Failed to add external OSPF LSA to LSDB\n");
                return false;
            }
        }

        if(lsa->lsa_buf_len < lsa_len) {
            if(lsa->lsa) free(lsa->lsa);
            lsa->lsa = malloc(lsa_len);
            lsa->lsa_buf_len = lsa_len;
        }
        memcpy(lsa->lsa, hdr, lsa_len);
        lsa->lsa_len = lsa_len;
        lsa->source.type = OSPF_SOURCE_EXTERNAL;
        lsa->source.router_id = 0;
        lsa->seq = be32toh(hdr->seq);
        lsa->age = be16toh(hdr->age);
        lsa->timestamp.tv_sec = now.tv_sec;
        lsa->timestamp.tv_nsec = now.tv_sec;
        lsa->expired = false;
        ospf_lsa_update_age(lsa, &now);
        ospf_lsa_flood(lsa);
        ospf_lsa_lifetime(lsa);
    }
    return true;
}