/*
 * BNG Blaster (BBL) - LDP Database
 *
 * The database of an instance holds one entry per prefix (address and
 * prefix length) with the label mappings of all sessions (liberal label
 * retention). The entry label and source are those of the selected
 * mapping, which is kept as long as the session has a mapping.
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

int
ldb_db_ipv4_compare(void *id1, void *id2)
{
    const ipv4_prefix *a = id1;
    const ipv4_prefix *b = id2;
    uint32_t addr_a = be32toh(a->address);
    uint32_t addr_b = be32toh(b->address);
    if(addr_a != addr_b) {
        return (addr_a > addr_b) - (addr_a < addr_b);
    }
    return (a->len > b->len) - (a->len < b->len);
}

int
ldb_db_ipv6_compare(void *id1, void *id2)
{
    const ipv6_prefix *a = id1;
    const ipv6_prefix *b = id2;
    int result = memcmp(a->address, b->address, sizeof(ipv6addr_t));
    if(result) {
        return result;
    }
    return (a->len > b->len) - (a->len < b->len);
}

bool
ldb_db_init(ldp_instance_s *instance)
{
    instance->db.ipv4 = hb_tree_new((dict_compare_func)ldb_db_ipv4_compare);
    instance->db.ipv6 = hb_tree_new((dict_compare_func)ldb_db_ipv6_compare);
    return true;
}

/* Traffic streams (TX threads) read the state and version without
 * lock and rebuild their packets (with lock) if the version changes,
 * so the version must be updated after all other fields. A changed
 * state also increments the instance version, which lets streams
 * search the longest active prefix again (with lock). */
static void
ldb_db_update(ldp_instance_s *instance, ldp_db_entry_s *entry)
{
    ldp_db_mapping_s *mapping = entry->mappings;
    ldp_db_mapping_s *selected = NULL;
    bool active = entry->active;

    /* Keep the current source if it still has a mapping. */
    while(mapping) {
        if(mapping->session == entry->source || !selected) {
            selected = mapping;
            if(mapping->session == entry->source) break;
        }
        mapping = mapping->next;
    }
    if(selected) {
        entry->label = selected->label;
        entry->source = selected->session;
    }
    __atomic_store_n(&entry->active, selected != NULL, __ATOMIC_RELAXED);
    __atomic_store_n(&entry->version, entry->version + 1, __ATOMIC_RELEASE);
    if(entry->active != active) {
        __atomic_store_n(&instance->db_version, instance->db_version + 1, __ATOMIC_RELEASE);
    }
}

static void
ldb_db_mapping_add(ldp_db_entry_s *entry, ldp_session_s *session, uint32_t label)
{
    ldp_db_mapping_s **ptr = &entry->mappings;
    while(*ptr) {
        if((*ptr)->session == session) {
            (*ptr)->label = label;
            ldb_db_update(session->instance, entry);
            return;
        }
        ptr = &(*ptr)->next;
    }
    *ptr = calloc(1, sizeof(ldp_db_mapping_s));
    (*ptr)->session = session;
    (*ptr)->label = label;
    ldb_db_update(session->instance, entry);
}

/* Remove the mapping of the session, with any label
 * or only with the given label (label withdraw with label TLV). */
static void
ldb_db_mapping_del(ldp_db_entry_s *entry, ldp_session_s *session, uint32_t label, bool any_label)
{
    ldp_db_mapping_s **ptr = &entry->mappings;
    ldp_db_mapping_s *mapping;
    while(*ptr) {
        mapping = *ptr;
        if(mapping->session == session) {
            if(any_label || mapping->label == label) {
                *ptr = mapping->next;
                free(mapping);
                ldb_db_update(session->instance, entry);
            }
            return;
        }
        ptr = &mapping->next;
    }
}

bool
ldb_db_add_ipv4(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label)
{
    void **search = NULL;
    ldp_instance_s *instance = session->instance;
    ldp_db_entry_s *entry;
    dict_insert_result result;
    ipv4_prefix key = {.len = prefix->len, .address = prefix->address};

    pthread_rwlock_wrlock(&g_ctx->label_db_lock);
    search = hb_tree_search(instance->db.ipv4, &key);
    if(search) {
        entry = *search;
    } else {
        entry = calloc(1, sizeof(ldp_db_entry_s));
        entry->afi = IANA_AFI_IPV4;
        entry->prefix.ipv4 = key;
        result = hb_tree_insert(instance->db.ipv4, &entry->prefix.ipv4);
        if(result.inserted) {
            *result.datum_ptr = entry;
        } else {
            pthread_rwlock_unlock(&g_ctx->label_db_lock);
            free(entry);
            LOG(ERROR, "LDP (%s - %s) failed to add IPv4 entry to database\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
            return false;
        }
    }
    ldb_db_mapping_add(entry, session, label);
    pthread_rwlock_unlock(&g_ctx->label_db_lock);
    return true;
}

/**
 * ldb_db_lookup_ipv4
 *
 * @param instance LDP instance
 * @param address IPv4 address
 * @return active entry with this address and the longest prefix length
 */
ldp_db_entry_s *
ldb_db_lookup_ipv4(ldp_instance_s *instance, uint32_t address)
{
    void **search = NULL;
    ldp_db_entry_s *entry;
    ipv4_prefix key = {.len = UINT8_MAX, .address = address};

    while((search = hb_tree_search_le(instance->db.ipv4, &key))) {
        entry = *search;
        if(entry->prefix.ipv4.address != address) {
            break;
        }
        if(entry->active) {
            return entry;
        }
        if(!entry->prefix.ipv4.len) {
            break;
        }
        key.len = entry->prefix.ipv4.len - 1;
    }
    return NULL;
}

bool
ldb_db_add_ipv6(ldp_session_s *session, ipv6_prefix *prefix, uint32_t label)
{
    void **search = NULL;
    ldp_instance_s *instance = session->instance;
    ldp_db_entry_s *entry;
    dict_insert_result result;
    ipv6_prefix key = {.len = prefix->len};

    memcpy(&key.address, &prefix->address, sizeof(ipv6addr_t));

    pthread_rwlock_wrlock(&g_ctx->label_db_lock);
    search = hb_tree_search(instance->db.ipv6, &key);
    if(search) {
        entry = *search;
    } else {
        entry = calloc(1, sizeof(ldp_db_entry_s));
        entry->afi = IANA_AFI_IPV6;
        entry->prefix.ipv6 = key;
        result = hb_tree_insert(instance->db.ipv6, &entry->prefix.ipv6);
        if(result.inserted) {
            *result.datum_ptr = entry;
        } else {
            pthread_rwlock_unlock(&g_ctx->label_db_lock);
            free(entry);
            LOG(ERROR, "LDP (%s - %s) failed to add IPv6 entry to database\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
            return false;
        }
    }
    ldb_db_mapping_add(entry, session, label);
    pthread_rwlock_unlock(&g_ctx->label_db_lock);
    return true;
}

/**
 * ldb_db_lookup_ipv6
 *
 * @param instance LDP instance
 * @param address IPv6 address
 * @return active entry with this address and the longest prefix length
 */
ldp_db_entry_s *
ldb_db_lookup_ipv6(ldp_instance_s *instance, ipv6addr_t *address)
{
    void **search = NULL;
    ldp_db_entry_s *entry;
    ipv6_prefix key = {.len = UINT8_MAX};

    memcpy(&key.address, address, sizeof(ipv6addr_t));
    while((search = hb_tree_search_le(instance->db.ipv6, &key))) {
        entry = *search;
        if(memcmp(&entry->prefix.ipv6.address, address, sizeof(ipv6addr_t)) != 0) {
            break;
        }
        if(entry->active) {
            return entry;
        }
        if(!entry->prefix.ipv6.len) {
            break;
        }
        key.len = entry->prefix.ipv6.len - 1;
    }
    return NULL;
}

/**
 * ldb_db_label
 *
 * Label of the entry for streams sent on the interface, which prefers
 * the mapping of a session on this interface (called with lock).
 *
 * @param entry LDP database entry
 * @param interface network interface or NULL
 * @return label
 */
uint32_t
ldb_db_label(ldp_db_entry_s *entry, bbl_network_interface_s *interface)
{
    ldp_db_mapping_s *mapping = entry->mappings;
    while(mapping && interface) {
        if(mapping->session->interface == interface) {
            return mapping->label;
        }
        mapping = mapping->next;
    }
    return entry->label;
}

void
ldb_db_withdraw_ipv4(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label, bool any_label)
{
    void **search = NULL;
    ipv4_prefix key = {.len = prefix->len, .address = prefix->address};

    pthread_rwlock_wrlock(&g_ctx->label_db_lock);
    search = hb_tree_search(session->instance->db.ipv4, &key);
    if(search) {
        ldb_db_mapping_del(*search, session, label, any_label);
    }
    pthread_rwlock_unlock(&g_ctx->label_db_lock);
}

void
ldb_db_withdraw_ipv6(ldp_session_s *session, ipv6_prefix *prefix, uint32_t label, bool any_label)
{
    void **search = NULL;
    ipv6_prefix key = {.len = prefix->len};

    memcpy(&key.address, &prefix->address, sizeof(ipv6addr_t));
    pthread_rwlock_wrlock(&g_ctx->label_db_lock);
    search = hb_tree_search(session->instance->db.ipv6, &key);
    if(search) {
        ldb_db_mapping_del(*search, session, label, any_label);
    }
    pthread_rwlock_unlock(&g_ctx->label_db_lock);
}

/**
 * ldb_db_withdraw_session
 *
 * Remove all mappings learned from the session (e.g. session down
 * or label withdraw with wildcard FEC). Entries are kept because traffic
 * streams hold references.
 *
 * @param session LDP session
 * @param label label (label withdraw with label TLV)
 * @param any_label withdraw entries with any label
 */
void
ldb_db_withdraw_session(ldp_session_s *session, uint32_t label, bool any_label)
{
    ldp_instance_s *instance = session->instance;
    hb_tree *trees[] = { instance->db.ipv4, instance->db.ipv6 };
    hb_itor *itor;
    bool next;
    size_t i;

    pthread_rwlock_wrlock(&g_ctx->label_db_lock);
    for(i = 0; i < sizeof(trees)/sizeof(trees[0]); i++) {
        if(!trees[i]) continue;
        itor = hb_itor_new(trees[i]);
        next = hb_itor_first(itor);
        while(next) {
            ldb_db_mapping_del(*hb_itor_datum(itor), session, label, any_label);
            next = hb_itor_next(itor);
        }
        hb_itor_free(itor);
    }
    pthread_rwlock_unlock(&g_ctx->label_db_lock);
}
