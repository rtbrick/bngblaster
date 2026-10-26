/*
 * BNG Blaster (BBL) - LDP Database
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
    const uint32_t a = *(const uint32_t*)id1;
    const uint32_t b = *(const uint32_t*)id2;
    return (a > b) - (a < b);
}

int
ldb_db_ipv6_compare(void *id1, void *id2)
{
    return memcmp(id1, id2, sizeof(ipv6addr_t));
}

bool
ldb_db_init(ldp_instance_s *instance)
{
    instance->db.ipv4 = hb_tree_new((dict_compare_func)ldb_db_ipv4_compare);
    instance->db.ipv6 = hb_tree_new((dict_compare_func)ldb_db_ipv6_compare);
    return true;
}

bool
ldb_db_add_ipv4(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label)
{
    void **search = NULL;
    ldp_instance_s *instance = session->instance;
    ldp_db_entry_s *entry;
    dict_insert_result result;

    search = hb_tree_search(instance->db.ipv4, &prefix->address);
    if(search) {
        entry = *search;
        entry->version++;
    } else {
        entry = calloc(1, sizeof(ldp_db_entry_s));
        entry->afi = IANA_AFI_IPV4;
        entry->prefix.ipv4.address = prefix->address;
        result = hb_tree_insert(instance->db.ipv4, &entry->prefix.ipv4.address);
        if(result.inserted) {
            *result.datum_ptr = entry;
        } else {
            LOG(ERROR, "LDP (%s - %s) failed to add IPv4 entry to database\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
            return false;
        }
    }
    entry->active = true;
    entry->prefix.ipv4.len = prefix->len;
    entry->label = label;
    entry->source = session;
    return true;
}

ldp_db_entry_s *
ldb_db_lookup_ipv4(ldp_instance_s *instance, uint32_t address)
{
    void **search = NULL;
    ldp_db_entry_s *entry;

    search = hb_tree_search(instance->db.ipv4, &address);
    if(search) {
        entry = *search;
        return entry;
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

    search = hb_tree_search(instance->db.ipv6, &prefix->address);
    if(search) {
        entry = *search;
        entry->version++;
    } else {
        entry = calloc(1, sizeof(ldp_db_entry_s));
        entry->afi = IANA_AFI_IPV6;
        memcpy(&entry->prefix.ipv6, prefix, sizeof(ipv6_prefix));
        result = hb_tree_insert(instance->db.ipv6, &entry->prefix.ipv6.address);
        if(result.inserted) {
            *result.datum_ptr = entry;
        } else {
            free(entry);
            LOG(ERROR, "LDP (%s - %s) failed to add IPv6 entry to database\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
            return false;
        }
    }
    entry->active = true;
    entry->prefix.ipv6.len = prefix->len;
    entry->label = label;
    entry->source = session;
    return true;

}

ldp_db_entry_s *
ldb_db_lookup_ipv6(ldp_instance_s *instance, ipv6addr_t *address)
{
    void **search = NULL;
    ldp_db_entry_s *entry;

    search = hb_tree_search(instance->db.ipv6, address);
    if(search) {
        entry = *search;
        return entry;
    }
    return NULL;
}

/* Deactivate an entry learned from the session, with any label
 * or only with the given label (label withdraw with label TLV). */
static void
ldb_db_deactivate(ldp_session_s *session, ldp_db_entry_s *entry, uint32_t label, bool any_label)
{
    if(entry->active && entry->source == session && (any_label || entry->label == label)) {
        entry->active = false;
        entry->version++;
    }
}

void
ldb_db_withdraw_ipv4(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label, bool any_label)
{
    ldp_db_entry_s *entry = ldb_db_lookup_ipv4(session->instance, prefix->address);
    if(entry) {
        ldb_db_deactivate(session, entry, label, any_label);
    }
}

void
ldb_db_withdraw_ipv6(ldp_session_s *session, ipv6_prefix *prefix, uint32_t label, bool any_label)
{
    ldp_db_entry_s *entry = ldb_db_lookup_ipv6(session->instance, &prefix->address);
    if(entry) {
        ldb_db_deactivate(session, entry, label, any_label);
    }
}

/**
 * ldb_db_withdraw_session
 *
 * Deactivate all entries learned from the session (e.g. session down
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

    for(i = 0; i < sizeof(trees)/sizeof(trees[0]); i++) {
        if(!trees[i]) continue;
        itor = hb_itor_new(trees[i]);
        next = hb_itor_first(itor);
        while(next) {
            ldb_db_deactivate(session, *hb_itor_datum(itor), label, any_label);
            next = hb_itor_next(itor);
        }
        hb_itor_free(itor);
    }
}
