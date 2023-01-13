/*
 * BNG Blaster (BBL) - LDP Database
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
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
    const uint64_t a = *(const uint64_t*)id1;
    const uint64_t b = *(const uint64_t*)id2;
    return (a > b) - (a < b);
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