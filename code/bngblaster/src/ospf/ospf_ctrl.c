/*
 * BNG Blaster (BBL) - OSPF CTRL (Control Commands)
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"
#include "../bbl_ctrl.h"

#define OSPF_CTRL_ARG_INSTANCE(_arguments, _fd, _instance_id, _instance) \
    do { \
        if(json_unpack(_arguments, "{s:i}", "instance", &_instance_id) != 0) { \
            return bbl_ctrl_status(_fd, "error", 400, "missing OSPF instance"); \
        } \
        /* Search for matching instance */ \
        _instance = g_ctx->ospf_instances; \
        while(_instance) { \
            if(_instance->config->id == _instance_id) { \
                break; \
            } \
            _instance = _instance->next; \
        } \
        if(!_instance) { \
            return bbl_ctrl_status(_fd, "error", 404, "OSPF instance not found"); \
        } \
    } while(0)

static void
ospf_ctrl_append_database_entries(hb_tree *lsdb, json_t *array, struct timespec *now)
{
    json_t *entry;
    ospf_lsa_s *lsa;
    hb_itor *itor;
    bool next;

    struct timespec ago;
    uint16_t age;

    uint32_t lsa_id, lsa_router;

    if(!lsdb) return;


    itor = hb_itor_new(lsdb);
    next = hb_itor_first(itor);

    while(next) {
        lsa = *hb_itor_datum(itor);

        if(lsa->deleted) {
            /* Ignore deleted LSP. */
            next = hb_itor_next(itor);
            continue;
        }
        timespec_sub(&ago, now, &lsa->timestamp);
        age = lsa->age + ago.tv_sec;
        if(age >= OSPF_LSA_MAX_AGE) {
            age = OSPF_LSA_MAX_AGE;
        }

        lsa_id = lsa->key.id;
        lsa_router = lsa->key.router;
        entry = json_pack("{si ss ss sI si ss ss}", 
            "type", lsa->type,
            "id", format_ipv4_address(&lsa_id),
            "router", format_ipv4_address(&lsa_router),
            "seq", lsa->seq,
            "age", age,
            "source-type", ospf_source_string(lsa->source.type),
            "source-router-id", format_ipv4_address(&lsa->source.router_id));

        if(entry) {
            json_array_append(array, entry);
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);
}

int
ospf_ctrl_database(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root = NULL;
    json_t *database = NULL;
    ospf_instance_s *instance = NULL;
    int instance_id = 0;
    uint8_t type;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Unpack further arguments */
    OSPF_CTRL_ARG_INSTANCE(arguments, fd, instance_id, instance);

    database = json_array();
    for(type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
        ospf_ctrl_append_database_entries(instance->lsdb[type], database, &now);
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "ospf-database", database);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(database);
    }
    return result;
}