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

extern uint8_t g_pdu_buf[];

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
    ospf_instance_s *ospf_instance = NULL;
    int instance_id = 0;
    uint8_t type;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Unpack further arguments */
    OSPF_CTRL_ARG_INSTANCE(arguments, fd, instance_id, ospf_instance);

    database = json_array();
    for(type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
        ospf_ctrl_append_database_entries(ospf_instance->lsdb[type], database, &now);
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

int
ospf_ctrl_interfaces(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root = NULL;
    json_t *interface = NULL;
    json_t *interfaces = NULL;
    ospf_instance_s *ospf_instance = NULL;
    ospf_interface_s *ospf_interface = NULL;

    int instance_id = 0;

    /* Unpack further arguments */
    OSPF_CTRL_ARG_INSTANCE(arguments, fd, instance_id, ospf_instance);

    interfaces = json_array();
    ospf_interface = ospf_instance->interfaces;
    while(ospf_interface) {
        interface = json_pack("{ss ss ss ss ss si si s{sI sI sI sI sI sI sI sI sI sI}}", 
            "name", ospf_interface->interface->name,
            "type", ospf_interface_type_string(ospf_interface->type),
            "state", ospf_interface_state_string(ospf_interface->state),
            "dr", format_ipv4_address(&ospf_interface->dr),
            "bdr", format_ipv4_address(&ospf_interface->bdr),
            "neighbors", ospf_interface->neighbors_count,
            "neighbors-full", ospf_interface->neighbors_full,
            "stats", 
            "hello-rx",  ospf_interface->stats.hello_rx,
            "hello-tx", ospf_interface->stats.hello_tx,
            "dbd-rx", ospf_interface->stats.db_des_rx,
            "dbd-tx", ospf_interface->stats.db_des_tx,
            "ls-req-rx", ospf_interface->stats.ls_req_rx,
            "ls-req-tx", ospf_interface->stats.ls_req_tx,
            "ls-update-rx", ospf_interface->stats.ls_upd_rx,
            "ls-update-tx", ospf_interface->stats.ls_upd_tx,
            "ls-ack-rx", ospf_interface->stats.ls_ack_rx,
            "ls-ack-tx", ospf_interface->stats.ls_ack_tx);
        if(interface) {
            json_array_append(interfaces, interface);
        }
        ospf_interface = ospf_interface->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "ospf-interfaces", interfaces);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(interfaces);
    }
    return result;
}

int
ospf_ctrl_neighbors(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root = NULL;
    json_t *neighbor = NULL;
    json_t *neighbors = NULL;
    ospf_instance_s *ospf_instance = NULL;
    ospf_interface_s *ospf_interface = NULL;
    ospf_neighbor_s *ospf_neighbor = NULL;

    uint8_t type;
    uint32_t retries, requests;

    int instance_id = 0;

    /* Unpack further arguments */
    OSPF_CTRL_ARG_INSTANCE(arguments, fd, instance_id, ospf_instance);

    neighbors = json_array();
    ospf_interface = ospf_instance->interfaces;
    while(ospf_interface) {
        ospf_neighbor = ospf_interface->neighbors;
        while(ospf_neighbor) {
            retries = 0; requests = 0;
            for(type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
                retries += hb_tree_count(ospf_neighbor->lsa_retry_tree[type]);
                requests += hb_tree_count(ospf_neighbor->lsa_request_tree[type]);
            }
            neighbor = json_pack("{ss ss ss si si}", 
                "interface", ospf_interface->interface->name,
                "router-id", format_ipv4_address(&ospf_neighbor->router_id),
                "state", ospf_neighbor_state_string(ospf_neighbor->state),
                "retry-tree-entries", retries,
                "request-tree-entries", requests);
            if(neighbor) {
                json_array_append(neighbors, neighbor);
            }
            ospf_neighbor = ospf_neighbor->next;
        }
        ospf_interface = ospf_interface->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "ospf-neighbors", neighbors);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(neighbors);
    }
    return result;
}

int
ospf_ctrl_load_mrt(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    char *file_path;

    ospf_instance_s *ospf_instance = NULL;
    int instance_id = 0;

    /* Unpack further arguments */
    OSPF_CTRL_ARG_INSTANCE(arguments, fd, instance_id, ospf_instance);

    if(json_unpack(arguments, "{s:s}", "file", &file_path) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing MRT file");
    }
    if(!ospf_mrt_load(ospf_instance, file_path)) {
        return bbl_ctrl_status(fd, "error", 500, "failed to load OSPF MRT file");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
ospf_ctrl_lsa_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    json_t *value;
    size_t lsa_count;

    const char *lsa_string;
    uint16_t lsa_string_len;

    uint16_t len;

    ospf_instance_s *ospf_instance = NULL;
    int instance_id = 0;

    /* Unpack further arguments */
    OSPF_CTRL_ARG_INSTANCE(arguments, fd, instance_id, ospf_instance);

    /* Process LSA array */
    value = json_object_get(arguments, "lsa");
    if(json_is_array(value)) {
        lsa_count = json_array_size(value);
        for(size_t i = 0; i < lsa_count; i++) {
            lsa_string = json_string_value(json_array_get(value, i));
            if(!lsa_string) {
                return bbl_ctrl_status(fd, "error", 500, "failed to read OSPF LSA");
            }
            lsa_string_len = strlen(lsa_string);
            /* Load LSA from hexstring */
            for (len = 0; len < (lsa_string_len/2); len++) {
                sscanf(lsa_string + len*2, "%02hhx", &g_pdu_buf[len]);
            }
            if(!ospf_lsa_load_external(ospf_instance, 1, (uint8_t*)g_pdu_buf, len)) {
                return bbl_ctrl_status(fd, "error", 500, "failed to load OSPF LSA");
            }
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing OSPF LSA list");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
ospf_ctrl_pdu_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    json_t *value;
    size_t lsa_count;

    ospf_pdu_s pdu = {0};
    const char *lsa_string;
    uint16_t lsa_string_len;

    uint16_t len;

    ospf_instance_s *ospf_instance = NULL;
    int instance_id = 0;

    /* Unpack further arguments */
    OSPF_CTRL_ARG_INSTANCE(arguments, fd, instance_id, ospf_instance);

    /* Process LSA array */
    value = json_object_get(arguments, "pdu");
    if(json_is_array(value)) {
        lsa_count = json_array_size(value);
        for (size_t i = 0; i < lsa_count; i++) {
            lsa_string = json_string_value(json_array_get(value, i));
            if(!lsa_string) {
                return bbl_ctrl_status(fd, "error", 500, "failed to read OSPF PDU");
            }
            lsa_string_len = strlen(lsa_string);
            /* Load LSA from hexstring */
            for (len = 0; len < (lsa_string_len/2); len++) {
                sscanf(lsa_string + len*2, "%02hhx", &g_pdu_buf[len]);
            }

            if(ospf_pdu_load(&pdu, g_pdu_buf, len) != PROTOCOL_SUCCESS) {
                return bbl_ctrl_status(fd, "error", 500, "failed to load OSPF PDU");
            }
            if(pdu.pdu_type != OSPF_PDU_LS_UPDATE) {
                return bbl_ctrl_status(fd, "error", 500, "failed to load OSPF PDU (wrong PDU type)");
            }
            if(pdu.pdu_version != ospf_instance->config->version) {
                return bbl_ctrl_status(fd, "error", 500, "failed to load OSPF PDU (wrong version)");
            }
            if(pdu.pdu_version == OSPF_VERSION_2) {
                if(pdu.pdu_len < OSPFV2_LS_UPDATE_LEN_MIN) {
                    return bbl_ctrl_status(fd, "error", 500, "failed to load OSPF PDU (wrong PDU len)");
                }
                lsa_count = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(&pdu, OSPFV2_OFFSET_LS_UPDATE_COUNT));
                OSPF_PDU_CURSOR_SET(&pdu, OSPFV2_OFFSET_LS_UPDATE_LSA);
            } else {
                if(pdu.pdu_len < OSPFV3_LS_UPDATE_LEN_MIN) {
                    return bbl_ctrl_status(fd, "error", 500, "failed to load OSPF PDU (wrong PDU len)");
                }
                lsa_count = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(&pdu, OSPFV3_OFFSET_LS_UPDATE_COUNT));
                OSPF_PDU_CURSOR_SET(&pdu, OSPFV3_OFFSET_LS_UPDATE_LSA);
            }
            if(!ospf_lsa_load_external(ospf_instance, lsa_count, OSPF_PDU_CURSOR(&pdu), OSPF_PDU_CURSOR_LEN(&pdu))) {
                return bbl_ctrl_status(fd, "error", 500, "failed to load OSPF PDU (LSA load error)");
            }
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing OSPF PDU list");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
ospf_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused))) 
{
    ospf_teardown();
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}