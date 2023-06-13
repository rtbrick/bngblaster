/*
 * BNG Blaster (BBL) - IS-IS CTRL (Control Commands)
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"
#include "../bbl_ctrl.h"

isis_lsp_flap_s *g_isis_lsp_flap = NULL;


#define ISIS_CTRL_ARG_INSTANCE(_arguments, _fd, _instance_id, _instance) \
    do { \
        if(json_unpack(_arguments, "{s:i}", "instance", &_instance_id) != 0) { \
            return bbl_ctrl_status(_fd, "error", 400, "missing ISIS instance"); \
        } \
        /* Search for matching instance */ \
        _instance = g_ctx->isis_instances; \
        while(_instance) { \
            if(_instance->config->id == _instance_id) { \
                break; \
            } \
            _instance = _instance->next; \
        } \
        if(!_instance) { \
            return bbl_ctrl_status(_fd, "error", 404, "ISIS instance not found"); \
        } \
    } while(0)

#define ISIS_CTRL_ARG_LEVEL(_arguments, _fd, _level) \
    do { \
        if(json_unpack(_arguments, "{s:i}", "level", &_level) != 0) { \
            return bbl_ctrl_status(_fd, "error", 400, "missing ISIS level"); \
        } \
        if(!(_level == ISIS_LEVEL_1 || _level == ISIS_LEVEL_2)) { \
            return bbl_ctrl_status(_fd, "error", 400, "invalid ISIS level"); \
        } \
    } while(0)

static json_t *
isis_ctrl_adjacency(isis_adjacency_s *adjacency)
{
    json_t *root = NULL;
    json_t *peer = NULL;

    if(!adjacency) {
        return NULL;
    }

    peer = json_pack("{ss si}",
                     "system-id", isis_system_id_to_str(adjacency->peer->system_id),
                     "hold-timer", adjacency->peer->hold_time);

    root = json_pack("{ss ss ss si ss so}",
                "interface", adjacency->interface->name,
                "type", "LAN",
                "level", isis_level_string(adjacency->level),
                "instance-id", adjacency->instance->config->id,
                "adjacency-state", isis_adjacency_state_string(adjacency->state),
                "peer", peer);

    if(!root) {
        if(peer) json_decref(peer);
    }

    return root;
}

static json_t *
isis_ctrl_adjacency_p2p(isis_adjacency_p2p_s *adjacency)
{
    json_t *root = NULL;
    json_t *peer = NULL;

    if(!adjacency) {
        return NULL;
    }

    peer = json_pack("{ss si}",
                     "system-id", isis_system_id_to_str(adjacency->peer->system_id),
                     "hold-timer", adjacency->peer->hold_time);

    root = json_pack("{ss ss, ss si ss so}",
                     "interface", adjacency->interface->name,
                     "type", "P2P",
                     "level", isis_level_string(adjacency->level),
                     "instance-id", adjacency->instance->config->id,
                     "adjacency-state", isis_p2p_adjacency_state_string(adjacency->state),
                     "peer", peer);

    if(!root) {
        if(peer) json_decref(peer);
    }
    return root;
}

int
isis_ctrl_adjacencies(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    int level;
    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;
    json_t *root, *adjacencies, *adjacency;

    adjacencies = json_array();
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        while(network_interface) {
            if(network_interface->isis_adjacency_p2p) {
                adjacency = isis_ctrl_adjacency_p2p(network_interface->isis_adjacency_p2p);
                if(adjacency) {
                    json_array_append(adjacencies, adjacency);
                }
            } else {
                for(level=0; level<ISIS_LEVELS; level++) {
                    adjacency = isis_ctrl_adjacency(network_interface->isis_adjacency[level]);
                    if(adjacency) {
                        json_array_append(adjacencies, adjacency);
                    }
                }
            }
            network_interface = network_interface->next;
        }
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "isis-adjacencies", adjacencies);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(adjacencies);
    }
    return result;
}

static json_t *
isis_ctrl_database_entries(hb_tree *lsdb)
{
    json_t *database, *entry;
    isis_lsp_s *lsp;
    hb_itor *itor;
    bool next;

    struct timespec now;
    struct timespec ago;
    uint16_t remaining_lifetime;

    char *source_system_id;

    if(!lsdb) {
        return NULL;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);

    itor = hb_itor_new(lsdb);
    next = hb_itor_first(itor);

    database = json_array();
    while(next) {
        lsp = *hb_itor_datum(itor);

        if(lsp->deleted) {
            /* Ignore deleted LSP. */
            next = hb_itor_next(itor);
            continue;
        }

        timespec_sub(&ago, &now, &lsp->timestamp);
        if(lsp->expired || ago.tv_sec >= lsp->lifetime) {
            remaining_lifetime = 0;
        } else {
            remaining_lifetime = lsp->lifetime - ago.tv_sec;
        }

        if(lsp->source.adjacency) {
            source_system_id = isis_system_id_to_str(lsp->source.adjacency->peer->system_id);
        } else {
            source_system_id = NULL;
        }
        
        entry = json_pack("{ss si si si ss ss*}", 
            "id", isis_lsp_id_to_str(&lsp->id),
            "seq", lsp->seq,
            "lifetime", lsp->lifetime,
            "lifetime-remaining", remaining_lifetime,
            "source-type", isis_source_string(lsp->source.type),
            "source-system-id", source_system_id);

        if(entry) {
            json_array_append(database, entry);
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);

    return database;
}

int
isis_ctrl_database(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root = NULL;
    json_t *database = NULL;
    isis_instance_s *instance = NULL;
    int instance_id = 0;
    int level = 0;

    /* Unpack further arguments */
    ISIS_CTRL_ARG_INSTANCE(arguments, fd, instance_id, instance);
    ISIS_CTRL_ARG_LEVEL(arguments, fd, level);

    if(!instance->level[level-1].lsdb) {
        return bbl_ctrl_status(fd, "error", 404, "ISIS database not found");
    }

    database = isis_ctrl_database_entries(instance->level[level-1].lsdb);
    if(database) {
        root = json_pack("{ss si so}",
                         "status", "ok",
                         "code", 200,
                         "isis-database", database);
        if(root) {
            result = json_dumpfd(root, fd, 0);
            json_decref(root);
        } else {
            result = bbl_ctrl_status(fd, "error", 500, "internal error");
            json_decref(database);
        }
        return result;
    } else {
        return bbl_ctrl_status(fd, "error", 500, "internal error");
    }
}

int
isis_ctrl_load_mrt(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    char *file_path;
    isis_instance_s *instance = NULL;
    int instance_id = 0;

    /* Unpack further arguments */
    ISIS_CTRL_ARG_INSTANCE(arguments, fd, instance_id, instance);

    if(json_unpack(arguments, "{s:s}", "file", &file_path) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing MRT file");
    }
    if(!isis_mrt_load(instance, file_path, false)) {
        return bbl_ctrl_status(fd, "error", 500, "failed to load ISIS MRT file");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
isis_ctrl_lsp_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    protocol_error_t result;

    json_t *value;
    size_t pdu_count;


    isis_pdu_s pdu = {0};
    const char *pdu_string;
    uint16_t pdu_string_len;

    uint8_t buf[ISIS_MAX_PDU_LEN];
    uint16_t len;

    isis_instance_s *instance = NULL;
    int instance_id = 0;

    /* Unpack further arguments */
    ISIS_CTRL_ARG_INSTANCE(arguments, fd, instance_id, instance);

    /* Process PDU array */
    value = json_object_get(arguments, "pdu");
    if(json_is_array(value)) {
        pdu_count = json_array_size(value);
        for (size_t i = 0; i < pdu_count; i++) {
            pdu_string = json_string_value(json_array_get(value, i));
            if(!pdu_string) {
                return bbl_ctrl_status(fd, "error", 500, "failed to read ISIS PDU");
            }
            pdu_string_len = strlen(pdu_string);
            /* Load PDU from hexstring */
            for (len = 0; len < (pdu_string_len/2); len++) {
                sscanf(pdu_string + len*2, "%02hhx", &buf[len]);
            }
            result = isis_pdu_load(&pdu, (uint8_t*)buf, len);
            if(result != PROTOCOL_SUCCESS) {
                return bbl_ctrl_status(fd, "error", 500, "failed to decode ISIS PDU");
            }
            /* Update external LSP */
            if(!isis_lsp_update_external(instance, &pdu, false)) {
                return bbl_ctrl_status(fd, "error", 500, "failed to update ISIS LSP");
            }
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing PDU list");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
isis_ctrl_lsp_purge(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    json_t *value;

    isis_lsp_s *lsp = NULL;
    uint64_t lsp_id;

    hb_tree *lsdb;
    void **search = NULL;

    isis_instance_s *instance = NULL;
    int instance_id = 0;
    int level = 0;

    /* Unpack further arguments */
    ISIS_CTRL_ARG_INSTANCE(arguments, fd, instance_id, instance);
    ISIS_CTRL_ARG_LEVEL(arguments, fd, level);

    if(!instance->level[level-1].lsdb) {
        return bbl_ctrl_status(fd, "error", 404, "ISIS database not found");
    }

    value = json_object_get(arguments, "id");
    if(json_is_string(value)) {
        if(!isis_str_to_lsp_id(json_string_value(value), &lsp_id)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid ISIS LSP identifier");
        }
        lsdb = instance->level[level-1].lsdb;
        search = hb_tree_search(lsdb, &lsp_id);
        if(search) {
            lsp = *search;
            if(lsp && lsp->source.type == ISIS_SOURCE_EXTERNAL) {
                isis_lsp_purge(lsp);
            } else {
                return bbl_ctrl_status(fd, "error", 500, "failed to purge ISIS LSP");
            }
        } else {
            return bbl_ctrl_status(fd, "error", 404, "ISIS LSP not found");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing ISIS LSP identifier");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

void
isis_ctrl_lsp_flap_job(timer_s *timer)
{
    isis_lsp_flap_s *flap = timer->data;
    uint32_t seq;

    if(flap) {
        seq = be32toh(*(uint32_t*)PDU_OFFSET(&flap->pdu, ISIS_OFFSET_LSP_SEQ));
        *(uint32_t*)PDU_OFFSET(&flap->pdu, ISIS_OFFSET_LSP_SEQ) = htobe32(++seq);

        if(!isis_lsp_update_external(flap->instance, &flap->pdu, true)) {
            LOG(ISIS, "Failed to flap ISIS LSP %s\n", isis_lsp_id_to_str(&flap->id));
        }
        flap->free = true;
    }
}

static isis_lsp_flap_s *
isis_ctrl_lsp_flap_new(isis_lsp_s *lsp)
{
    isis_lsp_flap_s *flap = g_isis_lsp_flap;

    while(flap) {
        if(flap->free) {
            break;
        }
        flap = flap->next;
    }
    if(!flap) {
        flap = calloc(1, sizeof(isis_lsp_flap_s));
        flap->next = g_isis_lsp_flap;
        g_isis_lsp_flap = flap;
    }

    flap->free = false;
    flap->timer = NULL;
    flap->id = lsp->id;
    flap->instance = lsp->instance;
    memcpy(&flap->pdu, &lsp->pdu, sizeof(isis_pdu_s));

    return flap;
}

int
isis_ctrl_lsp_flap(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    json_t *value;

    isis_lsp_s *lsp = NULL;
    uint64_t lsp_id;

    time_t timer = 30;
    hb_tree *lsdb;
    void **search = NULL;

    isis_lsp_flap_s *flap;

    isis_instance_s *instance = NULL;
    int instance_id = 0;
    int level = 0;

    /* Unpack further arguments */
    ISIS_CTRL_ARG_INSTANCE(arguments, fd, instance_id, instance);
    ISIS_CTRL_ARG_LEVEL(arguments, fd, level);

    if(!instance->level[level-1].lsdb) {
        return bbl_ctrl_status(fd, "error", 404, "ISIS database not found");
    }

    value = json_object_get(arguments, "timer");
    if(json_is_number(value)) {
        timer = json_number_value(value);
    }

    value = json_object_get(arguments, "id");
    if(json_is_string(value)) {
        if(!isis_str_to_lsp_id(json_string_value(value), &lsp_id)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid ISIS LSP identifier");
        }
        lsdb = instance->level[level-1].lsdb;
        search = hb_tree_search(lsdb, &lsp_id);
        if(search) {
            lsp = *search;
            if(lsp && lsp->source.type == ISIS_SOURCE_EXTERNAL) {
                LOG(ISIS, "ISIS FLAP %s-LSP %s in %lus\n", 
                    isis_level_string(lsp->level), 
                    isis_lsp_id_to_str(&lsp->id),
                    timer);

                flap = isis_ctrl_lsp_flap_new(lsp);
                timer_add(&g_ctx->timer_root, &flap->timer, "ISIS FLAP", timer, 0, flap, &isis_ctrl_lsp_flap_job);
                isis_lsp_purge(lsp);
            } else {
                return bbl_ctrl_status(fd, "error", 500, "failed to flap ISIS LSP");
            }
        } else {
            return bbl_ctrl_status(fd, "error", 404, "ISIS LSP not found");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing ISIS LSP identifier");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
isis_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused))) 
{
    isis_teardown();
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}