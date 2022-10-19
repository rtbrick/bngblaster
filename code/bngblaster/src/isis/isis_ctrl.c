/*
 * BNG Blaster (BBL) - IS-IS CTRL (Control Commands)
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"
#include "../bbl_ctrl.h"

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
                     "holding-timer", adjacency->peer->holding_time);

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
                     "holding-timer", adjacency->peer->holding_time);

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
        timespec_sub(&ago, &now, &lsp->timestamp);
        if(ago.tv_sec < lsp->lifetime) {
            remaining_lifetime = lsp->lifetime - ago.tv_sec;
        } else {
            remaining_lifetime = 0;
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
    if(json_unpack(arguments, "{s:i}", "instance", &instance_id) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing ISIS instance");
    }
    if(json_unpack(arguments, "{s:i}", "level", &level) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing ISIS level");
    }
    if(!(level == ISIS_LEVEL_1 || level == ISIS_LEVEL_2)) {
        return bbl_ctrl_status(fd, "error", 400, "invalid ISIS level");
    }

    /* Search for matching instance */
    instance = g_ctx->isis_instances;
    while(instance) {
        if(instance->config->id == instance_id) {
            break;
        }
        instance = instance->next;
    }

    if(!instance) {
        return bbl_ctrl_status(fd, "error", 400, "ISIS instance not found");
    }

    if(!instance->level[level-1].lsdb) {
        return bbl_ctrl_status(fd, "error", 400, "ISIS database not found");
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
    int instance_id = 0;

    isis_instance_s *instance = NULL;

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:s}", "file", &file_path) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing MRT file");
    }
    if(json_unpack(arguments, "{s:i}", "instance", &instance_id) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing ISIS instance");
    }

    /* Search for matching instance */
    instance = g_ctx->isis_instances;
    while(instance) {
        if(instance->config->id == instance_id) {
            break;
        }
        instance = instance->next;
    }

    if(!instance) {
        return bbl_ctrl_status(fd, "error", 404, "ISIS instance not found");
    }

    if(!isis_mrt_load(instance, file_path)) {
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

    int instance_id = 0;
    isis_instance_s *instance = NULL;

    isis_pdu_s pdu = {0};

    const char *pdu_string;
    uint16_t pdu_string_len;

    uint8_t buf[ISIS_MAX_PDU_LEN];
    uint16_t len;


    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:i}", "instance", &instance_id) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing ISIS instance");
    }

    /* Search for matching instance */
    instance = g_ctx->isis_instances;
    while(instance) {
        if(instance->config->id == instance_id) {
            break;
        }
        instance = instance->next;
    }

    if(!instance) {
        return bbl_ctrl_status(fd, "error", 404, "ISIS instance not found");
    }

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
            if(!isis_lsp_update_external(instance, &pdu)) {
                return bbl_ctrl_status(fd, "error", 500, "failed to update ISIS LSP");
            }
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing PDU list");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
isis_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused))) 
{
    isis_teardown();
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}