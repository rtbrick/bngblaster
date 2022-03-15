/*
 * BNG Blaster (BBL) - IS-IS CTRL (Control Commands)
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

json_t *
isis_ctrl_adjacency_p2p(isis_adjacency_p2p_t *adjacency) {
    json_t *root = NULL;
    json_t *peer = NULL;

    if(!adjacency) {
        return NULL;
    }

    peer = json_pack("{ss}",
                     "system-id", isis_system_id_to_str(adjacency->peer->system_id));

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

json_t *
isis_ctrl_adjacency(isis_adjacency_t *adjacency) {
    json_t *root = NULL;
    json_t *peer = NULL;

    if(!adjacency) {
        return NULL;
    }

    peer = json_pack("{ss}",
                     "system-id", isis_system_id_to_str(adjacency->peer->system_id));

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

json_t *
isis_ctrl_database(hb_tree *lsdb) {
    json_t *database, *entry;
    isis_lsp_t *lsp;
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