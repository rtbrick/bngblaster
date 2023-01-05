/*
 * BNG Blaster (BBL) - LDP CTRL (Control Commands)
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"
#include "../bbl_ctrl.h"

static const char *
raw_update_state(ldp_session_s *session) 
{
    if(session->raw_update) {
        if(session->update_start_timestamp.tv_sec) {
            if(session->raw_update_sending) {
                return "sending";
            }
            if(session->update_stop_timestamp.tv_sec) {
                return "done";
            }
        } else {
            return "wait";
        }
    }
    return NULL;
}

int
ldp_ctrl_adjacencies(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *adjacencies, *adjacency;

    ldp_instance_s *ldp_instance = g_ctx->ldp_instances;
    ldp_adjacency_s *ldp_adjacency;

    int ldp_instance_id = 0;

    /* Unpack further arguments */
    json_unpack(arguments, "{s:i}", "ldp-instance-id", &ldp_instance_id);

    adjacencies = json_array();
    while(ldp_instance) {
        if(ldp_instance_id > 0 && ldp_instance_id != ldp_instance->config->id) {
            ldp_instance = ldp_instance->next;
            continue;
        }
        ldp_adjacency = ldp_instance->adjacencies;
        while(ldp_adjacency) {
            adjacency = json_pack("{si ss ss si si si si}",
                                  "ldp-instance-id", ldp_adjacency->instance->config->id,
                                  "interface", ldp_adjacency->interface->name,
                                  "state", ldp_adjacency->state == LDP_ADJACENCY_STATE_UP ? "up" : "down",
                                  "state-transitions", ldp_adjacency->state_transitions,
                                  "rx-discovery", ldp_adjacency->interface->stats.ldp_udp_rx,
                                  "rx-discovery-error", ldp_adjacency->interface->stats.ldp_udp_rx_error,
                                  "tx-discovery", ldp_adjacency->interface->stats.ldp_udp_tx);
            if(adjacency) {
                json_array_append(adjacencies, adjacency);
            }
            ldp_adjacency = ldp_adjacency->next;
        }
        ldp_instance = ldp_instance->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "ldp-adjacencies", adjacencies);
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
ldp_ctrl_session_json(ldp_session_s *session)
{
    json_t *root = NULL;
    json_t *stats = NULL;
    
    const char *raw_update_file = NULL;

    if(!session) {
        return NULL;
    }

    if(session->raw_update) {
        raw_update_file = session->raw_update->file;
    }

    stats = json_pack("{si si si si si si}",
                      "pdu-rx", session->stats.pdu_rx,
                      "pdu-tx", session->stats.pdu_tx,
                      "messages-rx", session->stats.message_rx,
                      "messages-tx", session->stats.message_tx,
                      "keepalive-rx", session->stats.keepalive_rx,
                      "keepalive-tx", session->stats.keepalive_tx);

    if(!stats) {
        return NULL;
    }

    root = json_pack("{si ss ss ss ss ss ss si ss* ss* so*}",
                     "ldp-instance-id", session->instance->config->id,
                     "interface", session->interface->name,
                     "local-address", format_ipv4_address(&session->local.ipv4_address),
                     "local-identifier", ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                     "peer-address", format_ipv4_address(&session->peer.ipv4_address),
                     "peer-identifier", ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
                     "state", ldp_session_state_string(session->state),
                     "state-transitions", session->state_transitions,
                     "raw-update-state", raw_update_state(session),
                     "raw-update-file", raw_update_file,
                     "stats", stats);
    if(!root) {
        if(stats) json_decref(stats);
    }
    return root;
}

int
ldp_ctrl_sessions(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *sessions, *session;

    ldp_instance_s *ldp_instance = g_ctx->ldp_instances;
    ldp_session_s *ldp_session;

    const char *s;
    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;
    int ldp_instance_id = 0;

    /* Unpack further arguments */
    json_unpack(arguments, "{s:i}", "ldp-instance-id", &ldp_instance_id);
    if(json_unpack(arguments, "{s:s}", "local-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv4-address");
        }
    }

    sessions = json_array();
    while(ldp_instance) {
        if(ldp_instance_id > 0 && ldp_instance_id != ldp_instance->config->id) {
            ldp_instance = ldp_instance->next;
            continue;
        }
        ldp_session = ldp_instance->sessions;
        while(ldp_session) {
            if(ipv4_local_address && ldp_session->local.ipv4_address != ipv4_local_address) {
                ldp_session = ldp_session->next;
                continue;
            }
            if(ipv4_peer_address && ldp_session->peer.ipv4_address != ipv4_peer_address) {
                ldp_session = ldp_session->next;
                continue;
            }
            session = ldp_ctrl_session_json(ldp_session);
            if(session) {
                json_array_append(sessions, session);
            }
            ldp_session = ldp_session->next;
        }
        ldp_instance = ldp_instance->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "ldp-sessions", sessions);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(sessions);
    }
    return result;
}

int
ldp_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    ldp_teardown();
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
ldp_ctrl_raw_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root;

    ldp_instance_s *ldp_instance = g_ctx->ldp_instances;
    ldp_session_s *ldp_session;
    ldp_raw_update_s *raw_update;

    const char *s;
    const char *file_path;

    uint16_t started = 0;
    uint16_t skipped = 0;
    uint16_t filtered = 0;

    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;
    int ldp_instance_id = 0;

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:s}", "file", &file_path) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing argument file");
    }
    json_unpack(arguments, "{s:i}", "ldp-instance-id", &ldp_instance_id);
    if(json_unpack(arguments, "{s:s}", "local-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv4-address");
        }
    }

    /* Load file. */
    raw_update = ldp_raw_update_load(file_path, true);
    if(!raw_update) {
        return bbl_ctrl_status(fd, "error", 400, "failed to load file");
    }

    while(ldp_instance) {
        ldp_session = ldp_instance->sessions;
        while(ldp_session) {
            if(ldp_instance_id > 0 && ldp_instance_id != ldp_instance->config->id) {
                ldp_session = ldp_session->next;
                filtered++;
                continue;
            }
            if(ipv4_local_address && ldp_session->local.ipv4_address != ipv4_local_address) {
                ldp_session = ldp_session->next;
                filtered++;
                continue;
            }
            if(ipv4_peer_address && ldp_session->peer.ipv4_address != ipv4_peer_address) {
                ldp_session = ldp_session->next;
                filtered++;
                continue;
            }
            if(ldp_session->raw_update_sending) {
                ldp_session = ldp_session->next;
                skipped++;
                continue;
            }
            ldp_session->raw_update = raw_update;
            timer_add(&g_ctx->timer_root, &ldp_session->update_timer, 
                      "LDP UPDATE", 0, 0, ldp_session,
                      &ldp_session_update_job);
            
            started++;
            ldp_session = ldp_session->next;
        }
        ldp_instance = ldp_instance->next;
    }

    root = json_pack("{ss si s{si si si}}",
                     "status", "ok",
                     "code", 200,
                     "ldp-raw-update",
                     "started", started,
                     "skipped", skipped,
                     "filtered", filtered);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}

int
ldp_ctrl_raw_update_list(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    ldp_raw_update_s *raw_update = g_ctx->ldp_raw_updates;
    json_t *root, *updates, *update;

    updates = json_array();

    while(raw_update){
        update = json_pack("{ss* si si si}",
                           "file", raw_update->file,
                           "len", raw_update->len,
                           "pdu", raw_update->pdu,
                           "messages", raw_update->messages);
        if(update) {
            json_array_append(updates, update);
        }
        raw_update = raw_update->next;
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "ldp-raw-update-list", updates);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(updates);
    }
    return result;
}

int
ldp_ctrl_disconnect(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root;

    ldp_instance_s *ldp_instance = g_ctx->ldp_instances;
    ldp_session_s *ldp_session;

    const char *s;

    uint16_t disconnected = 0;
    uint16_t skipped = 0;
    uint16_t filtered = 0;

    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;
    int ldp_instance_id = 0;

    /* Unpack further arguments */
    json_unpack(arguments, "{s:i}", "ldp-instance-id", &ldp_instance_id);
    if(json_unpack(arguments, "{s:s}", "local-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv4-address");
        }
    }

    while(ldp_instance) {
        ldp_session = ldp_instance->sessions;
        while(ldp_session) {
            if(ldp_instance_id > 0 && ldp_instance_id != ldp_instance->config->id) {
                ldp_session = ldp_session->next;
                filtered++;
                continue;
            }
            if(ipv4_local_address && ldp_session->local.ipv4_address != ipv4_local_address) {
                ldp_session = ldp_session->next;
                filtered++;
                continue;
            }
            if(ipv4_peer_address && ldp_session->peer.ipv4_address != ipv4_peer_address) {
                ldp_session = ldp_session->next;
                filtered++;
                continue;
            }
            if(ldp_session->state == LDP_CLOSED || ldp_session->state == LDP_CLOSING) {
                ldp_session = ldp_session->next;
                skipped++;
                continue;
            }
            if(!ldp_session->error_code) {
                ldp_session->error_code = LDP_STATUS_SHUTDOWN|LDP_STATUS_FATAL_ERROR;
            }
            ldp_session_close(ldp_session);
            disconnected++;
            ldp_session = ldp_session->next;
        }
        ldp_instance = ldp_instance->next;
    }

    root = json_pack("{ss si s{si si si}}",
                     "status", "ok",
                     "code", 200,
                     "ldp-disconnect",
                     "disconnected", disconnected,
                     "skipped", skipped,
                     "filtered", filtered);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}

static json_t *
ldb_ctrl_database_entries(ldp_instance_s *instance)
{
    json_t *json_database, *json_entry;
    ldp_db_entry_s *entry;

    hb_tree *db;
    hb_itor *itor;
    bool next;

    json_database = json_array();

    /* Add IPv4 prefixes. */
    db = instance->db.ipv4;
    itor = hb_itor_new(db);
    next = hb_itor_first(itor);
    while(next) {
        entry = *hb_itor_datum(itor);
        json_entry = json_pack("{ss ss* si ss*}", 
            "afi", "ipv4",
            "prefix", format_ipv4_prefix(&entry->prefix.ipv4),
            "label", entry->label,
            "source-identifier", ldp_id_to_str(entry->source->peer.lsr_id, entry->source->peer.label_space_id));

        if(json_entry) {
            json_array_append(json_database, json_entry);
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);

    /* Add IPv6 prefixes. */
    db = instance->db.ipv6;
    itor = hb_itor_new(db);
    next = hb_itor_first(itor);
    while(next) {
        entry = *hb_itor_datum(itor);
        json_entry = json_pack("{ss ss* si ss*}", 
            "afi", "ipv6",
            "prefix", format_ipv6_prefix(&entry->prefix.ipv6),
            "label", entry->label,
            "source-identifier", ldp_id_to_str(entry->source->peer.lsr_id, entry->source->peer.label_space_id));

        if(json_entry) {
            json_array_append(json_database, json_entry);
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);

    return json_database;
}

int
ldb_ctrl_database(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root = NULL;
    json_t *database = NULL;
    ldp_instance_s *instance = NULL;

    int instance_id = 0;

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:i}", "ldp-instance-id", &instance_id) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "LDP instance missing");
    }

    /* Search for matching instance */
    instance = g_ctx->ldp_instances;
    while(instance) {
        if(instance->config->id == instance_id) {
            break;
        }
        instance = instance->next;
    }

    if(!instance) {
        return bbl_ctrl_status(fd, "error", 400, "LDP instance not found");
    }

    database = ldb_ctrl_database_entries(instance);
    if(database) {
        root = json_pack("{ss si so}",
                         "status", "ok",
                         "code", 200,
                         "ldp-database", database);
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