/*
 * BNG Blaster (BBL) - BGP CTRL (Control Commands)
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"
#include "../bbl_ctrl.h"

static const char *
raw_update_state(bgp_session_s *session) 
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

static json_t *
bgp_ctrl_session_json(bgp_session_s *session)
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
                      "messages-rx", session->stats.message_rx,
                      "messages-tx", session->stats.message_tx,
                      "keepalive-rx", session->stats.keepalive_rx,
                      "keepalive-tx", session->stats.keepalive_tx,
                      "update-rx", session->stats.update_rx,
                      "update-tx", session->stats.update_tx);

    if(!stats) {
        return NULL;
    }

    root = json_pack("{ss ss ss si si ss ss si si ss ss* ss* so*}",
                     "interface", session->interface->name,
                     "local-address", format_ipv4_address(&session->ipv4_local_address),
                     "local-id", format_ipv4_address(&session->config->id),
                     "local-as", session->config->local_as,
                     "local-hold-time", session->config->hold_time,
                     "peer-address", format_ipv4_address(&session->ipv4_peer_address),
                     "peer-id", format_ipv4_address(&session->peer.id),
                     "peer-as", session->peer.as,
                     "peer-hold-time", session->peer.hold_time,
                     "state", bgp_session_state_string(session->state),
                     "raw-update-state", raw_update_state(session),
                     "raw-update-file", raw_update_file,
                     "stats", stats);

    if(!root) {
        if(stats) json_decref(stats);
    }
    return root;
}

int
bgp_ctrl_sessions(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *sessions, *session;

    bgp_session_s *bgp_session = g_ctx->bgp_sessions;

    const char *s;
    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;

    /* Unpack further arguments */
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
    while(bgp_session) {
        if(ipv4_local_address && bgp_session->ipv4_local_address != ipv4_local_address) {
            bgp_session = bgp_session->next;
            continue;
        }
        if(ipv4_peer_address && bgp_session->ipv4_peer_address != ipv4_peer_address) {
            bgp_session = bgp_session->next;
            continue;
        }

        session = bgp_ctrl_session_json(bgp_session);
        if(session) {
            json_array_append(sessions, session);
        }
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "bgp-sessions", sessions);
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
bgp_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    bgp_teardown();
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bgp_ctrl_raw_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root;

    bgp_session_s *bgp_session = g_ctx->bgp_sessions;
    bgp_raw_update_s *raw_update;

    const char *s;
    const char *file_path;

    uint16_t started = 0;
    uint16_t skipped = 0;
    uint16_t filtered = 0;

    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:s}", "file", &file_path) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing argument file");
    }
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
    raw_update = bgp_raw_update_load(file_path, true);
    if(!raw_update) {
        return bbl_ctrl_status(fd, "error", 400, "failed to load file");
    }

    while(bgp_session) {
        if(ipv4_local_address && bgp_session->ipv4_local_address != ipv4_local_address) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(ipv4_peer_address && bgp_session->ipv4_peer_address != ipv4_peer_address) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(bgp_session->raw_update_sending) {
            bgp_session = bgp_session->next;
            skipped++;
            continue;
        }

        bgp_session->raw_update = raw_update;
        timer_add(&g_ctx->timer_root, &bgp_session->update_timer, 
                 "BGP UPDATE", 0, 0, bgp_session,
                 &bgp_session_update_job);
        
        started++;
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si s{si si si}}",
                     "status", "ok",
                     "code", 200,
                     "bgp-raw-update",
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
bgp_ctrl_raw_update_list(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    bgp_raw_update_s *raw_update = g_ctx->bgp_raw_updates;
    json_t *root, *updates, *update;

    updates = json_array();

    while(raw_update){
        update = json_pack("{ss* si si}",
                           "file", raw_update->file,
                           "len", raw_update->len,
                           "updates", raw_update->updates);
        if(update) {
            json_array_append(updates, update);
        }
        raw_update = raw_update->next;
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "bgp-raw-update-list", updates);
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
bgp_ctrl_disconnect(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root;

    bgp_session_s *bgp_session = g_ctx->bgp_sessions;

    const char *s;

    uint16_t disconnected = 0;
    uint16_t skipped = 0;
    uint16_t filtered = 0;

    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;

    /* Unpack further arguments */
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

    while(bgp_session) {
        if(ipv4_local_address && bgp_session->ipv4_local_address != ipv4_local_address) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(ipv4_peer_address && bgp_session->ipv4_peer_address != ipv4_peer_address) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(bgp_session->state == BGP_CLOSED || bgp_session->state == BGP_CLOSING) {
            bgp_session = bgp_session->next;
            skipped++;
            continue;
        }
        if(!bgp_session->error_code) {
            bgp_session->error_code = 6; /* Cease */
            bgp_session->error_subcode = 2; /* Shutdown */
        }
        bgp_session_close(bgp_session);
        disconnected++;
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si s{si si si}}",
                     "status", "ok",
                     "code", 200,
                     "bgp-disconnect",
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