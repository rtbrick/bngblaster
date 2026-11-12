/*
 * BNG Blaster (BBL) - BFD CTRL (Control Commands)
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bfd.h"
#include "../bbl_ctrl.h"

typedef struct bfd_ctrl_filter_ {
    uint32_t id;
    const char *interface;
    const char *state;
    bool peer_set;
    uint8_t af;
    uint8_t peer[IPV6_ADDR_LEN];
} bfd_ctrl_filter_s;

/* Parse session filter arguments, returns false
 * if invalid with error response sent. */
static bool
bfd_ctrl_filter(int fd, json_t *arguments, bfd_ctrl_filter_s *filter)
{
    json_t *value;
    const char *peer = NULL;

    memset(filter, 0x0, sizeof(bfd_ctrl_filter_s));
    value = json_object_get(arguments, "bfd-session-id");
    if(value) {
        if(!(json_is_integer(value) && json_integer_value(value) > 0 &&
             json_integer_value(value) <= UINT32_MAX)) {
            bbl_ctrl_status(fd, "error", 400, "invalid bfd-session-id");
            return false;
        }
        filter->id = json_integer_value(value);
    }
    json_unpack(arguments, "{s?s s?s s?s}",
                "network-interface", &filter->interface,
                "state", &filter->state,
                "peer-address", &peer);
    if(peer) {
        filter->peer_set = true;
        if(inet_pton(AF_INET, peer, filter->peer) == 1) {
            filter->af = AF_INET;
        } else if(inet_pton(AF_INET6, peer, filter->peer) == 1) {
            filter->af = AF_INET6;
        } else {
            bbl_ctrl_status(fd, "error", 400, "invalid peer-address");
            return false;
        }
    }
    return true;
}

static bool
bfd_ctrl_match(bfd_session_s *session, bfd_ctrl_filter_s *filter)
{
    if(session->deleted) return false;
    if(filter->id && session->id != filter->id) return false;
    if(filter->interface && (!session->interface || strcmp(filter->interface, session->interface->name) != 0)) return false;
    if(filter->state && strcasecmp(filter->state, bfd_state_string(session->state)) != 0) return false;
    if(filter->peer_set) {
        if(session->key.af != filter->af) return false;
        if(memcmp(session->key.peer, filter->peer, filter->af == AF_INET ? IPV4_ADDR_LEN : IPV6_ADDR_LEN) != 0) return false;
    }
    return true;
}

int
bfd_ctrl_sessions(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *sessions, *jobj;
    bfd_session_s *session = g_ctx->bfd.sessions;
    bfd_ctrl_filter_s filter;

    if(!bfd_ctrl_filter(fd, arguments, &filter)) {
        return 0;
    }
    sessions = json_array();
    while(session) {
        if(bfd_ctrl_match(session, &filter)) {
            jobj = bfd_session_json(session);
            if(jobj) json_array_append_new(sessions, jobj);
        }
        session = session->next;
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "bfd-sessions", sessions);
    if(root) {
        result = json_dumpfd(root, fd, BBL_JSON_REAL_PRECISION);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(sessions);
    }
    return result;
}

static int
bfd_ctrl_session_set(int fd, json_t *arguments, bool enable)
{
    bfd_session_s *session = g_ctx->bfd.sessions;
    bfd_ctrl_filter_s filter;
    bool found = false;

    if(!bfd_ctrl_filter(fd, arguments, &filter)) {
        return 0;
    }
    while(session) {
        if(bfd_ctrl_match(session, &filter)) {
            bfd_session_enable(session, enable);
            found = true;
        }
        session = session->next;
    }
    if(!found) {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bfd_ctrl_session_enable(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    return bfd_ctrl_session_set(fd, arguments, true);
}

int
bfd_ctrl_session_disable(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    return bfd_ctrl_session_set(fd, arguments, false);
}

static bool
bfd_ctrl_number(int fd, json_t *arguments, const char *key, uint32_t min, uint32_t max, uint32_t *number)
{
    char error[64];
    json_t *value = json_object_get(arguments, key);
    *number = 0;
    if(!value) return true;
    if(!(json_is_integer(value) && json_integer_value(value) >= min && json_integer_value(value) <= max)) {
        snprintf(error, sizeof(error), "invalid %s (%u - %u)", key, min, max);
        bbl_ctrl_status(fd, "error", 400, error);
        return false;
    }
    *number = json_integer_value(value);
    return true;
}

int
bfd_ctrl_session_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    bfd_session_s *session = g_ctx->bfd.sessions;
    bfd_ctrl_filter_s filter;
    bool found = false;
    uint32_t tx_interval, rx_interval, multiplier;

    if(!bfd_ctrl_filter(fd, arguments, &filter)) {
        return 0;
    }
    if(!(bfd_ctrl_number(fd, arguments, "tx-interval", 1, 60000, &tx_interval) &&
         bfd_ctrl_number(fd, arguments, "rx-interval", 1, 60000, &rx_interval) &&
         bfd_ctrl_number(fd, arguments, "multiplier", 1, 255, &multiplier))) {
        return 0;
    }
    if(!(tx_interval || rx_interval || multiplier)) {
        return bbl_ctrl_status(fd, "error", 400, "missing tx-interval, rx-interval or multiplier");
    }
    while(session) {
        if(bfd_ctrl_match(session, &filter)) {
            bfd_session_update(session, tx_interval * 1000, rx_interval * 1000, multiplier);
            found = true;
        }
        session = session->next;
    }
    if(!found) {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}
