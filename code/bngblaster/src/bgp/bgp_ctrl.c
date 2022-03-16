/*
 * BNG Blaster (BBL) - BGP CTRL (Control Commands)
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

json_t *
bgp_ctrl_session(bgp_session_t *session) {
    json_t *root = NULL;
    json_t *stats = NULL;

    if(!session) {
        return NULL;
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

    root = json_pack("{ss ss ss si si ss ss si si ss so}",
                     "interface", session->interface->name,
                     "local-address", format_ipv4_address(&session->ipv4_local_address),
                     "local-id", format_ipv4_address(&session->config->id),
                     "local-as", session->config->local_as,
                     "local-holdtime", session->config->holdtime,
                     "peer-address", format_ipv4_address(&session->ipv4_peer_address),
                     "peer-id", format_ipv4_address(&session->peer.id),
                     "peer-as", session->peer.as,
                     "peer-holdtime", session->peer.holdtime,
                     "state", bgp_session_state_string(session->state),
                     "stats", stats);

    if(!root) {
        if(stats) json_decref(stats);
    }
    return root;
}