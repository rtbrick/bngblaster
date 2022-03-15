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

    if(!session) {
        return NULL;
    }

    root = json_pack("{ss ss ss si si ss ss si si ss }",
                     "interface", session->interface->name,
                     "local-address", format_ipv4_address(&session->ipv4_local_address),
                     "local-id", format_ipv4_address(&session->config->id),
                     "local-as", session->config->local_as,
                     "local-holdtime", session->config->holdtime,
                     "peer-address", format_ipv4_address(&session->ipv4_peer_address),
                     "peer-id", format_ipv4_address(&session->peer.id),
                     "peer-as", session->peer.as,
                     "peer-holdtime", session->peer.holdtime,
                     "state", bgp_session_state_string(session->state));

    return root;
}