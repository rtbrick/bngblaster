/*
 * BNG Blaster (BBL) - OSPF Helper Functions
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

const char *
ospf_source_string(uint8_t source)
{
    switch(source) {
        case OSPF_SOURCE_SELF: return "self";
        case OSPF_SOURCE_ADJACENCY: return "adjacency";
        case OSPF_SOURCE_EXTERNAL: return "external";
        default: return "INVALID";
    }
}

const char *
ospf_p2p_adjacency_state_string(uint8_t state)
{
    switch(state) {
        case OSPF_P2P_ADJACENCY_STATE_UP: return "Up";
        case OSPF_P2P_ADJACENCY_STATE_INIT: return "Init";
        case OSPF_P2P_ADJACENCY_STATE_DOWN: return "Down";
        default: return "INVALID";
    }
}

const char *
ospf_adjacency_state_string(uint8_t state)
{
    switch(state) {
        case OSPF_ADJACENCY_STATE_DOWN: return "Up";
        case OSPF_ADJACENCY_STATE_UP: return "Down";
        default: return "INVALID";
    }
}


