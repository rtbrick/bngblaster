/*
 * BNG Blaster (BBL) - OSPF Helper Functions
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_UTILS_H__
#define __BBL_OSPF_UTILS_H__

const char *
ospf_source_string(uint8_t source);

const char *
ospf_p2p_adjacency_state_string(uint8_t state);

const char *
ospf_adjacency_state_string(uint8_t state);

const char *
ospf_pdu_type_string(uint8_t type);

#endif