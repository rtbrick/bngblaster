/*
 * BNG Blaster (BBL) - IS-IS Helper Functions
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_UTILS_H__
#define __BBL_ISIS_UTILS_H__

const char *
isis_source_string(uint8_t source);

const char *
isis_level_string(uint8_t level);

const char *
isis_p2p_adjacency_state_string(uint8_t state);

const char *
isis_adjacency_state_string(uint8_t state);

const char *
isis_pdu_type_string(uint8_t type);

bool
isis_str_to_area(const char *str, isis_area_s *area);

char *
isis_area_so_str(isis_area_s *area);

bool
isis_str_to_system_id(const char *str, uint8_t *system_id);

char *
isis_system_id_to_str(uint8_t *system_id);

bool
isis_str_to_lsp_id(const char *str, uint64_t *lsp_id);

char *
isis_lsp_id_to_str(uint64_t *lsp_id);

#endif