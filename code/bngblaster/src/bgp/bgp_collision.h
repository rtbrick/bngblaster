/*
 * BNG Blaster (BBL) - BGP Connection Collision Detection (RFC 4271 6.8)
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_COLLISION_H__
#define __BBL_BGP_COLLISION_H__

void
bgp_session_close_tcpc_with_notification(bbl_tcp_ctx_s *tcpc, uint8_t error_code, uint8_t error_subcode);

bool
bgp_session_new_connection(bgp_session_s *session, bbl_tcp_ctx_s *tcpc, bool active);

bool
bgp_session_collision_resolve(bgp_session_s *session, bool trigger_is_primary);

void
bgp_session_collision_free(bgp_session_s *session);

#endif
