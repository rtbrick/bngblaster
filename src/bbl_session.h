/*
 * BNG Blaster (BBL) - Sessions
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_SESSIONS_H__
#define __BBL_SESSIONS_H__

const char *
session_state_string(uint32_t state);

bbl_session_s *
bbl_session_get(bbl_ctx_s *ctx, uint32_t session_id);

void
bbl_session_update_state(bbl_ctx_s *ctx, bbl_session_s *session, session_state_t state);

void
bbl_session_clear(bbl_ctx_s *ctx, bbl_session_s *session);

bool
bbl_sessions_init(bbl_ctx_s *ctx);

#endif
