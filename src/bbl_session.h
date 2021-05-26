/*
 * BNG Blaster (BBL) - Sessions
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_SESSIONS_H__
#define __BBL_SESSIONS_H__

bbl_session_s *
bbl_session_get(bbl_ctx_s *ctx, uint32_t session_id);

void
bbl_session_update_state(bbl_ctx_s *ctx, bbl_session_s *session, session_state_t state);

void
bbl_session_clear(bbl_ctx_s *ctx, bbl_session_s *session);

bool
bbl_sessions_init(bbl_ctx_s *ctx);

#endif
