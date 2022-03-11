/*
 * BNG Blaster (BBL) - BGP Main
 *
 * Christian Giese, Mach 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_H__
#define __BBL_BGP_H__

#include "../bbl.h"
#include "bgp_def.h"
#include "bgp_message.h"
#include "bgp_receive.h"
#include "bgp_mrt.h"

void
bgp_reset_write_buffer(bgp_session_t *session);

void
bgp_state_change(bgp_session_t *session, bgp_state_t new_state);

bool
bgp_send(bgp_session_t *session);

void
bgp_session_connect(bgp_session_t *session);

void
bgp_session_close(bgp_session_t *session);

void
bgp_restart_timeout(bgp_session_t *session, time_t timeout);

bool
bgp_init(bbl_ctx_s *ctx);

#endif