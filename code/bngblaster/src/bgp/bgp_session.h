/*
 * BNG Blaster (BBL) - BGP Session Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_SESSION_H__
#define __BBL_BGP_SESSION_H__

void
bgp_session_state_change(bgp_session_t *session, bgp_state_t new_state);

void
bgp_session_connect(bgp_session_t *session, time_t delay);

void
bgp_session_close(bgp_session_t *session);

void
bgp_restart_hold_timer(bgp_session_t *session, time_t timeout);

#endif