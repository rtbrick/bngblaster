/*
 * BNG Blaster (BBL) - BGP Session Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_SESSION_H__
#define __BBL_BGP_SESSION_H__

const char *
bgp_session_state_string(bgp_state_t state);

void
bgp_session_reset_read_buffer(bgp_session_s *session);

void
bgp_session_reset_write_buffer(bgp_session_s *session);

bgp_session_s *
bgp_session_find_ipv4(ipv4addr_t local_address, ipv4addr_t peer_address);

bgp_session_s *
bgp_session_find_ipv6(ipv6addr_t *local_address, ipv6addr_t *peer_address);

void
bgp_session_update_job(timer_s *timer);

void
bgp_session_state_change(bgp_session_s *session, bgp_state_t new_state);

void
bgp_session_connect(bgp_session_s *session, time_t delay);

void
bgp_session_listen(bgp_session_s *session);

void
bgp_session_listen_teardown(void);

void
bgp_session_close(bgp_session_s *session);

void
bgp_restart_hold_timer(bgp_session_s *session, time_t timeout);

void
bgp_error_cb(void *arg, err_t err);

#endif