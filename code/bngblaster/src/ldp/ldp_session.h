/*
 * BNG Blaster (BBL) - LDP Session
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_SESSION_H__
#define __BBL_LDP_SESSION_H__

const char *
ldp_session_state_string(ldp_state_t state);

void
ldp_session_update_job(timer_s *timer);

void
ldp_session_restart_keepalive_timeout(ldp_session_s *session);

void
ldp_session_fsm(ldp_session_s *session, ldp_event_t event);

void
ldp_session_connect(ldp_session_s *session, time_t delay);

void
ldp_session_listen_teardown(void);

int
ldp_session_key_compare(void *key1, void *key2);

uint32_t
ldp_session_key_hash(const void *k);

ldp_session_s *
ldp_session_find_ipv4(ipv4addr_t local_address, ipv4addr_t peer_address);

ldp_session_s *
ldp_session_find_ipv6(ipv6addr_t *local_address, ipv6addr_t *peer_address);

void
ldp_session_ipv4_init(ldp_session_s *session, ldp_adjacency_s *adjacency, 
                      bbl_ipv4_s *ipv4, bbl_ldp_hello_s *ldp);

void
ldp_session_ipv6_init(ldp_session_s *session, ldp_adjacency_s *adjacency, 
                      bbl_ipv6_s *ipv6, bbl_ldp_hello_s *ldp);

void
ldp_session_close(ldp_session_s *session);

void
ldp_session_close_received(ldp_session_s *session);

void
ldp_session_closed(ldp_session_s *session);

void
ldp_session_hello(ldp_session_s *session, uint16_t hold_time);

#endif