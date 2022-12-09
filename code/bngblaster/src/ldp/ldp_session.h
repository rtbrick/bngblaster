/*
 * BNG Blaster (BBL) - LDP Session
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_SESSION_H__
#define __BBL_LDP_SESSION_H__

void
ldp_session_fsm(ldp_session_s *session, ldp_event_t event);

void
ldp_session_connect(ldp_session_s *session, time_t delay);

void
ldp_session_init(ldp_session_s *session, ldp_adjacency_s *adjacency, 
                 bbl_ipv4_s *ipv4, bbl_ldp_hello_s *ldp);

void
ldp_session_close(ldp_session_s *session);

#endif