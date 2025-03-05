/*
 * BNG Blaster (BBL) - LDP Protocol Messages
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_MESSAGE_H__
#define __BBL_LDP_MESSAGE_H__

void
ldp_pdu_close(ldp_session_s *session);

bool
ldp_pdu_init(ldp_session_s *session);

void
ldp_push_init_message(ldp_session_s *session);

void
ldp_push_keepalive_message(ldp_session_s *session);

void
ldp_push_notification_message(ldp_session_s *session);

void
ldp_push_label_mapping_message(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label);

void
ldp_push_self_message(ldp_session_s *session);

#endif