/*
 * BNG Blaster (BBL) - LDP Protocol Messages
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_MESSAGE_H__
#define __BBL_LDP_MESSAGE_H__

void
ldp_push_init_message(ldp_session_s *session, bool keepalive);

void
ldp_push_keepalive_message(ldp_session_s *session);

void
ldp_push_notification_message(ldp_session_s *session);

#endif