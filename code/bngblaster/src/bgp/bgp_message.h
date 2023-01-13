/*
 * BNG Blaster (BBL) - BGP Protocol Messages
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_MESSAGE_H__
#define __BBL_BGP_MESSAGE_H__

void
bgp_push_open_message(bgp_session_s *session);

void
bgp_push_keepalive_message(bgp_session_s *session);

void
bgp_push_notification_message(bgp_session_s *session);

#endif