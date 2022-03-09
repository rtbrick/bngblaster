/*
 * BNG Blaster (BBL) - Session Traffic
 *
 * Christian Giese, May 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_SESSION_TRAFFIC_H__
#define __BBL_SESSION_TRAFFIC_H__

bool
bbl_session_traffic_start_ipv4(bbl_ctx_s *ctx, bbl_session_s *session);

bool
bbl_session_traffic_start_ipv6(bbl_ctx_s *ctx, bbl_session_s *session);

bool
bbl_session_traffic_start_ipv6pd(bbl_ctx_s *ctx, bbl_session_s *session);

#endif
