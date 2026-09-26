/*
 * BNG Blaster (BBL) - BGP RIB (Adj-RIB-In)
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_RIB_H__
#define __BBL_BGP_RIB_H__

bool
bgp_rib_init(bgp_session_s *session);

bool
bgp_rib_update(bgp_session_s *session, bgp_update_s *update);

void
bgp_rib_flush(bgp_session_s *session);

char *
bgp_rib_format_as_path(bgp_rib_attr_s *attr);

#endif
