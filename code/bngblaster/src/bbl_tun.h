/*
 * BNG Blaster (BBL) - TUN Interfaces
 *
 * Christian Giese, March 2025
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

 #ifndef __BBL_TUN_H__
 #define __BBL_TUN_H__
 
 #include "bbl.h"

bool
bbl_tun_session_up(bbl_session_s *session);

bool
bbl_tun_session_down(bbl_session_s *session);

bool
bbl_tun_session_init(bbl_session_s *session);

#endif