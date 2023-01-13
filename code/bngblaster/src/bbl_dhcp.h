/*
 * BNG Blaster (BBL) - DHCP
 *
 * Christian Giese, April 2021
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_DHCP_H__
#define __BBL_DHCP_H__

void
bbl_dhcp_stop(bbl_session_s *session);

void
bbl_dhcp_start(bbl_session_s *session);

void
bbl_dhcp_restart(bbl_session_s *session);

void
bbl_dhcp_rx(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_dhcp_s *dhcp);

#endif
