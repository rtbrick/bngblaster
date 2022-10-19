/*
 * BNG Blaster (BBL) - DHCPv6
 *
 * Christian Giese, May 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_DHCPV6_H__
#define __BBL_DHCPV6_H__

void
bbl_dhcpv6_stop(bbl_session_s *session);

void
bbl_dhcpv6_start(bbl_session_s *session);

void
bbl_dhcpv6_restart(bbl_session_s *session);

void
bbl_dhcpv6_rx(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_dhcpv6_s *dhcpv6);

#endif
