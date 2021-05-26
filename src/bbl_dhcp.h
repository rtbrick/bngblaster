/*
 * BNG Blaster (BBL) - DHCP
 *
 * Christian Giese, April 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_DHCP_H__
#define __BBL_DHCP_H__

void
bbl_dhcp_restart(bbl_session_s *session);

void
bbl_dhcp_rx(bbl_ethernet_header_t *eth, bbl_dhcp_t *dhcp, bbl_session_s *session);

#endif
