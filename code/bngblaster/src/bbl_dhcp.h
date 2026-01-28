/*
 * BNG Blaster (BBL) - DHCP
 *
 * Christian Giese, April 2021
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_DHCP_H__
#define __BBL_DHCP_H__

typedef enum {
    DHCP_ACTION_START = 0,
    DHCP_ACTION_STOP = 1,
    DHCP_ACTION_RELEASE = 2
} __attribute__ ((__packed__)) dhcp_ctrl_action;

void
bbl_dhcp_stop(bbl_session_s *session, bool keep_address);

void
bbl_dhcp_start(bbl_session_s *session);

void
bbl_dhcp_restart(bbl_session_s *session);

void
bbl_dhcp_rx(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_dhcp_s *dhcp);

int
bbl_dhcp_ctrl_start(int fd, uint32_t session_id, json_t *arguments);

int
bbl_dhcp_ctrl_stop(int fd, uint32_t session_id, json_t *arguments);

int
bbl_dhcp_ctrl_release(int fd, uint32_t session_id, json_t *arguments);

#endif
