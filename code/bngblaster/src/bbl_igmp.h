/*
 * BNG Blaster (BBL) - IGMP Functions
 *
 * Christian Giese, October 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_IGMP_H__
#define __BBL_IGMP_H__

void
bbl_igmp_rx(bbl_session_s *session, bbl_ipv4_s *ipv4);

int
bbl_igmp_ctrl_join(int fd, uint32_t session_id, json_t *arguments);

int
bbl_igmp_ctrl_join_iter(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
bbl_igmp_ctrl_leave(int fd, uint32_t session_id, json_t *arguments);

int
bbl_igmp_ctrl_leave_all(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
bbl_igmp_ctrl_info(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_igmp_ctrl_zapping_start(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
bbl_igmp_ctrl_zapping_stop(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
bbl_igmp_ctrl_zapping_stats(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif