/*
 * BNG Blaster (BBL) - IGMP Functions
 *
 * Christian Giese, October 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_IGMP_H__
#define __BBL_IGMP_H__

typedef struct bbl_igmp_group_
{
    uint8_t  state;
    uint8_t  robustness_count;
    bool     send;
    bool     zapping;
    bool     zapping_result;
    uint32_t group;
    uint32_t source[IGMP_MAX_SOURCES];
    uint64_t packets;
    uint64_t loss;
    struct timespec join_tx_time;
    struct timespec first_mc_rx_time;
    struct timespec leave_tx_time;
    struct timespec last_mc_rx_time;
} bbl_igmp_group_s;

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