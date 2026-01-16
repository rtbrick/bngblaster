/*
 * BNG Blaster (BBL) - CFM Functions
 *
 * Christian Giese, October 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_CFM_H__
#define __BBL_CFM_H__

typedef struct bbl_cfm_session_
{
    bool cfm_cc;
    bool cfm_rdi;

    uint32_t cfm_cc_tx;
    uint32_t cfm_cc_rx;

    uint32_t cfm_seq;
    uint8_t cfm_level;
    uint8_t cfm_interval;
    uint16_t cfm_ma_id;
    char *cfm_md_name;
    uint8_t cfm_md_name_format;
    bool cfm_md_name_format_set;
    char *cfm_ma_name;
    uint8_t cfm_ma_name_format;
    bool cfm_ma_name_format_set;
    uint8_t vlan_priority;

    struct timer_ *timer_cfm_cc;

    bbl_session_s *session;
    bbl_network_interface_s *network_interface;
} bbl_cfm_session_s;

void
bbl_cfm_cc_start(bbl_cfm_session_s *session);

int
bbl_cfm_ctrl_cc_start(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_cfm_ctrl_cc_stop(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_cfm_ctrl_cc_rdi_on(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_cfm_ctrl_cc_rdi_off(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

#endif
