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
    bool cc;
    bool rdi;

    uint32_t cc_tx;
    uint32_t cc_rx;

    uint32_t seq;

    char    *md_name;
    uint8_t *md_name_buf;
    uint16_t md_name_len;
    char    *ma_name;
    uint8_t *ma_name_buf;
    uint16_t ma_name_len;

    struct timer_ *timer_cfm_cc;

    bbl_cfm_config_s *config;

    bbl_session_s *session;
    bbl_network_interface_s *network_interface;
} bbl_cfm_session_s;

bool
bbl_cfm_init(bbl_cfm_session_s *cfm);

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
