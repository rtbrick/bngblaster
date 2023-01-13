/*
 * BNG Blaster (BBL) - CFM Functions
 *
 * Christian Giese, October 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_CFM_H__
#define __BBL_CFM_H__

void
bbl_cfm_cc_start(bbl_session_s *session);

int
bbl_cfm_ctrl_cc_start(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_cfm_ctrl_cc_stop(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_cfm_ctrl_cc_rdi_on(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_cfm_ctrl_cc_rdi_off(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

#endif