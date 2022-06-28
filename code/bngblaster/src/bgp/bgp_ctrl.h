/*
 * BNG Blaster (BBL) - BGP CTRL (Control Commands)
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_CTRL_H__
#define __BBL_BGP_CTRL_H__

int
bgp_ctrl_sessions(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)));

int
bgp_ctrl_teardown(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)));

int
bgp_ctrl_raw_update(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments);

int
bgp_ctrl_raw_update_list(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)));

int
bgp_ctrl_disconnect(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments);

#endif