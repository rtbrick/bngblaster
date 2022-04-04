/*
 * BNG Blaster (BBL) - IS-IS CTRL (Control Commands)
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_CTRL_H__
#define __BBL_ISIS_CTRL_H__

ssize_t
isis_ctrl_adjacencies(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)));

ssize_t
isis_ctrl_database(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments);

ssize_t
isis_ctrl_load_mrt(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments);

ssize_t
isis_ctrl_lsp_update(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments);

ssize_t
isis_ctrl_teardown(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)));

#endif