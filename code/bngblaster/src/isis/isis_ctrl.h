/*
 * BNG Blaster (BBL) - IS-IS CTRL (Control Commands)
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_CTRL_H__
#define __BBL_ISIS_CTRL_H__

int
isis_ctrl_adjacencies(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
isis_ctrl_database(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
isis_ctrl_load_mrt(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
isis_ctrl_lsp_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
isis_ctrl_lsp_purge(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
isis_ctrl_lsp_flap(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
isis_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif