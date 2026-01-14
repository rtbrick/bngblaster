/*
 * BNG Blaster (BBL) - LDP CTRL (Control Commands)
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_CTRL_H__
#define __BBL_LDP_CTRL_H__

int
ldp_ctrl_adjacencies(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
ldp_ctrl_sessions(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
ldp_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
ldp_ctrl_raw_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
ldp_ctrl_raw_update_list(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
ldp_ctrl_disconnect(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
ldb_ctrl_database(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

#endif