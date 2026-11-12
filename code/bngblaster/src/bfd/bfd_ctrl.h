/*
 * BNG Blaster (BBL) - BFD CTRL (Control Commands)
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BFD_CTRL_H__
#define __BBL_BFD_CTRL_H__

int
bfd_ctrl_sessions(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
bfd_ctrl_session_enable(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
bfd_ctrl_session_disable(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
bfd_ctrl_session_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

#endif
