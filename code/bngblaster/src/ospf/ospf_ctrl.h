/*
 * BNG Blaster (BBL) - OSPF CTRL (Control Commands)
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_CTRL_H__
#define __BBL_OSPF_CTRL_H__

int
ospf_ctrl_database(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
ospf_ctrl_interfaces(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
ospf_ctrl_neighbors(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

#endif