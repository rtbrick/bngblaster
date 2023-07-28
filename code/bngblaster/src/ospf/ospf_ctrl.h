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

int
ospf_ctrl_load_mrt(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
ospf_ctrl_lsa_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
ospf_ctrl_pdu_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
ospf_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif