/*
 * BNG Blaster (BBL) - Interfaces
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_INTERFACE_H__
#define __BBL_INTERFACE_H__

typedef struct bbl_interface_
{
    char *name; /* interface name */
    interface_type_t type; /* interface type */
    interface_state_t state; /* interface state */
    uint32_t state_transitions; /* interface state transitions */
    uint32_t ifindex; /* interface index */
    uint32_t pcap_index; /* interface index for packet captures */
    uint16_t portid; /* DPDK port identifier */


    bbl_link_config_s *config;

    bbl_lag_s *lag;
    bbl_lag_member_s *lag_member;

    bbl_access_interface_s *access;
    bbl_network_interface_s *network;
    bbl_a10nsp_interface_s *a10nsp;

    /* Network interface VLAN lookup table. */
    bbl_network_interface_s *network_vlan[4096];

    uint8_t mac[ETH_ADDR_LEN];
    uint32_t send_requests;
    
    CIRCLEQ_ENTRY(bbl_interface_) interface_qnode;
    struct {
        struct timer_ *rx_job;
        struct timer_ *tx_job;
        io_handle_s *rx;
        io_handle_s *tx;
    } io;
} bbl_interface_s;

const char *
interface_type_string(interface_type_t type);

const char *
interface_state_string(interface_state_t state);

void
bbl_interface_unlock_all();

bool
bbl_interface_init();

bbl_interface_s *
bbl_interface_get(char *interface_name);

int
bbl_interface_ctrl(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif