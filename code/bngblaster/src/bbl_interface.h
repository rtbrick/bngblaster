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

    bbl_link_config_s *config;
    bbl_lag_s *lag;

    bbl_a10nsp_interface_s *a10nsp;
    bbl_access_interface_s *access;
    bbl_network_interface_s *network;

    interface_state_t state;
    uint8_t mac[ETH_ADDR_LEN];
    uint32_t send_requests;
    
    CIRCLEQ_ENTRY(bbl_interface_) interface_qnode;
    CIRCLEQ_ENTRY(bbl_interface_) interface_lag_qnode;

    struct {
        io_handle_s *rx;
        io_handle_s *tx;
    } io;

    uint32_t ifindex; /* interface index */
    uint32_t pcap_index; /* interface index for packet captures */

    struct timer_ *tx_job;
    struct timer_ *rx_job;
} bbl_interface_s;

void
bbl_interface_unlock_all();

bool
bbl_interface_init();

bbl_interface_s *
bbl_interface_get(char *interface_name);

#endif