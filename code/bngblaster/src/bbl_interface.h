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

    bbl_interface_state_type_t state;
    uint8_t mac[ETH_ADDR_LEN];
    uint32_t send_requests;
    
    CIRCLEQ_ENTRY(bbl_interface_) interface_qnode;
    CIRCLEQ_ENTRY(bbl_interface_) interface_lag_qnode;

    struct {
        io_handle_s *rx;
        io_handle_s *tx;
        uint8_t *sp;
        bool ctrl;
    } io;

    uint32_t ifindex; /* interface index */
    uint32_t pcap_index; /* interface index for packet captures */
    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        uint64_t bytes_tx;
        uint64_t bytes_rx;
        uint64_t unknown;
        uint64_t encode_errors;
        uint64_t decode_error;
        uint64_t sendto_failed;
        uint64_t no_buffer;
        uint64_t poll_tx;
        uint64_t poll_rx;

        /* Rate Stats */

        bbl_rate_s rate_packets_tx;
        bbl_rate_s rate_packets_rx;
        bbl_rate_s rate_bytes_tx;
        bbl_rate_s rate_bytes_rx;
    } stats;

    struct timer_ *tx_job;
    struct timer_ *rx_job;
    struct timer_ *rate_job;
} bbl_interface_s;

void
bbl_interface_unlock_all();

bool
bbl_interface_init();

bbl_interface_s *
bbl_interface_get(char *interface_name);

#endif