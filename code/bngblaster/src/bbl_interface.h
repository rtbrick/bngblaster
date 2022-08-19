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

    uint8_t mac[ETH_ADDR_LEN];

    uint32_t send_requests;
    
    CIRCLEQ_ENTRY(bbl_interface_) interface_qnode;
    CIRCLEQ_ENTRY(bbl_interface_) interface_lag_qnode;

    struct {
        bbl_io_mode_t mode;

        int fd_tx;
        int fd_rx;

        struct tpacket_req req_tx;
        struct tpacket_req req_rx;
        struct sockaddr_ll addr;

        uint8_t *rx_buf; /* RX buffer */
        uint16_t rx_len;
        uint8_t *tx_buf; /* TX buffer */
        uint16_t tx_len;

        uint8_t *ring_tx; /* TX ring buffer */
        uint8_t *ring_rx; /* RX ring buffer */
        uint16_t cursor_tx; /* slot # inside the ring buffer */
        uint16_t cursor_rx; /* slot # inside the ring buffer */
        uint16_t queued_tx;

        bool pollout;
        bool ctrl; /* control traffic */

#ifdef BNGBLASTER_NETMAP
        struct nm_desc *port;
#endif
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

    struct timespec tx_timestamp; /* user space timestamps */
    struct timespec rx_timestamp; /* user space timestamps */

} bbl_interface_s;

void
bbl_interface_unlock_all();

bool
bbl_interface_init();

bbl_interface_s *
bbl_interface_get(char *interface_name);

#endif