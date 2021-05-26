/*
 * BNG Blaster (BBL) - Streams
 *
 * Christian Giese, Match 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_STREAM_H__
#define __BBL_STREAM_H__

typedef enum {
    STREAM_IPV4,    /* From/to framed IPv4 address */
    STREAM_IPV6,    /* From/to framed IPv6 address */
    STREAM_IPV6PD,  /* From/to delegated IPv6 address */
} __attribute__ ((__packed__)) bbl_stream_type_t;

typedef enum {
    STREAM_DIRECTION_UP     = 1,
    STREAM_DIRECTION_DOWN   = 2,
    STREAM_DIRECTION_BOTH   = 3
} __attribute__ ((__packed__)) bbl_stream_direction_t;

typedef struct bbl_stream_config_
{
    char *name;
    uint16_t stream_group_id;

    bbl_stream_type_t type;
    bbl_stream_direction_t direction;

    uint32_t pps;
    uint16_t length;
    uint8_t  priority; /* IPv4 TOS or IPv6 TC */
    uint8_t  vlan_priority;

    uint32_t ipv4_network_address; /* overwrite default IPv4 network address */
    ipv6addr_t ipv6_network_address; /* overwrite default IPv6 network address */
    uint32_t ipv4_destination_address; /* overwrite IPv4 destination address */
    ipv6addr_t ipv6_destination_address; /* overwrite IPv6 destination address */

    bool threaded;
    void *next; /* next bbl_stream_config */
} bbl_stream_config;

typedef struct bbl_stream_
{
    uint64_t flow_id;
    uint64_t flow_seq;

    struct timer_ *timer;
    struct timer_ *timer_rate;

    bbl_stream_config *config;
    bbl_stream_direction_t direction;

    bbl_interface_s *interface;
    bbl_session_s *session;

    uint8_t *buf;
    uint16_t tx_len;
    uint16_t rx_len;
    uint64_t rx_first_seq;
    uint64_t rx_last_seq;

    uint64_t tx_interval; /* TX interval in nsec */
    uint64_t send_window_packets;
    struct timespec send_window_start;

    uint8_t rx_priority; /* IPv4 TOS or IPv6 TC */
    uint8_t rx_outer_vlan_pbit;
    uint8_t rx_inner_vlan_pbit;

    uint64_t packets_tx;
    uint64_t packets_rx;
    uint64_t packets_tx_last_sync;
    uint64_t packets_rx_last_sync;

    uint64_t loss;

    uint64_t min_delay_ns;
    uint64_t max_delay_ns;

    bbl_rate_s rate_packets_tx;
    bbl_rate_s rate_packets_rx;

    void *next; /* next stream of same session */
} bbl_stream;

bool
bbl_stream_add(bbl_ctx_s *ctx, bbl_access_config_s *access_config, bbl_session_s *session);

bool
bbl_stream_raw_add(bbl_ctx_s *ctx);

void
bbl_stream_tx_job (timer_s *timer);

#endif
