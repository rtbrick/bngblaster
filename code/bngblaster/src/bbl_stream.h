/*
 * BNG Blaster (BBL) - Traffic Streams
 *
 * Christian Giese, Match 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
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

    double pps;
    uint32_t max_packets;
    uint32_t start_delay;

    uint16_t src_port;
    uint16_t dst_port;

    uint16_t length;
    uint8_t  priority; /* IPv4 TOS or IPv6 TC */
    uint8_t  vlan_priority;

    uint32_t ipv4_access_src_address; /* overwrite default IPv4 access address */
    ipv6addr_t ipv6_access_src_address; /* overwrite default IPv6 access address */
    uint32_t ipv4_network_address; /* overwrite default IPv4 network address */
    ipv6addr_t ipv6_network_address; /* overwrite default IPv6 network address */
    uint32_t ipv4_destination_address; /* overwrite IPv4 destination address */
    ipv6addr_t ipv6_destination_address; /* overwrite IPv6 destination address */
    char *network_interface;
    char *a10nsp_interface;

    bool     ipv4_df;
    bool     tx_mpls1;
    uint32_t tx_mpls1_label;
    uint8_t  tx_mpls1_exp;
    uint8_t  tx_mpls1_ttl;

    bool     tx_mpls2;
    uint32_t tx_mpls2_label;
    uint8_t  tx_mpls2_exp;
    uint8_t  tx_mpls2_ttl;
    
    bool     rx_mpls1;
    uint32_t rx_mpls1_label;
    
    bool     rx_mpls2;
    uint32_t rx_mpls2_label;

    bool threaded;
    uint8_t thread_group;

    bbl_stream_config_s *next; /* Next stream config */
} bbl_stream_config_s;

typedef struct bbl_stream_
{
    uint64_t flow_id;
    uint64_t flow_seq;

    struct timer_ *timer_tx;

    bbl_stream_config_s *config;
    bbl_stream_direction_t direction;

    bbl_interface_s *interface;
    bbl_session_s *session;
    bbl_stream_s *session_next; /* Next stream of same session */
    bbl_stream_thread_s *thread;
    bbl_stream_s *thread_next; /* Next stream of same thread */

    uint8_t *buf;
    uint16_t tx_len;
    uint16_t rx_len;
    uint64_t rx_first_seq;
    uint64_t rx_last_seq;
    uint64_t tx_interval; /* TX interval in nsec */

    bool wait;
    bool stop;

    struct timespec wait_start;
    struct timespec send_window_start;
    uint64_t send_window_packets;
    uint64_t packets_tx;

    char _pad0 __attribute__((__aligned__(CACHE_LINE_SIZE))); /* empty cache line */

    uint64_t packets_rx;
    uint64_t loss;
    uint64_t min_delay_ns;
    uint64_t max_delay_ns;

    uint8_t  rx_priority; /* IPv4 TOS or IPv6 TC */
    uint8_t  rx_outer_vlan_pbit;
    uint8_t  rx_inner_vlan_pbit;

    bool     rx_mpls1;
    uint8_t  rx_mpls1_exp;
    uint8_t  rx_mpls1_ttl;
    uint32_t rx_mpls1_label;

    bool     rx_mpls2;
    uint8_t  rx_mpls2_exp;
    uint8_t  rx_mpls2_ttl;
    uint32_t rx_mpls2_label;

    char _pad1 __attribute__((__aligned__(CACHE_LINE_SIZE))); /* empty cache line */

    struct timer_ *timer_ctrl;
    uint64_t last_sync_packets_rx;
    uint64_t last_sync_packets_tx;
    bbl_rate_s rate_packets_rx;
    bbl_rate_s rate_packets_tx;

} bbl_stream_s;

void
bbl_stream_tx_job(timer_s *timer);

void
bbl_stream_delay(bbl_stream_s *stream, struct timespec *rx_timestamp, struct timespec *bbl_timestamp);

bool
bbl_stream_add(bbl_access_config_s *access_config, bbl_session_s *session);

bool
bbl_stream_raw_add();

bool
bbl_stream_rx(bbl_ethernet_header_t *eth, bbl_bbl_t *bbl, uint64_t *loss, uint8_t tos);

json_t *
bbl_stream_json(bbl_stream_s *stream);

#endif