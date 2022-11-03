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

typedef struct bbl_stream_config_
{
    char *name;
    uint16_t stream_group_id;

    uint8_t type;
    uint8_t direction;

    bool session_traffic;

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

    bbl_stream_config_s *next; /* Next stream config */
} bbl_stream_config_s;

typedef struct bbl_stream_group_
{
    uint32_t count;
    bbl_stream_s *head;
    struct timer_ *timer;
    bbl_stream_group_s *next;
} bbl_stream_group_s;

typedef struct bbl_stream_
{
    uint64_t flow_id;
    uint64_t flow_seq;

    uint8_t type;
    uint8_t sub_type;
    uint8_t direction;

    bbl_stream_config_s *config;

    bbl_stream_group_s *group;
    bbl_stream_s *group_next; /* Next stream of same group */

    uint32_t session_version;
    bbl_session_s *session;
    bbl_stream_s *session_next; /* Next stream of same session */
    endpoint_state_t *endpoint;

    io_handle_s *io;

    bbl_access_interface_s *access_interface;
    bbl_network_interface_s *network_interface;
    bbl_a10nsp_interface_s *a10nsp_interface;

    struct timer_ *tx_timer;
    bbl_interface_s *tx_interface; /* TX interface */
    uint8_t *tx_buf; /* TX buffer */
    uint16_t tx_len; /* TX length */
    uint64_t tx_interval; /* TX interval in nsec */

    bool threaded;
    bool session_traffic;
    bool verified;
    bool wait;
    bool stop;
    bool reset;
    bool lag;

    bool send_window_active;
    uint64_t send_window_start_packets;
    struct timespec send_window_start;
    
    struct timespec wait_start;

    CIRCLEQ_ENTRY(bbl_stream_) tx_qnode;
    uint32_t token_bucket;
    uint32_t token_burst;

    uint64_t lag_select;

    uint64_t tx_packets;

    char _pad0 __attribute__((__aligned__(CACHE_LINE_SIZE))); /* empty cache line */

    uint64_t rx_packets;
    uint64_t rx_loss;
    uint64_t rx_wrong_session;

    uint64_t rx_min_delay_us;
    uint64_t rx_max_delay_us;

    uint16_t rx_len;
    uint64_t rx_first_seq;
    uint64_t rx_last_seq;

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

    bbl_access_interface_s *rx_access_interface;
    bbl_network_interface_s *rx_network_interface;
    bbl_a10nsp_interface_s *rx_a10nsp_interface;

    char _pad1 __attribute__((__aligned__(CACHE_LINE_SIZE))); /* empty cache line */

    uint64_t last_sync_packets_tx;
    uint64_t last_sync_packets_rx;
    uint64_t last_sync_loss;
    uint64_t last_sync_wrong_session;

    uint64_t reset_packets_tx;
    uint64_t reset_packets_rx;
    uint64_t reset_loss;
    uint64_t reset_wrong_session;

    bbl_rate_s rate_packets_tx;
    bbl_rate_s rate_packets_rx;

} bbl_stream_s;

bool
bbl_stream_session_init(bbl_session_s *session);

bool
bbl_stream_init();

void
bbl_stream_final();

protocol_error_t
bbl_stream_tx(io_handle_s *io, uint8_t *buf, uint16_t *len);

bbl_stream_s *
bbl_stream_rx(bbl_ethernet_header_s *eth, bbl_session_s *session);

void
bbl_stream_reset(bbl_stream_s *stream);

json_t *
bbl_stream_json(bbl_stream_s *stream);

int
bbl_stream_ctrl_stats(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
bbl_stream_ctrl_info(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
bbl_stream_ctrl_summary(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
bbl_stream_ctrl_session(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_stream_ctrl_traffic_start(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_stream_ctrl_traffic_stop(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_stream_ctrl_reset(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif