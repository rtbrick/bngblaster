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

    bbl_stream_config *next; /* Next stream config */
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

    struct timespec wait_start;
    bool wait;
    bool stop;

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

    bool     rx_mpls1;
    uint32_t rx_mpls1_label;
    uint8_t  rx_mpls1_exp;
    uint8_t  rx_mpls1_ttl;

    bool     rx_mpls2;
    uint32_t rx_mpls2_label;
    uint8_t  rx_mpls2_exp;
    uint8_t  rx_mpls2_ttl;

    bbl_rate_s rate_packets_tx;
    bbl_rate_s rate_packets_rx;

    bbl_stream *next; /* Next stream of same session */

    /* Attributes used for threaded streams only! */
    struct {
        bbl_stream_thread *thread;
        bbl_stream *next; /* Next stream in same thread */
        pthread_mutex_t mutex;
        bool can_send;
    } thread;
} bbl_stream;

/* Structure for traffic stream threads
 * with one or more streams. */
typedef struct bbl_stream_thread_
{
    /* The thread-group allows to assign
     * multiple streams to one thread. The
     * group zero has the special meaning of
     * one thread per stream. */
    uint8_t thread_group;
    pthread_t thread_id;
    pthread_mutex_t mutex;

    /* True if thread is active! */
    bool active;

    /* Root for thread local timers */
    struct timer_root_ timer_root;

    /* Timer for synchronice job of thread
     * counters with main counters. */
    struct timer_ *sync_timer;

    /* TX interface */
    bbl_interface_s *interface;

    /* TX interface file RAW socket */
    struct {
        int fd_tx;
        struct sockaddr_ll addr;
    } socket;

    uint32_t stream_count; /* Number of streams in group */
    bbl_stream *stream; /* First stream in group */
    bbl_stream *stream_tail; /* Last stream in group */

    /* Thread counters ... */

    uint64_t packets_tx;
    uint64_t packets_tx_last_sync;
    uint64_t bytes_tx;
    uint64_t bytes_tx_last_sync;

    uint64_t sendto_failed;
    uint64_t sendto_failed_last_sync;

    void *next; /* Next stream thread */
} bbl_stream_thread;

void
bbl_stream_delay(bbl_stream *stream, struct timespec *rx_timestamp, struct timespec *bbl_timestamp);

bool
bbl_stream_add(bbl_ctx_s *ctx, bbl_access_config_s *access_config, bbl_session_s *session);

bool
bbl_stream_raw_add(bbl_ctx_s *ctx);

bool
bbl_stream_start_threads(bbl_ctx_s *ctx);

void
bbl_stream_stop_threads(bbl_ctx_s *ctx);

void
bbl_stream_tx_job(timer_s *timer);

json_t *
bbl_stream_json(bbl_stream *stream);

#endif