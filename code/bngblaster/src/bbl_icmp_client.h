/*
 * BNG Blaster (BBL) - ICMP Client
 *
 * Christian Giese, December 2024
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_ICMP_CLIENT_H__
#define __BBL_ICMP_CLIENT_H__

typedef enum {
    ICMP_DOWN = 0,
    ICMP_WAIT = 1,
    ICMP_STARTED = 2,
    ICMP_STOPPED = 3,
} __attribute__ ((__packed__)) icmp_state_t;

typedef enum {
    ICMP_RESULT_NONE = 0,
    ICMP_RESULT_WAIT = 1,
    ICMP_RESULT_OKAY = 2,
    ICMP_RESULT_UNREACHABLE = 3,
    ICMP_RESULT_REDIRECTED = 4,
    ICMP_RESULT_FRAGMENTATION_NEEDED = 5,
    ICMP_RESULT_TTL_EXCEEDED = 6
} __attribute__ ((__packed__)) icmp_result_t;

typedef enum {
    ICMP_MODE_PING = 0,
    ICMP_MODE_TRACEROUTE = 1
} __attribute__ ((__packed__)) icmp_mode_t;

typedef struct bbl_icmp_client_result_ping_
{
    uint16_t seq;
    uint16_t size;
    uint32_t rtt;
    uint8_t ttl;
    uint8_t state;
    struct timespec timestamp_tx;
    struct timespec timestamp_rx;
} bbl_icmp_client_result_ping_s;

typedef struct bbl_icmp_client_config_
{
    uint16_t icmp_client_group_id;
    char *network_interface;

    uint8_t mode;
    uint8_t ttl;
    uint8_t tos;
    bool df;
    uint16_t count;
    uint16_t size;
    uint16_t start_delay;
    uint16_t results;
    uint32_t src; /* set IPv4 source address */
    uint32_t dst; /* set IPv4 destination address */

    double interval;
    time_t interval_sec;
    long interval_nsec;

    bool autostart;

    bbl_icmp_client_config_s *next; /* Next icmp client config */
} bbl_icmp_client_config_s;

typedef struct bbl_icmp_client_
{
    uint32_t src; /* IPv4 source address */
    uint32_t dst; /* IPv4 destination address */
    uint16_t id;
    uint16_t seq;
    uint8_t state;

    bbl_session_s *session;
    bbl_network_interface_s *network_interface;

    bbl_icmp_client_config_s *config;
    bbl_icmp_client_s *next; /* Next icmp client of same session/interface */
    bbl_icmp_client_s *global_next; /* Next icmp client (global) */

    struct timer_ *state_timer;
    struct timer_ *send_timer;
    void *result; /* result structure is different based on type */
    uint16_t results;
    uint16_t start_delay_countdown;
    uint8_t last_result;

    uint32_t send;
    uint32_t received;
    uint32_t errors;

    uint8_t *data; 
    uint16_t data_len;
} bbl_icmp_client_s;

bool
bbl_icmp_client_rx(bbl_session_s *session,
                   bbl_network_interface_s *network_interface,
                   bbl_ethernet_header_s *eth,
                   bbl_ipv4_s *ipv4,
                   bbl_icmp_s *icmp);

bool
bbl_icmp_client_session_init(bbl_session_s *session);

bool
bbl_icmp_client_network_interface_init(bbl_network_interface_s *network_interface);

int
bbl_icmp_client_ctrl(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_icmp_client_ctrl_start(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_icmp_client_ctrl_stop(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

#endif
