/*
 * BNG Blaster (BBL) - BGP Definitions
 *
 * Christian Giese, MARCH 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_DEF_H__
#define __BBL_BGP_DEF_H__

/* DEFINITIONS ... */

#define BGP_PORT                179
#define BGP_MAX_MESSAGE_SIZE    4096
#define BGP_WRITEBUFSIZE        4096
#define BGP_DEFAULT_AS          65000
#define BGP_DEFAULT_HOLDTIME    90

#define BGP_MSG_OPEN            1
#define BGP_MSG_UPDATE          2
#define BGP_MSG_NOTIFICATION    3
#define BGP_MSG_KEEPALIVE       4

typedef enum bgp_state_ {
    BGP_IDLE,
    BGP_CONNECT,
    BGP_ACTIVE,
    BGP_OPENSENT,
    BGP_OPENCONFIRM,
    BGP_ESTABLISHED
} bgp_state_t;

/*
 * BGP Configuration
 */
typedef struct bgp_config_ {
    uint32_t ipv4_src_address;
    uint32_t ipv4_dst_address;
    uint32_t id;
    uint32_t local_as;
    uint32_t peer_as;
    uint16_t holdtime;

    char *network_interface;
    char *mrt_file;

    /* Pointer to next instance */
    struct bgp_config_ *next;
} bgp_config_t;

/*
 * BGP Session
 */
typedef struct bgp_session_ {
    struct bbl_ctx_ *ctx; /* parent */
    
    uint32_t ipv4_src_address;
    uint32_t ipv4_dst_address;

    bgp_config_t    *config;
    bbl_interface_s *interface;
    bbl_tcp_ctx_t   *tcpc;

    struct timer_ *connect_timer;
    struct timer_ *send_open_timer;
    struct timer_ *open_sent_timer;
    struct timer_ *keepalive_timer;
    struct timer_ *hold_timer;
    struct timer_ *close_timer;

    uint8_t *write_buf;
    uint16_t write_idx;

    bgp_state_t state;

    struct bgp_session_ *next; /* pointer to next instance */
} bgp_session_t;

#endif