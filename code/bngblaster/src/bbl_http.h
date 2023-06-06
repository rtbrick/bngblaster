/*
 * BNG Blaster (BBL) - HTTP
 *
 * Christian Giese, June 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_HTTP_H__
#define __BBL_HTTP_H__

#define HTTP_REQUEST_STRING     "GET / HTTP/1.1\r\nHost: %s\r\n\r\n"
#define HTTP_RESPONSE_LIMIT     2048

typedef enum {
    HTTP_CLIENT_IDLE = 0,
    HTTP_CLIENT_CONNECTING,
    HTTP_CLIENT_CONNECTED,
    HTTP_CLIENT_REQUEST_SEND,
    HTTP_CLIENT_RESPONSE_RECEIVED,
    HTTP_CLIENT_CLOSED,
} __attribute__ ((__packed__)) http_client_state_t;

typedef struct bbl_http_client_config_
{
    char *name;
    const char *url;

    uint16_t http_client_group_id;
    uint16_t dst_port;

    uint8_t priority; /* IPv4 TOS or IPv6 TC */
    uint8_t vlan_priority;

    uint32_t start_delay;
    uint32_t ipv4_destination_address; /* set IPv4 destination address */
    ipv6addr_t ipv6_destination_address; /* set IPv6 destination address */

    bbl_http_client_config_s *next; /* Next http client config */
} bbl_http_client_config_s;

typedef struct bbl_http_client_
{
    bbl_session_s *session;

    bbl_http_client_config_s *config;
    bbl_http_client_s *next; /* Next http client of same session */

    char    *request;
    char    *response;
    uint32_t response_idx;
    uint32_t timeout;

    bbl_tcp_ctx_s *tcpc;
    const char *error_string;

    uint8_t state;
    struct timer_ *state_timer;
} bbl_http_client_s;

bool
bbl_http_client_session_init(bbl_session_s *session);

#endif
