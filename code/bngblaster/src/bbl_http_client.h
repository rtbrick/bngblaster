/*
 * BNG Blaster (BBL) - HTTP Client
 *
 * Christian Giese, June 2023
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_HTTP_CLIENT_H__
#define __BBL_HTTP_CLIENT_H__

#define HTTP_CLIENT_REQUEST_STRING     "GET / HTTP/1.1\r\nHost: %s\r\n\r\n"
#define HTTP_CLIENT_RESPONSE_LIMIT     2048
#define HTTP_CLIENT_RESPONSE_TIMEOUT   30
#define HTTP_CLIENT_CONNECT_TIMEOUT    10

typedef enum {
    HTTP_CLIENT_IDLE = 0,
    HTTP_CLIENT_CONNECTING,
    HTTP_CLIENT_CONNECTED,
    HTTP_CLIENT_CLOSING,
    HTTP_CLIENT_CLOSED,
    HTTP_CLIENT_SESSION_DOWN,
    HTTP_CLIENT_RETRY_WAIT,
} __attribute__ ((__packed__)) http_state_t;

typedef struct bbl_http_client_config_
{
    char *name;
    const char *url;

    uint16_t http_client_group_id;
    uint16_t dst_port;

    bool autostart;
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

    struct {
        int minor_version;
        int status;
        const char *msg;
        size_t msg_len;
        struct phr_header headers[8];
        size_t num_headers;
    } http;

    bbl_tcp_ctx_s *tcpc;
    const char *error_string;

    uint8_t state;
    struct timer_ *state_timer;
    uint32_t timeout;
} bbl_http_client_s;

bool
bbl_http_client_session_init(bbl_session_s *session);

int
bbl_http_client_ctrl(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_http_client_ctrl_start(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_http_client_ctrl_stop(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

#endif
