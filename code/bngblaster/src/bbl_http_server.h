/*
 * BNG Blaster (BBL) - HTTP Server
 *
 * Christian Giese, June 2023
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_HTTP_SERVER_H__
#define __BBL_HTTP_SERVER_H__

#define HTTP_SERVER_RESPONSE_STRING "HTTP/1.1 200 OK\r\nServer: BNG-Blaster\r\n\r\n"
#define HTTP_SERVER_RESPONSE_STRING_IP_PORT "HTTP/1.1 200 OK\r\nServer: BNG-Blaster\r\nX-Client-Ip: %s\r\nX-Client-Port: %d\r\n\r\n"

typedef struct bbl_http_server_config_
{
    char *name;
    char *network_interface;

    uint16_t port;
    uint32_t ipv4_address; /* set IPv4 address */
    ipv6addr_t ipv6_address; /* set IPv6 address */

    bbl_http_server_config_s *next; /* next http server config */
} bbl_http_server_config_s;

typedef struct bbl_http_server_connection_
{
    bbl_tcp_ctx_s *tcpc;
    bbl_http_server_connection_s *next; /* next connection */
} bbl_http_server_connection_s;

typedef struct bbl_http_server_
{
    bbl_http_server_config_s *config;
    bbl_http_server_connection_s *connections;
    bbl_tcp_ctx_s *listen_tcpc;

    struct timer_ *gc_timer;

    bbl_http_server_s *next; /* next http server of same network interface */
} bbl_http_server_s;

bool
bbl_http_server_init(bbl_network_interface_s *network_interface);

#endif
