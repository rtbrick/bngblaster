/*
 * BNG Blaster (BBL) - TCP
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_TCP_H__
#define __BBL_TCP_H__

#include "bbl.h"
#include "lwip/priv/tcp_priv.h"

#define BBL_TCP_BUF_SIZE 65000
#define BBL_TCP_INTERVAL 250*MSEC
#define BBL_TCP_HASHTABLE_SIZE 32771
#define BBL_TCP_NETIF_MAX 255

typedef enum bbl_tcp_state_ {
    BBL_TCP_STATE_CLOSED,
    BBL_TCP_STATE_LISTEN,
    BBL_TCP_STATE_CONNECTING,
    BBL_TCP_STATE_IDLE,
    BBL_TCP_STATE_SENDING,
} bbl_tcp_state_t;

typedef err_t (*bbl_tcp_accepted_fn)(bbl_tcp_ctx_s *tcpc, void *arg);
typedef void (*bbl_tcp_callback_fn)(void *arg);
typedef void (*bbl_tcp_receive_fn)(void *arg, uint8_t *buf, uint16_t len);
typedef void (*bbl_tcp_error_fn)(void *arg, err_t err);
typedef err_t (*bbl_tcp_poll_fn)(void *arg, struct tcp_pcb *tpcb);

typedef struct bbl_tcp_ctx_
{
    char* ifname;
    bbl_network_interface_s *interface;
    bbl_session_s *session;

    bool listen;
    uint8_t af; /* AF_INET or AF_INET6 */

    uint16_t   local_port;
    ip_addr_t  local_addr;

    uint16_t   remote_port;
    ip_addr_t  remote_addr;
    
    struct tcp_pcb *pcb;

    bbl_tcp_accepted_fn accepted_cb; /* accepted callback (listen) */
    bbl_tcp_callback_fn connected_cb; /* application connected callback */
    bbl_tcp_callback_fn idle_cb; /* application idle callback */

    bbl_tcp_receive_fn receive_cb; /* application receive callback */
    bbl_tcp_error_fn error_cb; /* application error callback */

    bbl_tcp_poll_fn poll_cb; /* application poll callback */
    uint8_t poll_interval;

    void *arg; /* application callback argument */

    bbl_tcp_state_t state;
    err_t err;

    struct {
        uint8_t *buf;
        uint32_t len;
        uint32_t offset;
        uint8_t  flags; /* e.g. TCP_WRITE_FLAG_COPY */
    } tx;

    uint64_t packets_rx;
    uint64_t bytes_rx;
    uint64_t packets_tx;
    uint64_t bytes_tx;

} bbl_tcp_ctx_s;

const char *
tcp_err_string(err_t err);

void
bbl_tcp_close(bbl_tcp_ctx_s *tcpc);

void
bbl_tcp_ctx_free(bbl_tcp_ctx_s *tcpc);

bbl_tcp_ctx_s *
bbl_tcp_ipv4_listen(bbl_network_interface_s *interface, ipv4addr_t *address,
                     uint16_t port, uint8_t ttl, uint8_t tos);

bbl_tcp_ctx_s *
bbl_tcp_ipv6_listen(bbl_network_interface_s *interface, ipv6addr_t *address,
                     uint16_t port, uint8_t ttl, uint8_t tos);

bbl_tcp_ctx_s *
bbl_tcp_ipv4_connect(bbl_network_interface_s *interface, ipv4addr_t *src, ipv4addr_t *dst, 
                     uint16_t port, uint8_t ttl, uint8_t tos);

bbl_tcp_ctx_s *
bbl_tcp_ipv4_connect_session(bbl_session_s *session, ipv4addr_t *src, ipv4addr_t *dst, 
                             uint16_t port);

bbl_tcp_ctx_s *
bbl_tcp_ipv6_connect(bbl_network_interface_s *interface, ipv6addr_t *src, ipv6addr_t *dst,
                     uint16_t port, uint8_t ttl, uint8_t tos);

bbl_tcp_ctx_s *
bbl_tcp_ipv6_connect_session(bbl_session_s *session, ipv6addr_t *src, ipv6addr_t *dst, 
                             uint16_t port);

void
bbl_tcp_ipv4_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4);

void
bbl_tcp_ipv4_rx_session(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4);

void
bbl_tcp_ipv6_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth, bbl_ipv6_s *ipv6);

void
bbl_tcp_ipv6_rx_session(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_ipv6_s *ipv6);

bool
bbl_tcp_send(bbl_tcp_ctx_s *tcpc, uint8_t *buf, uint32_t len);

bool
bbl_tcp_network_interface_init(bbl_network_interface_s *interface, bbl_network_config_s *config);

bool
bbl_tcp_session_init(bbl_session_s *session);

void
bbl_tcp_init();

#endif