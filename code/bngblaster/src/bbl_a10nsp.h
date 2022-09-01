/*
 * BNG Blaster (BBL) - A10NSP Functions
 *
 * Christian Giese, September 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_A10NSP_H__
#define __BBL_A10NSP_H__

#define A10NSP_PPPOE_SERVICE_NAME   "access"
#define A10NSP_PPPOE_AC_NAME        "BNG-Blaster-A10NSP"
#define A10NSP_REPLY_MESSAGE        "BNG-Blaster-A10NSP"

#define A10NSP_IP_LOCAL             168495882
#define A10NSP_IP_REMOTE            168430090
#define A10NSP_DNS1                 168561674
#define A10NSP_DNS2                 168627466

typedef struct bbl_a10nsp_interface_
{
    bbl_interface_s *interface;
    bbl_txq_s *txq;
    uint8_t mac[ETH_ADDR_LEN];
    bool qinq;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        uint64_t bytes_tx;
        uint64_t bytes_rx;
        
        uint64_t unknown;

        uint64_t session_ipv4_tx;
        uint64_t session_ipv4_rx;
        uint64_t session_ipv4_loss;
        uint64_t session_ipv6_tx;
        uint64_t session_ipv6_rx;
        uint64_t session_ipv6_loss;
        uint64_t session_ipv6pd_tx;
        uint64_t session_ipv6pd_rx;
        uint64_t session_ipv6pd_loss;

        uint64_t stream_tx;
        uint64_t stream_rx;
        uint64_t stream_loss;

        /* Rate Stats */

        bbl_rate_s rate_packets_tx;
        bbl_rate_s rate_packets_rx;
        bbl_rate_s rate_bytes_tx;
        bbl_rate_s rate_bytes_rx;
        bbl_rate_s rate_session_ipv4_tx;
        bbl_rate_s rate_session_ipv4_rx;
        bbl_rate_s rate_session_ipv6_tx;
        bbl_rate_s rate_session_ipv6_rx;
        bbl_rate_s rate_session_ipv6pd_tx;
        bbl_rate_s rate_session_ipv6pd_rx;
        bbl_rate_s rate_stream_tx;
        bbl_rate_s rate_stream_rx;
    } stats;

    struct timer_ *rate_job;

    CIRCLEQ_ENTRY(bbl_a10nsp_interface_) a10nsp_interface_qnode;
    CIRCLEQ_HEAD(session_tx_a10nsp_, bbl_session_ ) session_tx_qhead; /* list of sessions that want to transmit */

} bbl_a10nsp_interface_s;

typedef struct bbl_a10nsp_session_
{
    bbl_session_s *session;
    bbl_a10nsp_interface_s *a10nsp_interface;
    uint16_t s_vlan;

    bool qinq_received;

    char *pppoe_ari;
    char *pppoe_aci;
    char *dhcp_ari;
    char *dhcp_aci;
    char *dhcpv6_ari;
    char *dhcpv6_aci;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
    } stats;

} bbl_a10nsp_session_s;

bool
bbl_a10nsp_interfaces_add();

bbl_a10nsp_interface_s*
bbl_a10nsp_interface_get(char *interface_name);

void
bbl_a10nsp_session_free(bbl_session_s *session);

void
bbl_a10nsp_rx_handler(bbl_a10nsp_interface_s *interface,
                      bbl_ethernet_header_t *eth);

#endif
