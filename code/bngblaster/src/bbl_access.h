/*
 * BNG Blaster (BBL) - Access Functions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_ACCESS_H__
#define __BBL_ACCESS_H__

typedef struct bbl_access_interface_
{
    char *name; /* interface name */
    uint32_t ifindex; /* interface index */

    /* parent */
    bbl_interface_s *interface; 

    bbl_txq_s *txq;

    uint8_t mac[ETH_ADDR_LEN];
    uint32_t send_requests;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        uint64_t bytes_tx;
        uint64_t bytes_rx;

        uint64_t mc_rx;
        uint64_t mc_loss;
        uint64_t unknown;
        uint64_t no_session;

        /* Packet Stats */
        uint32_t arp_tx;
        uint32_t arp_rx;
        uint32_t cfm_cc_tx;
        uint32_t cfm_cc_rx;
        uint32_t padi_tx;
        uint32_t pado_rx;
        uint32_t padr_tx;
        uint32_t pads_rx;
        uint32_t padt_tx;
        uint32_t padt_rx;
        uint32_t lcp_tx;
        uint32_t lcp_rx;
        uint32_t lcp_timeout;
        uint32_t lcp_echo_timeout;
        uint32_t pap_tx;
        uint32_t pap_rx;
        uint32_t pap_timeout;
        uint32_t chap_tx;
        uint32_t chap_rx;
        uint32_t chap_timeout;
        uint32_t ipcp_tx;
        uint32_t ipcp_rx;
        uint32_t ipcp_timeout;
        uint32_t ip6cp_tx;
        uint32_t ip6cp_rx;
        uint32_t ip6cp_timeout;
        uint32_t igmp_rx;
        uint32_t igmp_tx;
        uint32_t icmp_tx;
        uint32_t icmp_rx;
        uint32_t icmpv6_tx;
        uint32_t icmpv6_rx;
        uint32_t icmpv6_rs_timeout;
        uint32_t tcp_tx;
        uint32_t tcp_rx;
        uint32_t dhcp_tx;
        uint32_t dhcp_rx;
        uint32_t dhcp_timeout;

        uint32_t dhcpv6_tx;
        uint32_t dhcpv6_rx;
        uint32_t dhcpv6_timeout;

        uint32_t ipv4_fragmented_rx;

        uint64_t session_ipv4_tx;
        uint64_t session_ipv4_rx;
        uint64_t session_ipv4_loss;
        uint64_t session_ipv4_wrong_session;
        uint64_t session_ipv6_tx;
        uint64_t session_ipv6_rx;
        uint64_t session_ipv6_loss;
        uint64_t session_ipv6_wrong_session;
        uint64_t session_ipv6pd_tx;
        uint64_t session_ipv6pd_rx;
        uint64_t session_ipv6pd_loss;
        uint64_t session_ipv6pd_wrong_session;

        uint64_t stream_tx;
        uint64_t stream_rx;
        uint64_t stream_loss;

        /* Rate Stats */

        bbl_rate_s rate_packets_tx;
        bbl_rate_s rate_packets_rx;
        bbl_rate_s rate_bytes_tx;
        bbl_rate_s rate_bytes_rx;
        bbl_rate_s rate_mc_rx;
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

    CIRCLEQ_ENTRY(bbl_access_interface_) access_interface_qnode;
    CIRCLEQ_HEAD(session_tx_access_, bbl_session_ ) session_tx_qhead; /* list of sessions that want to transmit */

} bbl_access_interface_s;

bool
bbl_access_interfaces_add();

bbl_access_interface_s*
bbl_access_interface_get(char *interface_name);

void
bbl_access_rx_established_ipoe(bbl_access_interface_s *interface, 
                               bbl_session_s *session, 
                               bbl_ethernet_header_s *eth);

void
bbl_access_rx_established_pppoe(bbl_access_interface_s *interface, 
                                bbl_session_s *session, 
                                bbl_ethernet_header_s *eth);

void
bbl_access_rx_handler(bbl_access_interface_s *interface, 
                      bbl_ethernet_header_s *eth);

int
bbl_access_ctrl_interfaces(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif
