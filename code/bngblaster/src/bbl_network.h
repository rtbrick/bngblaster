/*
 * BNG Blaster (BBL) - Network Functions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_NETWORK_H__
#define __BBL_NETWORK_H__

typedef struct bbl_network_interface_
{
    char *name; /* interface name */
    uint32_t ifindex; /* interface index */

    /* parent */
    bbl_interface_s *interface; 

    /* next network interface with same parent */
    struct bbl_network_interface_ *next;

    bbl_txq_s *txq;

    uint16_t vlan;
    bbl_mpls_s tx_label;
    
    uint8_t mac[ETH_ADDR_LEN];
    uint8_t gateway_mac[ETH_ADDR_LEN];

    uint32_t send_requests;

    ipv4_prefix ip;
    ipv4addr_t  gateway;

    bool ipv6_ra;

    ipv6_prefix ip6; /* global IPv6 address */
    ipv6addr_t  ip6_ll; /* link-local IPv6 address */
    ipv6addr_t  gateway6;
    ipv6addr_t  gateway6_solicited_node_multicast;

    bool arp_resolved;
    bool icmpv6_nd_resolved;
    bool gateway_resolve_wait;

    struct timer_ *timer_arp;
    struct timer_ *timer_nd;
    struct timer_ *timer_ra;
    struct timer_ *timer_isis_hello;

    uint8_t *mc_packets;
    uint16_t mc_packet_len;
    uint64_t mc_packet_seq;
    uint16_t mc_packet_cursor;

    struct netif netif; /* LwIP network interface */

    isis_adjacency_p2p_s *isis_adjacency_p2p;
    isis_adjacency_s     *isis_adjacency[ISIS_LEVELS];
    ldp_adjacency_s      *ldp_adjacency;
    ospf_interface_s     *ospf_interface;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        uint64_t bytes_tx;
        uint64_t bytes_rx;

        uint64_t unknown;
        uint64_t mc_tx;
        
        /* Packet Stats */
        uint32_t arp_tx;
        uint32_t arp_rx;
        uint32_t icmp_tx;
        uint32_t icmp_rx;
        uint32_t icmpv6_tx;
        uint32_t icmpv6_rx;
        uint32_t icmpv6_rs_timeout;
        uint32_t tcp_tx;
        uint32_t tcp_rx;

        uint32_t ipv4_fragmented_rx;

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

        uint32_t l2tp_control_rx;
        uint32_t l2tp_control_rx_dup; /* duplicate */
        uint32_t l2tp_control_rx_ooo; /* out of order */
        uint32_t l2tp_control_rx_nf;  /* session not found */
        uint32_t l2tp_control_tx;
        uint32_t l2tp_control_retry;
        uint64_t l2tp_data_rx;
        uint64_t l2tp_data_tx;

        uint64_t li_rx;

        uint32_t isis_rx;
        uint32_t isis_tx;
        uint32_t isis_rx_error;

        uint32_t ospf_tx;
        uint32_t ospf_rx;
        uint32_t ospf_rx_error;

        uint32_t ldp_udp_rx;
        uint32_t ldp_udp_tx;
        uint32_t ldp_udp_rx_error;

        /* Rate Stats */

        bbl_rate_s rate_packets_tx;
        bbl_rate_s rate_packets_rx;
        bbl_rate_s rate_bytes_tx;
        bbl_rate_s rate_bytes_rx;
        bbl_rate_s rate_mc_tx;
        bbl_rate_s rate_session_ipv4_tx;
        bbl_rate_s rate_session_ipv4_rx;
        bbl_rate_s rate_session_ipv6_tx;
        bbl_rate_s rate_session_ipv6_rx;
        bbl_rate_s rate_session_ipv6pd_tx;
        bbl_rate_s rate_session_ipv6pd_rx;
        bbl_rate_s rate_stream_tx;
        bbl_rate_s rate_stream_rx;
        bbl_rate_s rate_l2tp_data_rx;
        bbl_rate_s rate_l2tp_data_tx;
        bbl_rate_s rate_li_rx;
    } stats;

    struct timer_ *rate_job;

    CIRCLEQ_ENTRY(bbl_network_interface_) network_interface_qnode;
    CIRCLEQ_HEAD(l2tp_tx_, bbl_l2tp_queue_ ) l2tp_tx_qhead; /* list of messages that want to transmit */

} bbl_network_interface_s;

bool
bbl_network_interfaces_add();

bbl_network_interface_s*
bbl_network_interface_get(char *interface_name);

void
bbl_network_rx_handler(bbl_network_interface_s *interface, 
                       bbl_ethernet_header_s *eth);

int
bbl_network_ctrl_interfaces(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif
