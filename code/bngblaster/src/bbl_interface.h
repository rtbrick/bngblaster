/*
 * BNG Blaster (BBL) - Interfaces
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_INTERFACE_H__
#define __BBL_INTERFACE_H__

typedef struct bbl_interface_
{
    CIRCLEQ_ENTRY(bbl_interface_) interface_qnode;
    struct bbl_ctx_ *ctx; /* parent */
    char *name; /* interface name */

    bbl_interface_type_t type;

    struct timer_ *timer_arp;
    struct timer_ *timer_nd;
    struct timer_ *timer_isis_hello;

    struct {
        bbl_io_mode_t mode;

        int fd_tx;
        int fd_rx;

        struct tpacket_req req_tx;
        struct tpacket_req req_rx;
        struct sockaddr_ll addr;

        uint8_t *rx_buf; /* RX buffer */
        uint16_t rx_len;
        uint8_t *tx_buf; /* TX buffer */
        uint16_t tx_len;

        uint8_t *ring_tx; /* TX ring buffer */
        uint8_t *ring_rx; /* RX ring buffer */
        uint16_t cursor_tx; /* slot # inside the ring buffer */
        uint16_t cursor_rx; /* slot # inside the ring buffer */

        bool pollout;
        bool ctrl; /* control traffic */

#ifdef BNGBLASTER_NETMAP
        struct nm_desc *port;
#endif
    } io;

    struct {
        bbl_send_slot_t *ring;
        uint16_t size;  /* number of send slots */
        uint16_t read;  /* current read slot */
        uint16_t write; /* current write slot */
        uint16_t next;  /* next write slot */
        uint32_t full; 
    } send;

    uint32_t ifindex; /* interface index */
    uint32_t pcap_index; /* interface index for packet captures */

    uint32_t send_requests;
    bool     arp_resolved;

    uint16_t vlan;
    bool     qinq; /* use ethertype 0x8818 */
    uint8_t  mac[ETH_ADDR_LEN];
    uint8_t  gateway_mac[ETH_ADDR_LEN];

    ipv4_prefix ip;
    ipv4addr_t  gateway;

    ipv6_prefix ip6; /* global IPv6 address */
    ipv6addr_t  ip6_ll; /* link-local IPv6 address */
    ipv6addr_t  gateway6;
    ipv6addr_t  gateway6_solicited_node_multicast;

    bool icmpv6_nd_resolved;
    bool gateway_resolve_wait;

    uint8_t *mc_packets;
    uint16_t mc_packet_len;
    uint64_t mc_packet_seq;
    uint16_t mc_packet_cursor;

    struct netif netif; /* LwIP network interface */

    isis_adjacency_p2p_t *isis_adjacency_p2p;
    isis_adjacency_t     *isis_adjacency[ISIS_LEVELS];

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        uint64_t bytes_tx;
        uint64_t bytes_rx;
        uint64_t packets_rx_drop_unknown;
        uint64_t packets_rx_drop_decode_error;
        uint64_t sendto_failed;
        uint64_t no_tx_buffer;
        uint64_t poll_tx;
        uint64_t poll_rx;
        uint64_t encode_errors;

        uint64_t mc_tx;
        bbl_rate_s rate_mc_tx;
        uint64_t mc_rx;
        bbl_rate_s rate_mc_rx;
        uint64_t mc_loss;

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
        bbl_rate_s rate_l2tp_data_rx;
        bbl_rate_s rate_l2tp_data_tx;
        bbl_rate_s rate_li_rx;
    } stats;

    struct timer_ *tx_job;
    struct timer_ *rx_job;
    struct timer_ *rate_job;

    struct timespec tx_timestamp; /* user space timestamps */
    struct timespec rx_timestamp; /* user space timestamps */

    CIRCLEQ_HEAD(session_tx_, bbl_session_ ) session_tx_qhead; /* list of sessions that want to transmit */
    CIRCLEQ_HEAD(l2tp_tx_, bbl_l2tp_queue_ ) l2tp_tx_qhead; /* list of messages that want to transmit */
} bbl_interface_s;

void
bbl_interface_unlock_all(bbl_ctx_s *ctx);

bool
bbl_add_interfaces(bbl_ctx_s *ctx);

bbl_interface_s *
bbl_get_network_interface(bbl_ctx_s *ctx, char *interface_name);

bbl_interface_s *
bbl_get_a10nsp_interface(bbl_ctx_s *ctx, char *interface_name);

#endif