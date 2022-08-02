/*
 * BNG Blaster (BBL) - Sessions
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_SESSIONS_H__
#define __BBL_SESSIONS_H__

typedef struct bbl_igmp_group_
{
    uint8_t  state;
    uint8_t  robustness_count;
    bool     send;
    bool     zapping;
    bool     zapping_result;
    uint32_t group;
    uint32_t source[IGMP_MAX_SOURCES];
    uint64_t packets;
    uint64_t loss;
    struct timespec join_tx_time;
    struct timespec first_mc_rx_time;
    struct timespec leave_tx_time;
    struct timespec last_mc_rx_time;
} bbl_igmp_group_s;

typedef struct vlan_session_key_ {
    uint32_t ifindex;
    uint16_t outer_vlan_id;
    uint16_t inner_vlan_id;
} __attribute__ ((__packed__)) vlan_session_key_t;

/*
 * Client Session to a BNG device
 */
typedef struct bbl_session_
{
    uint32_t session_id; /* BNG Blaster internal session identifier */

    session_state_t session_state;
    uint32_t send_requests;
    uint32_t network_send_requests;

    CIRCLEQ_ENTRY(bbl_session_) session_tx_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_idle_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_teardown_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_network_tx_qnode;

    struct bbl_interface_ *interface; /* where this session is attached to */
    struct bbl_interface_ *network_interface; /* selected network interface */
    struct bbl_access_config_ *access_config;

    uint8_t *write_buf; /* pointer to the slot in the tx_ring */
    uint16_t write_idx;

    /* Session timer */
    struct timer_ *timer_arp;
    struct timer_ *timer_padi;
    struct timer_ *timer_padr;
    struct timer_ *timer_lcp;
    struct timer_ *timer_lcp_echo;
    struct timer_ *timer_auth;
    struct timer_ *timer_ipcp;
    struct timer_ *timer_ip6cp;
    struct timer_ *timer_dhcp_retry;
    struct timer_ *timer_dhcp_t1;
    struct timer_ *timer_dhcp_t2;
    struct timer_ *timer_dhcpv6;
    struct timer_ *timer_dhcpv6_t1;
    struct timer_ *timer_dhcpv6_t2;
    struct timer_ *timer_igmp;
    struct timer_ *timer_zapping;
    struct timer_ *timer_icmpv6;
    struct timer_ *timer_session;
    struct timer_ *timer_session_traffic_ipv4;
    struct timer_ *timer_session_traffic_ipv6;
    struct timer_ *timer_session_traffic_ipv6pd;
    struct timer_ *timer_rate;
    struct timer_ *timer_cfm_cc;
    struct timer_ *timer_reconnect;
    struct timer_ *timer_monkey;

    bbl_access_type_t access_type;

    uint16_t stream_group_id;
    void *stream;
    bool stream_traffic;

    struct {
        uint32_t ifindex;
        uint16_t outer_vlan_id;
        uint16_t inner_vlan_id;
    } vlan_key;

    uint16_t access_third_vlan;

    /* Set to true if session is tunnelled via L2TP. */
    bool l2tp;
    bbl_l2tp_session_t *l2tp_session;

    /* Set to true if session is connected to
     * BNG Blaster A10NSP Interface */
    bbl_a10nsp_session_t *a10nsp_session;

    /* Authentication */
    char *username;
    char *password;

    /* Optional reconnect delay in seconds */
    uint32_t reconnect_delay;

    uint8_t chap_identifier;
    uint8_t chap_response[CHALLENGE_LEN];

    /* Access Line */
    char *agent_circuit_id;
    char *agent_remote_id;
    uint32_t rate_up;
    uint32_t rate_down;
    uint32_t dsl_type;

    void *access_line_profile;

    /* Ethernet */
    uint8_t server_mac[ETH_ADDR_LEN];
    uint8_t client_mac[ETH_ADDR_LEN];

    /* CFM */
    bool cfm_cc;
    bool cfm_rdi;
    uint32_t cfm_seq;
    uint8_t cfm_level;
    uint16_t cfm_ma_id;
    char *cfm_ma_name;

    /* PPPoE */
    uint16_t pppoe_session_id;
    uint8_t *pppoe_ac_cookie;
    uint16_t pppoe_ac_cookie_len;
    uint8_t *pppoe_service_name;
    uint16_t pppoe_service_name_len;
    uint64_t pppoe_host_uniq;

    /* LCP */
    ppp_state_t lcp_state;
    uint8_t     lcp_response_code;
    uint8_t     lcp_request_code;
    uint8_t     lcp_options[PPP_OPTIONS_BUFFER];
    uint16_t    lcp_options_len;
    uint8_t     lcp_identifier;
    uint8_t     lcp_peer_identifier;
    uint8_t     lcp_retries;
    uint32_t    magic_number;
    uint32_t    peer_magic_number;
    uint16_t    mru;
    uint16_t    peer_mru;
    uint16_t    auth_protocol; /* PAP or CHAP */
    uint8_t     auth_retries;

    char       *reply_message;
    char       *connections_status_message;

    /* IPCP */
    ppp_state_t ipcp_state;
    uint8_t     ipcp_response_code;
    uint8_t     ipcp_request_code;
    uint8_t     ipcp_options[PPP_OPTIONS_BUFFER];
    uint16_t    ipcp_options_len;
    uint8_t     ipcp_identifier;
    uint8_t     ipcp_peer_identifier;
    uint8_t     ipcp_retries;

    /* IP6CP */
    ppp_state_t ip6cp_state;
    uint8_t     ip6cp_response_code;
    uint8_t     ip6cp_request_code;
    uint8_t     ip6cp_options[PPP_OPTIONS_BUFFER];
    uint16_t    ip6cp_options_len;
    uint8_t     ip6cp_identifier;
    uint8_t     ip6cp_peer_identifier;
    uint8_t     ip6cp_retries;
    uint64_t    ip6cp_ipv6_identifier;
    uint64_t    ip6cp_ipv6_peer_identifier;

    /* IPv4 */
    bool        arp_resolved;
    uint32_t    ip_address;
    uint32_t    ip_netmask;
    uint32_t    peer_ip_address;
    uint32_t    dns1;
    uint32_t    dns2;

    /* IPv6 */
    bool        icmpv6_nd_resolved;
    bool        icmpv6_ra_received;
    ipv6addr_t  link_local_ipv6_address;
    ipv6_prefix ipv6_prefix;
    ipv6addr_t  ipv6_address;
    ipv6_prefix delegated_ipv6_prefix;
    ipv6addr_t  delegated_ipv6_address;
    ipv6addr_t  ipv6_dns1; /* DNS learned via RA */
    ipv6addr_t  ipv6_dns2; /* DNS learned via RA */

    /* DHCP */
    dhcp_state_t dhcp_state;
    bool dhcp_requested;
    bool dhcp_established;
    uint8_t  dhcp_retry;
    uint32_t dhcp_xid;
    uint32_t dhcp_address;
    uint32_t dhcp_lease_time;
    uint32_t dhcp_t1;
    uint32_t dhcp_t2;
    uint32_t dhcp_server;
    uint32_t dhcp_server_identifier;
    uint8_t  dhcp_server_mac[ETH_ADDR_LEN];
    struct timespec dhcp_lease_timestamp;
    struct timespec dhcp_request_timestamp;
    char *dhcp_client_identifier;
    char *dhcp_host_name;
    char *dhcp_domain_name;

    /* DHCPv6 */
    dhcp_state_t dhcpv6_state;
    bool dhcpv6_requested;
    bool dhcpv6_established;
    uint8_t dhcpv6_retry;
    uint8_t dhcpv6_duid[DUID_LEN];
    uint8_t dhcpv6_server_duid[DHCPV6_BUFFER];
    uint8_t dhcpv6_server_duid_len;
    ipv6addr_t dhcpv6_dns1;
    ipv6addr_t dhcpv6_dns2;
    uint32_t dhcpv6_xid;
    uint32_t dhcpv6_lease_time;
    uint32_t dhcpv6_t1;
    uint32_t dhcpv6_t2;
    uint32_t dhcpv6_ia_na_iaid;
    uint32_t dhcpv6_ia_pd_iaid;
    uint8_t dhcpv6_ia_na_option[DHCPV6_BUFFER];
    uint8_t dhcpv6_ia_na_option_len;
    uint8_t dhcpv6_ia_pd_option[DHCPV6_BUFFER];
    uint8_t dhcpv6_ia_pd_option_len;
    struct timespec dhcpv6_lease_timestamp;
    struct timespec dhcpv6_request_timestamp;

    /* IGMP */
    bool     igmp_autostart;
    uint8_t  igmp_version;
    uint8_t  igmp_robustness;
    bbl_igmp_group_s igmp_groups[IGMP_MAX_GROUPS];

    /* IGMP Zapping */
    bbl_igmp_group_s *zapping_joined_group;
    bbl_igmp_group_s *zapping_leaved_group;
    uint32_t zapping_group_max;
    uint8_t  zapping_count;
    uint64_t zapping_join_delay_sum;
    uint32_t zapping_join_count;
    uint64_t zapping_leave_delay_sum;
    uint32_t zapping_leave_count;
    struct timespec zapping_view_start_time;

    /* Multicast Traffic */
    uint64_t mc_rx_last_seq;

    /* Session Traffic */
    bool session_traffic;

    uint8_t session_traffic_flows;
    uint8_t session_traffic_flows_verified;

    uint64_t access_ipv4_tx_flow_id;
    uint64_t access_ipv4_tx_seq;
    uint8_t *access_ipv4_tx_packet_template;
    uint8_t  access_ipv4_tx_packet_len;
    uint64_t access_ipv4_rx_first_seq;
    uint64_t access_ipv4_rx_last_seq;

    uint64_t network_ipv4_tx_flow_id;
    uint64_t network_ipv4_tx_seq;
    uint8_t *network_ipv4_tx_packet_template;
    uint8_t  network_ipv4_tx_packet_len;
    uint64_t network_ipv4_rx_first_seq;
    uint64_t network_ipv4_rx_last_seq;

    uint64_t access_ipv6_tx_flow_id;
    uint64_t access_ipv6_tx_seq;
    uint8_t *access_ipv6_tx_packet_template;
    uint8_t  access_ipv6_tx_packet_len;
    uint64_t access_ipv6_rx_first_seq;
    uint64_t access_ipv6_rx_last_seq;

    uint64_t network_ipv6_tx_flow_id;
    uint64_t network_ipv6_tx_seq;
    uint8_t *network_ipv6_tx_packet_template;
    uint8_t  network_ipv6_tx_packet_len;
    uint64_t network_ipv6_rx_first_seq;
    uint64_t network_ipv6_rx_last_seq;

    uint64_t access_ipv6pd_tx_flow_id;
    uint64_t access_ipv6pd_tx_seq;
    uint8_t *access_ipv6pd_tx_packet_template;
    uint8_t  access_ipv6pd_tx_packet_len;
    uint64_t access_ipv6pd_rx_first_seq;
    uint64_t access_ipv6pd_rx_last_seq;

    uint64_t network_ipv6pd_tx_flow_id;
    uint64_t network_ipv6pd_tx_seq;
    uint8_t *network_ipv6pd_tx_packet_template;
    uint8_t  network_ipv6pd_tx_packet_len;
    uint64_t network_ipv6pd_rx_first_seq;
    uint64_t network_ipv6pd_rx_last_seq;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        bbl_rate_s rate_packets_tx;
        bbl_rate_s rate_packets_rx;
        uint64_t bytes_tx;
        uint64_t bytes_rx;
        bbl_rate_s rate_bytes_tx;
        bbl_rate_s rate_bytes_rx;

        /* Accounting relevant traffic (without control). */
        uint64_t accounting_packets_tx;
        uint64_t accounting_packets_rx;
        uint64_t accounting_bytes_tx;
        uint64_t accounting_bytes_rx;

        uint32_t igmp_rx;
        uint32_t igmp_tx;

        uint32_t min_join_delay;
        uint32_t avg_join_delay;
        uint32_t max_join_delay;
        uint32_t join_delay_violations;
        uint32_t join_delay_violations_125ms;
        uint32_t join_delay_violations_250ms;
        uint32_t join_delay_violations_500ms;
        uint32_t join_delay_violations_1s;
        uint32_t join_delay_violations_2s;

        uint32_t min_leave_delay;
        uint32_t avg_leave_delay;
        uint32_t max_leave_delay;

        /* This value counts all MC packets for old
         * group received after first packet for new
         * group received. */
        uint32_t mc_old_rx_after_first_new;
        uint32_t mc_rx;
        uint32_t mc_loss; /* packet loss */
        uint32_t mc_not_received;
        uint32_t arp_rx;
        uint32_t arp_tx;
        uint32_t icmp_rx;
        uint32_t icmp_tx;
        uint32_t icmpv6_rx;
        uint32_t icmpv6_tx;
        uint32_t ipv4_fragmented_rx;

        uint32_t dhcp_tx;
        uint32_t dhcp_rx;
        uint32_t dhcp_tx_discover;
        uint32_t dhcp_rx_offer;
        uint32_t dhcp_tx_request;
        uint32_t dhcp_rx_ack;
        uint32_t dhcp_rx_nak;
        uint32_t dhcp_tx_release;

        uint32_t dhcpv6_tx;
        uint32_t dhcpv6_rx;
        uint32_t dhcpv6_tx_solicit;
        uint32_t dhcpv6_rx_advertise;
        uint32_t dhcpv6_tx_request;
        uint32_t dhcpv6_rx_reply;
        uint32_t dhcpv6_tx_renew;
        uint32_t dhcpv6_tx_release;

        uint64_t access_ipv4_rx;
        uint64_t access_ipv4_tx;
        uint64_t access_ipv4_loss;
        uint64_t network_ipv4_rx;
        uint64_t network_ipv4_tx;
        uint64_t network_ipv4_loss;

        uint64_t access_ipv6_rx;
        uint64_t access_ipv6_tx;
        uint64_t access_ipv6_loss;
        uint64_t network_ipv6_rx;
        uint64_t network_ipv6_tx;
        uint64_t network_ipv6_loss;

        uint64_t access_ipv6pd_rx;
        uint64_t access_ipv6pd_tx;
        uint64_t access_ipv6pd_loss;
        uint64_t network_ipv6pd_rx;
        uint64_t network_ipv6pd_tx;
        uint64_t network_ipv6pd_loss;

        uint32_t flapped; /* flap counter */
    } stats;

} bbl_session_s;

const char *
session_state_string(uint32_t state);

void
bbl_session_tx_qnode_insert(struct bbl_session_ *session);

void
bbl_session_tx_qnode_remove(struct bbl_session_ *session);

void
bbl_session_network_tx_qnode_insert(struct bbl_session_ *session);

void
bbl_session_network_tx_qnode_remove(struct bbl_session_ *session);

void
bbl_session_ncp_open(bbl_session_s *session, bool ipcp);

void
bbl_session_ncp_close(bbl_session_s *session, bool ipcp);

bbl_session_s *
bbl_session_get(bbl_ctx_s *ctx, uint32_t session_id);

void
bbl_session_free(bbl_session_s *session);

void
bbl_session_reset(bbl_session_s *session);

void
bbl_session_update_state(bbl_ctx_s *ctx, bbl_session_s *session, session_state_t state);

void
bbl_session_clear(bbl_ctx_s *ctx, bbl_session_s *session);

bool
bbl_sessions_init(bbl_ctx_s *ctx);

json_t *
bbl_session_json(bbl_session_s *session);

#endif