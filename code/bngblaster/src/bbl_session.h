/*
 * BNG Blaster (BBL) - Sessions
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_SESSIONS_H__
#define __BBL_SESSIONS_H__

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
    uint16_t session_group_id;

    session_state_t session_state;
    uint32_t send_requests;
    uint32_t version;

    CIRCLEQ_ENTRY(bbl_session_) session_idle_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_teardown_qnode;

    CIRCLEQ_ENTRY(bbl_session_) session_tx_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_network_tx_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_a10nsp_tx_qnode;

    bbl_access_config_s *access_config;
    bbl_access_interface_s *access_interface; /* where this session is attached to */
    bbl_network_interface_s *network_interface; /* selected network interface */

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
    struct timer_ *timer_rate;
    struct timer_ *timer_cfm_cc;
    struct timer_ *timer_reconnect;
    struct timer_ *timer_monkey;
    struct timer_ *timer_tun;

    access_type_t access_type;

    struct {
        endpoint_state_t ipv4;
        endpoint_state_t ipv6;
        endpoint_state_t ipv6pd;
    } endpoint;

    struct {
        uint32_t ifindex;
        uint16_t outer_vlan_id;
        uint16_t inner_vlan_id;
    } vlan_key;

    uint16_t access_third_vlan;

    int tun_fd;
    char *tun_dev;

    /* Set to true if session is tunnelled via L2TP. */
    bool l2tp;
    bbl_l2tp_session_s *l2tp_session;

    /* Set to true if session is connected to
     * BNG Blaster A10NSP Interface */
    bbl_a10nsp_session_s *a10nsp_session;
    bbl_a10nsp_interface_s *a10nsp_interface; /* a10nsp interface */

    /* Authentication */
    char *username;
    char *password;

    /* Optional reconnect delay in seconds */
    uint32_t reconnect_delay;
    bool reconnect_disabled;

    uint8_t chap_identifier;
    uint8_t chap_response[CHALLENGE_LEN];

    /* Access Line */
    char *agent_circuit_id;
    char *agent_remote_id;
    char *access_aggregation_circuit_id;
    uint32_t rate_up;
    uint32_t rate_down;
    uint32_t dsl_type;

    void *access_line_profile;

    /* ARP */
    bbl_arp_client_s *arp_client;

    /* ICMP */
    bbl_icmp_client_s *icmp_client;

    /* TCP */
    bbl_http_client_s *http_client;
    struct netif netif; /* LwIP interface */
    
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
    uint8_t  pppoe_retries;

    /* LCP */
    ppp_state_t lcp_state;
    uint8_t     lcp_response_code;
    uint8_t     lcp_request_code;
    uint8_t     lcp_options[PPP_OPTIONS_BUFFER];
    uint16_t    lcp_options_len;
    uint8_t     lcp_identifier;
    uint8_t     lcp_peer_identifier;
    uint8_t     lcp_retries;
    bool        lcp_echo_request_ignore;
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
    bool        ipcp_request_dns1;
    bool        ipcp_request_dns2;

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

    struct {
        uint16_t group_id;
        bbl_stream_s *head;
    } streams;

    struct {
        uint8_t flows;
        uint8_t flows_verified;
        bbl_stream_s *ipv4_up;
        bbl_stream_s *ipv4_down;
        bbl_stream_s *ipv6_up;
        bbl_stream_s *ipv6_down;
        bbl_stream_s *ipv6pd_up;
        bbl_stream_s *ipv6pd_down;
    } session_traffic;

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
bbl_session_ncp_open(bbl_session_s *session, bool ipcp);

void
bbl_session_ncp_close(bbl_session_s *session, bool ipcp);

bbl_session_s *
bbl_session_get(uint32_t session_id);

void
bbl_session_free(bbl_session_s *session);

void
bbl_session_update_state(bbl_session_s *session, session_state_t state);

void
bbl_session_clear(bbl_session_s *session);

bool
bbl_sessions_init();

json_t *
bbl_session_json(bbl_session_s *session);

int
bbl_session_ctrl_pending(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
bbl_session_ctrl_counters(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

int
bbl_session_ctrl_info(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_session_ctrl_stop(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_restart(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_start(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_ipcp_open(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_ipcp_close(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_ip6cp_open(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_ip6cp_close(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_lcp_echo_request_ignore(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_lcp_echo_request_accept(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_traffic_start(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_traffic_stop(int fd, uint32_t session_id, json_t *arguments);

int
bbl_session_ctrl_traffic_reset(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments);

int
bbl_session_ctrl_traffic_stats(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif