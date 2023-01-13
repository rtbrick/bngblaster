/*
 * BNG Blaster (BBL) - Global Context
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_CONTEXT_H__
#define __BBL_CONTEXT_H__

typedef struct bbl_secondary_ip_
{
    uint32_t ip;
    void *next;
} bbl_secondary_ip_s;

typedef struct bbl_secondary_ip6_
{
    ipv6addr_t ip;
    void *next;
} bbl_secondary_ip6_s;

/*
 * BBL context. Top level data structure.
 */
typedef struct bbl_ctx_
{
    struct timer_root_ timer_root; /* Root for our timers */
    struct timer_ *control_timer;
    struct timer_ *smear_timer;
    struct timer_ *stats_timer;
    struct timer_ *keyboard_timer;

    struct timer_ *tcp_timer;

    struct timespec timestamp_start;
    struct timespec timestamp_stop;
    struct timespec timestamp_resolved;
    struct timespec timestamp_established;

    uint32_t sessions;
    uint32_t sessions_pppoe;
    uint32_t sessions_ipoe;
    uint32_t sessions_established;
    uint32_t sessions_established_max;
    uint32_t sessions_outstanding;
    uint32_t sessions_terminated;
    uint32_t sessions_flapped;

    uint32_t dhcp_requested;
    uint32_t dhcp_established;
    uint32_t dhcp_established_max;
    uint32_t dhcpv6_requested;
    uint32_t dhcpv6_established;
    uint32_t dhcpv6_established_max;

    uint32_t l2tp_sessions;
    uint32_t l2tp_sessions_max;
    uint32_t l2tp_tunnels;
    uint32_t l2tp_tunnels_max;
    uint32_t l2tp_tunnels_established;
    uint32_t l2tp_tunnels_established_max;

    uint32_t routing_sessions;

    CIRCLEQ_HEAD(sessions_idle_, bbl_session_ ) sessions_idle_qhead;
    CIRCLEQ_HEAD(sessions_teardown_, bbl_session_ ) sessions_teardown_qhead;
    CIRCLEQ_HEAD(interface_, bbl_interface_ ) interface_qhead; /* list of interfaces */
    CIRCLEQ_HEAD(lag_, bbl_lag_ ) lag_qhead; /* list of LAG groups */
    CIRCLEQ_HEAD(access_interface_, bbl_access_interface_ ) access_interface_qhead; /* list of interfaces */
    CIRCLEQ_HEAD(network_interface_, bbl_network_interface_ ) network_interface_qhead; /* list of interfaces */
    CIRCLEQ_HEAD(a10nsp_interface_, bbl_a10nsp_interface_ ) a10nsp_interface_qhead; /* list of interfaces */

    bbl_session_s *session_list; /* list of sessions */

    dict *vlan_session_dict; /* hashtable for 1:1 vlan sessions */
    dict *l2tp_session_dict; /* hashtable for L2TP sessions */
    dict *li_flow_dict; /* hashtable for LI flows */
    dict *stream_flow_dict; /* hashtable for traffic stream flows */

    bbl_stream_group_s *stream_groups;

    uint16_t next_tunnel_id;

    uint64_t flow_id;

    char *ctrl_socket_path;
    bbl_ctrl_thread_s *ctrl_thread;
    io_thread_s *io_threads; /* single linked list of threads */

    bool tcp;
    bool dpdk;

    bgp_session_s *bgp_sessions;
    bgp_raw_update_s *bgp_raw_updates;
    isis_instance_s *isis_instances;
    ldp_instance_s *ldp_instances;
    ldp_raw_update_s *ldp_raw_updates;

    /* Scratchpad memory */
    uint8_t *sp;

    /* PCAP */
    struct {
        int fd;
        char *filename;
        uint8_t *write_buf;
        uint32_t write_idx;
        bool wrote_header;
        bool include_streams;
        uint32_t index; /* next to be allocated interface index */
    } pcap;

    /* Global Stats */
    struct {
        uint32_t setup_time; /* Time between first session started and last session established */
        double cps; /* PPPoE setup rate in calls per second */
        double cps_min;
        double cps_avg;
        double cps_max;
        double cps_sum;
        double cps_count;
        struct timespec first_session_tx;
        struct timespec last_session_established;
        uint32_t sessions_established_max;
        uint32_t session_traffic_flows;
        uint32_t session_traffic_flows_verified;
        uint32_t stream_traffic_flows;
        uint32_t stream_traffic_flows_verified;
        uint32_t multicast_traffic_flows;
        uint32_t multicast_traffic_flows_verified;
    } stats;

    endpoint_state_t multicast_endpoint;
    bool zapping;

    /* Config options */
    struct {
        bool interface_lock_force;
        uint8_t mac_modifier;

        io_mode_t io_mode;

        uint16_t io_slots;

        bool qdisc_bypass;

        uint64_t tx_interval; /* TX interval in nsec */
        uint64_t rx_interval; /* RX interval in nsec */

        uint8_t tx_threads;
        uint8_t rx_threads;

        char *json_report_filename;
        bool json_report_sessions; /* Include sessions */
        bool json_report_streams; /* Include streams */

        bbl_secondary_ip_s *secondary_ip_addresses;
        bbl_secondary_ip6_s *secondary_ip6_addresses;

        /* LAG */
        bbl_lag_config_s *lag_config;

        /* Links */
        bbl_link_config_s *link_config;

        /* Access Interfaces  */
        bbl_access_config_s *access_config;

        /* Network Interfaces */
        bbl_network_config_s *network_config;

        /* A10NSP Interfaces */
        bbl_a10nsp_config_s *a10nsp_config;

        /* Access Line Profiles */
        void *access_line_profile;

        /* Traffic Streams */
        bbl_stream_config_s *stream_config;
        bbl_stream_config_s *stream_config_multicast;
        bbl_stream_config_s *stream_config_session_ipv4_up;
        bbl_stream_config_s *stream_config_session_ipv4_down;
        bbl_stream_config_s *stream_config_session_ipv6_up;
        bbl_stream_config_s *stream_config_session_ipv6_down;
        bbl_stream_config_s *stream_config_session_ipv6pd_up;
        bbl_stream_config_s *stream_config_session_ipv6pd_down;

        /* BGP Instances */
        bgp_config_s *bgp_config;

        /* ISIS Instances */
        isis_config_s *isis_config;

        /* LDP Instances */
        ldp_config_s *ldp_config;

        /* Global Session Settings */
        uint32_t sessions;
        uint32_t sessions_max_outstanding;
        uint16_t sessions_start_rate;
        uint16_t sessions_stop_rate;
        uint16_t sessions_start_delay;
        bool sessions_reconnect;
        bool sessions_autostart;
        bool monkey_autostart;
        bool iterate_outer_vlan;

        /* Static */
        uint32_t static_ip;
        uint32_t static_ip_iter;
        uint32_t static_gateway;
        uint32_t static_gateway_iter;

        /* Authentication */
        const char *username;
        const char *password;

        /* Access Line */
        const char *agent_remote_id;
        const char *agent_circuit_id;
        uint32_t rate_up;
        uint32_t rate_down;
        uint32_t dsl_type;

        /* PPPoE */
        uint32_t pppoe_session_time;
        uint16_t pppoe_discovery_timeout;
        uint16_t pppoe_discovery_retry;
        uint8_t  pppoe_vlan_priority;
        char    *pppoe_service_name;
        bool     pppoe_reconnect;
        bool     pppoe_host_uniq;

        /* PPP */
        uint16_t ppp_mru;

        /* LCP */
        uint16_t lcp_conf_request_timeout;
        uint16_t lcp_conf_request_retry;
        uint16_t lcp_keepalive_interval;
        uint16_t lcp_keepalive_retry;
        uint16_t lcp_start_delay;
        bool lcp_vendor_ignore;
        bool lcp_connection_status_message;

        /* Authentication */
        uint16_t authentication_timeout;
        uint16_t authentication_retry;
        uint16_t authentication_protocol;

        /* IPCP */
        bool ipcp_enable;
        bool ipcp_request_ip;
        bool ipcp_request_dns1;
        bool ipcp_request_dns2;
        uint16_t ipcp_conf_request_timeout;
        uint16_t ipcp_conf_request_retry;

        /* IP6CP */
        bool ip6cp_enable;
        uint16_t ip6cp_conf_request_timeout;
        uint16_t ip6cp_conf_request_retry;

        /* IPv4 (IPoE) */
        bool ipoe_ipv4_enable;

        /* IPv6 (IPoE) */
        bool ipoe_ipv6_enable;

        /* ARP (IPoE) */
        uint16_t arp_timeout;
        uint16_t arp_interval;

        /* DHCP */
        bool dhcp_enable;
        bool dhcp_broadcast;
        bool dhcp_access_line;
        uint16_t dhcp_timeout;
        uint8_t dhcp_retry;
        uint8_t dhcp_release_interval;
        uint8_t dhcp_release_retry;
        uint8_t dhcp_tos;
        uint8_t dhcp_vlan_priority;

        /* DHCPv6 */
        bool dhcpv6_enable;
        bool dhcpv6_rapid_commit;
        bool dhcpv6_access_line;
        uint16_t dhcpv6_timeout;
        uint8_t dhcpv6_retry;
        uint8_t dhcpv6_tc;
        uint8_t dhcpv6_vlan_priority;

        /* IGMP */
        bool igmp_autostart;
        uint8_t  igmp_version;
        uint8_t  igmp_combined_leave_join;
        uint16_t igmp_start_delay;
        uint32_t igmp_group;
        uint32_t igmp_group_iter;
        uint32_t igmp_source;
        uint16_t igmp_group_count;
        uint16_t igmp_zap_interval;
        uint16_t igmp_zap_view_duration;
        uint16_t igmp_zap_count;
        uint16_t igmp_zap_wait;
        uint16_t igmp_max_join_delay;
        uint16_t igmp_robustness_interval;

        /* Multicast Traffic */
        bool send_multicast_traffic;
        bool multicast_traffic_autostart;
        uint8_t multicast_traffic_tos;
        uint16_t multicast_traffic_len;
        uint16_t multicast_traffic_pps;
        char *multicast_traffic_network_interface;

        /* Global Traffic */
        bool traffic_autostart;
        bool traffic_stop_verified;
        bool stream_rate_calc; /* Enable/disable stream rate calculation */
        uint8_t stream_max_burst; /* Limit the max packets per TX interval */

        /* Session Traffic */
        bool session_traffic_autostart;
        uint16_t    session_traffic_ipv4_pps;
        uint32_t    session_traffic_ipv4_label;
        ipv4addr_t  session_traffic_ipv4_address;
        uint16_t    session_traffic_ipv6_pps;
        uint32_t    session_traffic_ipv6_label;
        ipv6addr_t  session_traffic_ipv6_address;
        uint16_t    session_traffic_ipv6pd_pps;

        /* L2TP Server Config (LNS) */
        bbl_l2tp_server_s *l2tp_server;
    } config;
} bbl_ctx_s;

int
bbl_compare_key32 (void *key1, void *key2);

uint32_t
bbl_key32_hash(const void* k);

int
bbl_compare_key64(void *key1, void *key2);

uint32_t
bbl_key64_hash(const void* k);

bool
bbl_ctx_add();

void
bbl_ctx_del();

#endif