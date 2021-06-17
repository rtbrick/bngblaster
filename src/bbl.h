/*
 * BNG BLaster (BBL), a tool for scale testing the control plane of BNG and BRAS devices.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_H__
#define __BBL_H__

#include "config.h"

#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <signal.h>
#include <math.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>

#define NCURSES_NOMACROS 1
#include <curses.h>

/* Experimental NETMAP Support */
#ifdef BNGBLASTER_NETMAP
#define LIBNETMAP_NOTHREADSAFE
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif

#include "libdict/dict.h"
#include "bbl_logging.h"
#include "bbl_timer.h"
#include "bbl_protocols.h"
#include "bbl_utils.h"
#include "bbl_l2tp.h"
#include "bbl_li.h"

#define IO_BUFFER_LEN               2048
#define SCRATCHPAD_LEN              2048
#define CHALLENGE_LEN               16

/* Access Interface */
#define BBL_SEND_DISCOVERY          0x00000001
#define BBL_SEND_LCP_RESPONSE       0x00000002
#define BBL_SEND_LCP_REQUEST        0x00000004
#define BBL_SEND_PAP_REQUEST        0x00000008
#define BBL_SEND_CHAP_RESPONSE      0x00000010
#define BBL_SEND_IPCP_RESPONSE      0x00000020
#define BBL_SEND_IPCP_REQUEST       0x00000040
#define BBL_SEND_IP6CP_REQUEST      0x00000080
#define BBL_SEND_IP6CP_RESPONSE     0x00000100
#define BBL_SEND_ICMPV6_RS          0x00000200
#define BBL_SEND_DHCPV6_REQUEST     0x00000400
#define BBL_SEND_IGMP               0x00000800
#define BBL_SEND_ICMP_REPLY         0x00001000
#define BBL_SEND_SESSION_IPV4       0x00002000
#define BBL_SEND_SESSION_IPV6       0x00004000
#define BBL_SEND_SESSION_IPV6PD     0x00008000
#define BBL_SEND_ARP_REQUEST        0x00010000
#define BBL_SEND_ARP_REPLY          0x00020000
#define BBL_SEND_DHCP_REQUEST       0x00040000
#define BBL_SEND_ICMPV6_REPLY       0x00080000
#define BBL_SEND_ICMPV6_NS          0x00100000
#define BBL_SEND_ICMPV6_NA          0x00200000
#define BBL_SEND_CFM_CC             0x00400000

/* Network Interface */
#define BBL_IF_SEND_ARP_REQUEST     0x00000001
#define BBL_IF_SEND_ARP_REPLY       0x00000002
#define BBL_IF_SEND_ICMPV6_NS       0x00000004
#define BBL_IF_SEND_ICMPV6_NA       0x00000008
#define BBL_IF_SEND_SEC_ARP_REPLY   0x00000010
#define BBL_IF_SEND_SEC_ICMPV6_NA   0x00000020

#define DUID_LEN                    10

#define DHCPV6_BUFFER               64

#define BBL_MAX_ACCESS_INTERFACES   64
#define BBL_AVG_SAMPLES             5
#define DATA_TRAFFIC_MAX_LEN        1920

#define UNUSED(x)    (void)x

typedef struct bbl_session_ bbl_session_s;

typedef struct bbl_rate_
{
    uint64_t diff_value[BBL_AVG_SAMPLES];
    uint32_t cursor;
    uint64_t last_value;
    uint64_t avg;
    uint64_t avg_max;
} bbl_rate_s;

typedef enum {
    IO_MODE_PACKET_MMAP_RAW = 0,    /* RX packet_mmap ring / TX raw sockets */
    IO_MODE_PACKET_MMAP,            /* RX/TX packet_mmap ring */
    IO_MODE_RAW,                    /* RX/TX raw sockets */
    IO_MODE_NETMAP                  /* RX/TX netmap ring */
} __attribute__ ((__packed__)) bbl_io_mode_t;

typedef enum {
    ACCESS_TYPE_PPPOE = 0,
    ACCESS_TYPE_IPOE
} __attribute__ ((__packed__)) bbl_access_type_t;

typedef enum {
    VLAN_MODE_11 = 0,   /* VLAN mode 1:1 */
    VLAN_MODE_N1        /* VLAN mode N:1 */
} __attribute__ ((__packed__)) bbl_vlan_mode_t;
typedef enum {
    IGMP_GROUP_IDLE = 0,
    IGMP_GROUP_LEAVING,
    IGMP_GROUP_ACTIVE,
    IGMP_GROUP_JOINING,
    IGMP_GROUP_MAX
} __attribute__ ((__packed__)) igmp_group_state_t;

typedef struct bbl_igmp_group_
{
    uint8_t  state;
    uint8_t  robustness_count;
    bool     send;
    bool     zapping;
    uint32_t group;
    uint32_t source[IGMP_MAX_SOURCES];
    uint64_t packets;
    uint64_t loss;
    struct timespec join_tx_time;
    struct timespec first_mc_rx_time;
    struct timespec leave_tx_time;
    struct timespec last_mc_rx_time;
} bbl_igmp_group_s;

typedef struct bbl_secondary_ip_
{
    uint32_t ip;
    bool arp_reply;
    void *next;
} bbl_secondary_ip_s;

typedef struct bbl_secondary_ip6_
{
    ipv6addr_t ip;
    ipv6addr_t icmpv6_src;
    bool icmpv6_na;
    void *next;
} bbl_secondary_ip6_s;

typedef struct bbl_interface_
{
    CIRCLEQ_ENTRY(bbl_interface_) interface_qnode;
    struct bbl_ctx_ *ctx; /* parent */
    char *name; /* interface name */

    bool access; /* interface type (access/network) */

    struct timer_ *timer_arp;
    struct timer_ *timer_nd;

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

#ifdef BNGBLASTER_NETMAP
        struct nm_desc *port;
#endif
    } io;

    uint32_t ifindex; /* interface index */
    uint32_t pcap_index; /* interface index for packet captures */

    uint32_t send_requests;
    bool     arp_resolved;
    uint32_t arp_reply_ip;
    uint32_t ip;
    uint32_t gateway;
    uint8_t  mac[ETH_ADDR_LEN];
    uint8_t  gateway_mac[ETH_ADDR_LEN];


    ipv6_prefix ip6;
    ipv6_prefix gateway6;
    ipv6addr_t  icmpv6_src;
    bool        icmpv6_nd_resolved;

    uint8_t *mc_packets;
    uint16_t mc_packet_len;
    uint64_t mc_packet_seq;
    uint16_t mc_packet_cursor;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        bbl_rate_s rate_packets_tx;
        bbl_rate_s rate_packets_rx;
        uint64_t bytes_tx;
        uint64_t bytes_rx;
        bbl_rate_s rate_bytes_tx;
        bbl_rate_s rate_bytes_rx;
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

        uint32_t dhcp_tx;
        uint32_t dhcp_rx;
        uint32_t dhcp_timeout;

        uint32_t dhcpv6_tx;
        uint32_t dhcpv6_rx;
        uint32_t dhcpv6_timeout;

        uint32_t ipv4_fragmented_rx;

        uint64_t session_ipv4_tx;
        bbl_rate_s rate_session_ipv4_tx;
        uint64_t session_ipv4_rx;
        bbl_rate_s rate_session_ipv4_rx;
        uint64_t session_ipv4_loss;

        uint64_t session_ipv6_tx;
        bbl_rate_s rate_session_ipv6_tx;
        uint64_t session_ipv6_rx;
        bbl_rate_s rate_session_ipv6_rx;
        uint64_t session_ipv6_loss;

        uint64_t session_ipv6pd_tx;
        bbl_rate_s rate_session_ipv6pd_tx;
        uint64_t session_ipv6pd_rx;
        bbl_rate_s rate_session_ipv6pd_rx;
        uint64_t session_ipv6pd_loss;

        uint64_t session_ipv4_wrong_session;
        uint64_t session_ipv6_wrong_session;
        uint64_t session_ipv6pd_wrong_session;

        uint32_t l2tp_control_rx;
        uint32_t l2tp_control_rx_dup; /* duplicate */
        uint32_t l2tp_control_rx_ooo; /* out of order */
        uint32_t l2tp_control_rx_nf;  /* session not found */
        uint32_t l2tp_control_tx;
        uint32_t l2tp_control_retry;
        uint64_t l2tp_data_rx;
        uint64_t l2tp_data_tx;
        bbl_rate_s rate_l2tp_data_rx;
        bbl_rate_s rate_l2tp_data_tx;

        uint64_t li_rx;
        bbl_rate_s rate_li_rx;
    } stats;

    struct timer_ *tx_job;
    struct timer_ *rx_job;
    struct timer_ *rate_job;

    struct timespec tx_timestamp; /* user space timestamps */
    struct timespec rx_timestamp; /* user space timestamps */

    CIRCLEQ_HEAD(bbl_interface__, bbl_session_ ) session_tx_qhead; /* list of sessions that want to transmit */
    CIRCLEQ_HEAD(bbl_interface___, bbl_l2tp_queue_ ) l2tp_tx_qhead; /* list of messages that want to transmit */
} bbl_interface_s;

typedef struct bbl_access_config_
{
    bool exhausted;
    uint32_t sessions; /* per access config session counter */
    struct bbl_interface_ *access_if;

    char *interface;

    bbl_access_type_t access_type; /* pppoe or ipoe */
    bbl_vlan_mode_t vlan_mode; /* 1:1 (default) or N:1 */

    uint16_t stream_group_id;

    uint16_t access_outer_vlan;
    uint16_t access_outer_vlan_min;
    uint16_t access_outer_vlan_max;
    uint16_t access_inner_vlan;
    uint16_t access_inner_vlan_min;
    uint16_t access_inner_vlan_max;
    uint16_t access_third_vlan;

    /* Static */
    uint32_t static_ip;
    uint32_t static_ip_iter;
    uint32_t static_gateway;
    uint32_t static_gateway_iter;

    /* Authentication */
    char *username;
    char *password;
    uint16_t authentication_protocol;

    /* Access Line */
    char *agent_remote_id;
    char *agent_circuit_id;
    uint32_t rate_up;
    uint32_t rate_down;
    uint32_t dsl_type;

    uint16_t access_line_profile_id;

    /* Protocols */
    bool ipcp_enable;
    bool ip6cp_enable;
    bool ipv4_enable;
    bool ipv6_enable;
    bool dhcp_enable;
    bool dhcpv6_enable;
    bool igmp_autostart;
    uint8_t igmp_version;
    bool session_traffic_autostart;

    /* CFM CC */
    bool cfm_cc;
    uint8_t cfm_level;
    uint16_t cfm_ma_id;
    char *cfm_ma_name;

    /* Iterator */
    uint32_t i1;
    uint32_t i1_step;
    uint32_t i2;
    uint32_t i2_step;

    void *next; /* pointer to next access config element */
} bbl_access_config_s;

typedef struct bbl_access_line_profile_
{
    uint16_t access_line_profile_id;

    // broadband forum tr101

    uint32_t act_up; /* Actual Data Rate Upstream */
    uint32_t act_down; /* Actual Data Rate Downstream */
    uint32_t min_up; /* Minimum Data Rate Upstream */
    uint32_t min_down; /* Minimum Data Rate Downstream */
    uint32_t att_up; /* Attainable DataRate Upstream */
    uint32_t att_down; /* Attainable DataRate Downstream */
    uint32_t max_up; /* Maximum Data Rate Upstream */
    uint32_t max_down; /* Maximum Data Rate Downstream */
    uint32_t min_up_low; /* Min Data Rate Upstream in low power state */
    uint32_t min_down_low; /* Min Data Rate Downstream in low power state */
    uint32_t max_interl_delay_up; /* Max Interleaving Delay Upstream */
    uint32_t act_interl_delay_up; /* Actual Interleaving Delay Upstream */
    uint32_t max_interl_delay_down; /* Max Interleaving Delay Downstream */
    uint32_t act_interl_delay_down; /* Actual Interleaving Delay Downstream */
    uint32_t data_link_encaps; /* Data Link Encapsulation */
    uint32_t dsl_type; /* DSL Type */

    // draft-lihawi-ancp-protocol-access-extension-04

    uint32_t pon_type; /* PON-Access-Type */
    uint32_t etr_up; /* Expected Throughput (ETR) Upstream */
    uint32_t etr_down; /* Expected Throughput (ETR) Downstream */
    uint32_t attetr_up; /* Attainable Expected Throughput (ATTETR) Upstream */
    uint32_t attetr_down; /* Attainable Expected Throughput (ATTETR) Downstream */
    uint32_t gdr_up; /* Gamma Data Rate (GDR) Upstream */
    uint32_t gdr_down; /* Gamma Data Rate (GDR) Downstream */
    uint32_t attgdr_up; /* Attainable Gamma Data Rate (ATTGDR) Upstream */
    uint32_t attgdr_down; /* Attainable Gamma Data Rate (ATTGDR) Downstream */
    uint32_t ont_onu_avg_down; /* ONT/ONU-Average-Data-Rate-Downstream */
    uint32_t ont_onu_peak_down; /* ONT/ONU-Peak-Data-Rate-Downstream */
    uint32_t ont_onu_max_up; /* ONT/ONU-Maximum-Data-Rate-Upstream */
    uint32_t ont_onu_ass_up; /* ONT/ONU-Assured-Data-Rate-Upstream */
    uint32_t pon_max_up; /* PON-Tree-Maximum-Data-Rate-Upstream */
    uint32_t pon_max_down; /* PON-Tree-Maximum-Data-Rate-Downstream */

    void *next; /* pointer to next access line profile element */
} bbl_access_line_profile_s;

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
    struct timer_ *ctrl_socket_timer;

    struct timespec timestamp_start;
    struct timespec timestamp_stop;

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

    CIRCLEQ_HEAD(bbl_ctx_idle_, bbl_session_ ) sessions_idle_qhead;
    CIRCLEQ_HEAD(bbl_ctx_teardown_, bbl_session_ ) sessions_teardown_qhead;
    CIRCLEQ_HEAD(bbl_ctx__, bbl_interface_ ) interface_qhead; /* list of interfaces */

    bbl_session_s **session_list; /* list for sessions */

    dict *vlan_session_dict; /* hashtable for 1:1 vlan sessions */
    dict *l2tp_session_dict; /* hashtable for L2TP sessions */
    dict *li_flow_dict; /* hashtable for LI flows */
    dict *stream_flow_dict; /* hashtable for traffic stream flows */

    uint16_t next_tunnel_id;

    uint64_t flow_id;

    int ctrl_socket;
    char *ctrl_socket_path;

    /* Operational state */
    struct {
        uint8_t access_if_count;
        struct bbl_interface_ *access_if[BBL_MAX_ACCESS_INTERFACES];
        struct bbl_interface_ *network_if;
    } op;

    /* Scratchpad memory */
    uint8_t *sp_rx;
    uint8_t *sp_tx;

    /* PCAP */
    struct {
        int fd;
        char *filename;
        uint8_t *write_buf;
        uint write_idx;
        bool wrote_header;
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
    } stats;

    bool multicast_traffic;

    /* Config options */
    struct {
        bool interface_lock_force;

        uint64_t tx_interval; /* TX interval in nsec */
        uint64_t rx_interval; /* RX interval in nsec */

        uint16_t io_slots;
        uint16_t io_stream_max_ppi; /* Traffic stream max packets per interval */

        bool qdisc_bypass;
        bbl_io_mode_t io_mode;

        char *json_report_filename;

        /* Network Interface */
        char network_if[IFNAMSIZ];
        uint32_t network_ip;
        uint32_t network_gateway;
        ipv6_prefix network_ip6;
        ipv6_prefix network_gateway6;
        uint16_t network_vlan;

        bbl_secondary_ip_s *secondary_ip_addresses;
        bbl_secondary_ip6_s *secondary_ip6_addresses;

        /* Access Interfaces  */
        bbl_access_config_s *access_config;

        /* Access Line Profiles */
        void *access_line_profile;

        /* Traffic Streams */
        void *stream_config;

        /* Global Session Settings */
        uint32_t sessions;
        uint32_t sessions_max_outstanding;
        uint16_t sessions_start_rate;
        uint16_t sessions_stop_rate;
        bool iterate_outer_vlan;

        /* Static */
        uint32_t static_ip;
        uint32_t static_ip_iter;
        uint32_t static_gateway;
        uint32_t static_gateway_iter;

        /* Authentication */
        char *username;
        char *password;

        /* Access Line */
        char *agent_remote_id;
        char *agent_circuit_id;
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
        bool ipv4_enable;

        /* ARP (IPoE) */
        uint16_t arp_timeout;
        uint16_t arp_interval;

        /* IPv6 (IPoE) */
        bool ipv6_enable;

        /* DHCP */
        bool dhcp_enable;
        bool dhcp_broadcast;
        uint16_t dhcp_timeout;
        uint8_t dhcp_retry;
        uint8_t dhcp_release_interval;
        uint8_t dhcp_release_retry;
        uint8_t dhcp_tos;
        uint8_t dhcp_vlan_priority;

        /* DHCPv6 */
        bool dhcpv6_enable;
        bool dhcpv6_rapid_commit;
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

        /* Multicast Traffic */
        bool send_multicast_traffic;
        uint8_t multicast_traffic_tos;
        uint16_t multicast_traffic_len;

        /* Session Traffic */
        bool session_traffic_autostart;
        uint16_t session_traffic_ipv4_pps;
        uint16_t session_traffic_ipv6_pps;
        uint16_t session_traffic_ipv6pd_pps;

        /* L2TP Server Config (LNS) */
        bbl_l2tp_server_t *l2tp_server;
    } config;
} bbl_ctx_s;

/*
 * Session state
 */
typedef enum {
    BBL_IDLE = 0,
    BBL_IPOE_SETUP,         // IPoE setup
    BBL_PPPOE_INIT,         // send PADI
    BBL_PPPOE_REQUEST,      // send PADR
    BBL_PPP_LINK,           // send LCP requests
    BBL_PPP_AUTH,           // send authentication requests
    BBL_PPP_NETWORK,        // send NCP requests
    BBL_ESTABLISHED,        // established
    BBL_PPP_TERMINATING,    // send LCP terminate requests
    BBL_TERMINATING,        // send PADT
    BBL_TERMINATED,         // terminated
    BBL_MAX
} __attribute__ ((__packed__)) session_state_t;

/*
 * PPP state (LCP, IPCP and IP6CP)
 *
 * This is a simple not fully RFC conform version
 * of the PPP FSM.
 */
typedef enum {
    BBL_PPP_CLOSED      = 0,
    BBL_PPP_INIT        = 1,
    BBL_PPP_LOCAL_ACK   = 2,
    BBL_PPP_PEER_ACK    = 3,
    BBL_PPP_OPENED      = 4,
    BBL_PPP_TERMINATE   = 5,
    BBL_PPP_MAX
} __attribute__ ((__packed__)) ppp_state_t;


/*
 * DHCP state
 *
 * This is a simple not fully RFC conform version
 * of the DHCP FSM.
 */
typedef enum {
    BBL_DHCP_INIT           = 0,
    BBL_DHCP_SELECTING      = 1,
    BBL_DHCP_REQUESTING     = 2,
    BBL_DHCP_BOUND          = 3,
    BBL_DHCP_RENEWING       = 4,
    BBL_DHCP_RELEASE        = 5,
    BBL_DHCP_MAX
} __attribute__ ((__packed__)) dhcp_state_t;

typedef struct vlan_session_key_ {
    uint32_t ifindex;
    uint16_t outer_vlan_id;
    uint16_t inner_vlan_id;
} __attribute__ ((__packed__)) vlan_session_key_t;

#define BBL_SESSION_HASHTABLE_SIZE 128993 /* is a prime number */
#define BBL_LI_HASHTABLE_SIZE 32771 /* is a prime number */
#define BBL_STREAM_FLOW_HASHTABLE_SIZE 128993 /* is a prime number */

/*
 * Client Session to a BNG device.
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

    /* Authentication */
    char *username;
    char *password;

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
    uint32_t zapping_join_delay_count;
    uint64_t zapping_leave_delay_sum;
    uint32_t zapping_leave_delay_count;
    struct timespec zapping_view_start_time;

    /* ICMP */
    uint32_t icmp_reply_destination;
    uint8_t  icmp_reply_type;
    uint8_t  icmp_reply_data[ICMP_DATA_BUFFER];
    uint16_t icmp_reply_data_len;

    /* Multicast Traffic */
    uint64_t mc_rx_last_seq;

    /* Session Traffic */
    bool session_traffic;
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

        uint32_t min_leave_delay;
        uint32_t avg_leave_delay;
        uint32_t max_leave_delay;

        /* This value counts all MC packets for old
         * group received after first packet for new
         * group received.  */
        uint32_t mc_old_rx_after_first_new;
        uint32_t mc_rx;
        uint32_t mc_loss; /* packet loss */
        uint32_t mc_not_received;
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

        uint32_t flapped; // flap counter
    } stats;

} bbl_session_s;

void bbl_session_tx_qnode_insert(struct bbl_session_ *session);
void bbl_session_tx_qnode_remove(struct bbl_session_ *session);
void bbl_session_network_tx_qnode_insert(struct bbl_session_ *session);
void bbl_session_network_tx_qnode_remove(struct bbl_session_ *session);

WINDOW *log_win;
WINDOW *stats_win;

#endif
