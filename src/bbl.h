/*
 * BNG BLaster (BBL), a tool for scale testing the control plane of BNG and BRAS devices.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
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

#include "libdict/dict.h"
#include "bbl_logging.h"
#include "bbl_timer.h"
#include "bbl_protocols.h"
#include "bbl_utils.h"
#include "bbl_rx.h"
#include "bbl_tx.h"

#define WRITE_BUF_LEN               1514
#define SCRATCHPAD_LEN              1514
#define PPPOE_AC_COOKIE_LEN         32

#define USERNAME_LEN                65
#define PASSWORD_LEN                65
#define ARI_LEN                     65
#define ACI_LEN                     65
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
#define BBL_SEND_DHCPREQUEST        0x00040000
#define BBL_SEND_ICMPV6_REPLY       0x00080000
#define BBL_SEND_ICMPV6_NS          0x00100000
#define BBL_SEND_ICMPV6_NA          0x00200000

/* Network Interface */
#define BBL_IF_SEND_ARP_REQUEST     0x00000001
#define BBL_IF_SEND_ARP_REPLY       0x00000002
#define BBL_IF_SEND_ICMPV6_NS       0x00000004
#define BBL_IF_SEND_ICMPV6_NA       0x00000008

#define DUID_LEN                    10

#define DHCPV6_BUFFER               64

#define BBL_MAX_ACCESS_INTERFACES   64
#define BBL_AVG_SAMPLES             5
#define DATA_TRAFFIC_MAX_LEN        1500

typedef struct bbl_rate_
{
    uint32_t diff_value[BBL_AVG_SAMPLES];
    uint32_t cursor;
    uint64_t last_value;
    uint64_t avg;
    uint64_t avg_max;

} bbl_rate_s;

typedef enum {
    ACCESS_TYPE_PPPOE = 0,
    ACCESS_TYPE_IPOE
} __attribute__ ((__packed__)) bbl_access_type_t;

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

typedef struct bbl_interface_
{
    CIRCLEQ_ENTRY(bbl_interface_) interface_qnode;
    struct bbl_ctx_ *ctx; /* parent */
    char *name;

    bool access;

    struct timer_ *timer_arp;
    struct timer_ *timer_nd;

    int fd_tx;
    int fd_rx;
    struct tpacket_req req_tx;
    struct tpacket_req req_rx;
    struct sockaddr_ll addr;

    u_char *ring_tx; /* ringbuffer */
    u_char *ring_rx; /* ringbuffer */
    uint cursor_tx; /* slot # inside the ringbuffer */
    uint cursor_rx; /* slot # inside the ringbuffer */

    uint32_t pcap_index; /* interface index for packet captures */

    uint32_t send_requests;
    bool     arp_resolved;
    uint32_t ip;
    uint32_t gateway;
    uint8_t  mac[ETH_ADDR_LEN];
    uint8_t  gateway_mac[ETH_ADDR_LEN];

    bool        icmpv6_nd_resolved;
    ipv6_prefix ip6;
    ipv6_prefix gateway6;

    uint8_t *mc_packets;
    uint     mc_packet_len;
    uint64_t mc_packet_seq;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        bbl_rate_s rate_packets_tx;
        bbl_rate_s rate_packets_rx;
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

        uint32_t dhcpv6_tx;
        uint32_t dhcpv6_rx;
        uint32_t dhcpv6_timeout;

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
    } stats;

    struct timer_ *tx_job;
    struct timer_ *rx_job;
    struct timer_ *rate_job;

    struct timespec tx_timestamp; /* user space timestamps */
    struct timespec rx_timestamp; /* user space timestamps */
    CIRCLEQ_HEAD(bbl_interface__, bbl_session_ ) session_tx_qhead; /* list of sessions that want to transmit */
} bbl_interface_s;

typedef struct bbl_access_config_
{
        bool exhausted;
        uint32_t sessions; /* per access config session counter */
        struct bbl_interface_ *access_if;
        
        char interface[IFNAMSIZ];

        bbl_access_type_t access_type; /* pppoe or ipoe */
        
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
        char username[USERNAME_LEN];
        char password[PASSWORD_LEN];
        uint16_t authentication_protocol;

        /* Access Line */
        char agent_remote_id[ARI_LEN];
        char agent_circuit_id[ACI_LEN];
        uint32_t rate_up;
        uint32_t rate_down;

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

        void *next; /* pointer to next access config element */
} bbl_access_config_s;

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

    uint32_t dhcpv6_requested;
    uint32_t dhcpv6_established;
    uint32_t dhcpv6_established_max;

    CIRCLEQ_HEAD(bbl_ctx_idle_, bbl_session_ ) sessions_idle_qhead;
    CIRCLEQ_HEAD(bbl_ctx_teardown_, bbl_session_ ) sessions_teardown_qhead;
    CIRCLEQ_HEAD(bbl_ctx__, bbl_interface_ ) interface_qhead; /* list of interfaces */

    dict *session_dict; /* hashtable for sessions */

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
        uint32_t setup_time; // Time between first session started and last session established
        double cps; // PPPoE setup rate in calls per second
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
        uint16_t tx_interval;
        uint16_t rx_interval;

        char *json_report_filename;

        /* Network Interface */
        char network_if[IFNAMSIZ];
        uint32_t network_ip;
        uint32_t network_gateway;
        ipv6_prefix network_ip6;
        ipv6_prefix network_gateway6;
        uint16_t network_vlan;

        /* Access Interfaces  */
        bbl_access_config_s *access_config;

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
        char username[USERNAME_LEN];
        char password[PASSWORD_LEN];

        /* Access Line */
        char agent_remote_id[ARI_LEN];
        char agent_circuit_id[ACI_LEN];
        uint32_t rate_up;
        uint32_t rate_down;

        /* PPPoE */
        uint32_t pppoe_session_time;
        uint16_t pppoe_discovery_timeout;
        uint16_t pppoe_discovery_retry;
        bool pppoe_reconnect;

        /* PPP */
        uint16_t ppp_mru;

        /* LCP */
        uint16_t lcp_conf_request_timeout;
        uint16_t lcp_conf_request_retry;
        uint16_t lcp_keepalive_interval;
        uint16_t lcp_keepalive_retry;

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

        /* IPv6 (IPoE) */
        bool ipv6_enable;

        /* DHCP */
        bool dhcp_enable;

        /* DHCPv6 */
        bool dhcpv6_enable;
        bool dhcpv6_rapid_commit;

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

        /* Session Traffic */
        bool session_traffic_autostart;
        uint16_t session_traffic_ipv4_pps;
        uint16_t session_traffic_ipv6_pps;
        uint16_t session_traffic_ipv6pd_pps;
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

typedef struct session_key_ {
    uint32_t ifindex;
    uint16_t outer_vlan_id;
    uint16_t inner_vlan_id;
} __attribute__ ((__packed__)) session_key_t;


#define BBL_SESSION_HASHTABLE_SIZE 32771 /* is a prime number */

/*
 * Client Session to a BNG device.
 */
typedef struct bbl_session_
{
    uint64_t session_id; // internal session identifier */
    session_state_t session_state;
    uint32_t send_requests;
    uint32_t network_send_requests;

    CIRCLEQ_ENTRY(bbl_session_) session_tx_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_idle_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_teardown_qnode;
    CIRCLEQ_ENTRY(bbl_session_) session_network_tx_qnode;

    /* Key in the hashtable */
    struct {
        uint32_t ifindex;
        uint16_t outer_vlan_id;
        uint16_t inner_vlan_id;
    } key;

    struct bbl_interface_ *interface; /* where this session is attached to */
    struct bbl_access_config_ *access_config;

    u_char *write_buf; /* pointer to the slot in the tx_ring */
    uint write_idx;

    /* Session timer */
    struct timer_ *timer_arp;
    struct timer_ *timer_padi;
    struct timer_ *timer_padr;
    struct timer_ *timer_lcp;
    struct timer_ *timer_lcp_echo;
    struct timer_ *timer_auth;
    struct timer_ *timer_ipcp;
    struct timer_ *timer_ip6cp;
    struct timer_ *timer_dhcpv6;
    struct timer_ *timer_igmp;
    struct timer_ *timer_zapping;
    struct timer_ *timer_icmpv6;
    struct timer_ *timer_session;
    struct timer_ *timer_session_traffic_ipv4;
    struct timer_ *timer_session_traffic_ipv6;
    struct timer_ *timer_session_traffic_ipv6pd;

    bbl_access_type_t access_type;
    uint16_t access_third_vlan;
    
    /* Authentication */
    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];

    uint8_t chap_identifier;
    uint8_t chap_response[CHALLENGE_LEN];

    /* Access Line */
    char agent_circuit_id[ACI_LEN];
    char agent_remote_id[ARI_LEN];
    uint32_t rate_up;
    uint32_t rate_down;

    /* Ethernet */
    uint8_t server_mac[ETH_ADDR_LEN];
    uint8_t client_mac[ETH_ADDR_LEN];

    /* PPPoE */
    uint16_t pppoe_session_id;
    uint8_t  pppoe_ac_cookie[PPPOE_AC_COOKIE_LEN];
    uint16_t pppoe_ac_cookie_len;

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
    uint8_t     duid[DUID_LEN];
    uint8_t     server_duid[DHCPV6_BUFFER];
    uint8_t     server_duid_len;

    /* DHCPv6 */
    bool        dhcpv6_requested;
    bool        dhcpv6_received;
    uint8_t     dhcpv6_type;
    uint8_t     dhcpv6_ia_pd_option[DHCPV6_BUFFER];
    uint8_t     dhcpv6_ia_pd_option_len;

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
void bbl_session_update_state(bbl_ctx_s *ctx, bbl_session_s *session, session_state_t state);
void bbl_session_clear(bbl_ctx_s *ctx, bbl_session_s *session);

WINDOW *log_win;
WINDOW *stats_win;

#endif
