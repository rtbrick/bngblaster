/*
 * BNG Blaster (BBL) - BGP Definitions
 *
 * Christian Giese, MARCH 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_DEF_H__
#define __BBL_BGP_DEF_H__

#include "../bbl_tcp_ao.h"

/* DEFINITIONS ... */

#define BGP_PORT                    179
#define BGP_MIN_MESSAGE_SIZE        19U
#define BGP_MAX_MESSAGE_SIZE        4096U
#define BGP_BUF_SIZE                256*1024
#define BGP_DEFAULT_AS              65000
#define BGP_DEFAULT_HOLD_TIME       90
#define BGP_DEFAULT_TEARDOWN_TIME   5
/* RFC 4271 8.2.2: on entering OpenSent the hold timer is set to a large
 * value (4 minutes suggested), bounding a session that completes TCP but
 * never receives the peer's OPEN. */
#define BGP_OPENSENT_HOLD_TIME      240

#define BGP_MSG_OPEN                1
#define BGP_MSG_UPDATE              2
#define BGP_MSG_NOTIFICATION        3
#define BGP_MSG_KEEPALIVE           4

#define BGP_CAPABILITY              2
#define BGP_CAPABILITY_4_BYTE_AS    65

#define BGP_IPV4_UC                 0x00000001
#define BGP_IPv6_UC                 0x00000002
#define BGP_IPv4_MC                 0x00000004
#define BGP_IPv6_MC                 0x00000008
#define BGP_IPv4_LU                 0x00000010
#define BGP_IPv6_LU                 0x00000020
#define BGP_IPv4_VPN_UC             0x00000040
#define BGP_IPv6_VPN_UC             0x00000080
#define BGP_IPv4_VPN_MC             0x00000100
#define BGP_IPv6_VPN_MC             0x00000200
#define BGP_IPv4_FLOW               0x00000400
#define BGP_IPv6_FLOW               0x00000800
#define BGP_EVPN                    0x00001000

#define BGP_AFI_IPV4                1
#define BGP_AFI_IPV6                2
#define BGP_AFI_L2VPN               25
#define BGP_SAFI_UNICAST            1
#define BGP_SAFI_LABELED_UNICAST    4
#define BGP_SAFI_EVPN               70

/* Path attributes */
#define BGP_PA_FLAG_EXTENDED_LENGTH 0x10
#define BGP_PA_ORIGIN               1
#define BGP_PA_AS_PATH              2
#define BGP_PA_NEXT_HOP             3
#define BGP_PA_MED                  4
#define BGP_PA_LOCAL_PREF           5
#define BGP_PA_COMMUNITIES          8
#define BGP_PA_LARGE_COMMUNITIES    32
#define BGP_PA_MP_REACH_NLRI        14
#define BGP_PA_MP_UNREACH_NLRI      15
#define BGP_PA_EXT_COMMUNITIES      16
#define BGP_PA_PMSI_TUNNEL          22

/* EVPN (RFC 7432, RFC 9136) */
#define BGP_EVPN_ROUTE_AD           1 /* Ethernet Auto-Discovery */
#define BGP_EVPN_ROUTE_MAC_IP       2 /* MAC/IP Advertisement */
#define BGP_EVPN_ROUTE_IMET         3 /* Inclusive Multicast Ethernet Tag */
#define BGP_EVPN_ROUTE_ES           4 /* Ethernet Segment */
#define BGP_EVPN_ROUTE_IP_PREFIX    5 /* IP Prefix */

#define BGP_EVPN_MAX_ET             0xffffffff /* per-ES A-D route */

/* EVPN Layer 2 Attributes control flags (RFC 8214) */
#define BGP_EVPN_L2_FLAG_BACKUP     0x0001
#define BGP_EVPN_L2_FLAG_PRIMARY    0x0002
#define BGP_EVPN_L2_FLAG_CW         0x0004

#define BGP_RD_LEN                  8
#define BGP_ESI_LEN                 10
#define BGP_EVPN_MAX_RT             8

/* BGP tunnel encapsulation types (RFC 9012) */
#define BGP_ENCAP_VXLAN             8
#define BGP_ENCAP_NVGRE             9
#define BGP_ENCAP_MPLS              10
#define BGP_ENCAP_VXLAN_GPE         12
#define BGP_ENCAP_GENEVE            19

typedef enum bgp_state_ {
    BGP_CLOSED,
    BGP_IDLE,
    BGP_CONNECT,
    BGP_ACTIVE,
    BGP_OPENSENT,
    BGP_OPENCONFIRM,
    BGP_ESTABLISHED,
    BGP_CLOSING,
} bgp_state_t;

/*
 * BGP RAW Update File
 */
typedef struct bgp_raw_update_ {
    const char *file;

    uint8_t *buf;
    uint32_t len;
    uint32_t updates;

    /* Pointer to next instance */
    struct bgp_raw_update_ *next;
} bgp_raw_update_s;

/*
 * BGP Configuration
 */
typedef struct bgp_config_ {
    uint8_t  af; /* address family */
    uint32_t ipv4_local_address;
    uint32_t ipv4_peer_address;

    ipv6addr_t ipv6_local_address;
    ipv6addr_t ipv6_peer_address;

    uint32_t id;
    uint32_t local_as;
    uint32_t peer_as;
    uint16_t hold_time;
    uint16_t teardown_time;
    uint8_t  tos; /* IPv4 TOS or IPv6 TC */
    uint8_t  ttl;

    uint32_t family;
    uint32_t extended_nexthop;

    bool reconnect;
    bool start_traffic;
    bool learn_routes; /* store received IPv4, IPv6 and EVPN routes */

    char *network_interface;
    char *raw_update_file;

    /* TCP-AO (RFC 5925/5926, HMAC-SHA-256-128) */
    bool     tcp_ao_enabled;
    char     *tcp_ao_key;
    uint8_t  tcp_ao_key_id;
    uint8_t  tcp_ao_rnext_key_id;
    bbl_tcp_ao_algo_t tcp_ao_algo;

    /* Pointer to next instance */
    struct bgp_config_ *next;
} bgp_config_s;

/*
 * BGP Connection Collision (RFC 4271 6.8)
 *
 * Holds a second, not-yet-resolved TCP connection to the same peer while
 * both sides of a simultaneous active-open/passive-accept race independently
 * proceed far enough to exchange OPEN messages and compare BGP Identifiers.
 */
typedef struct bgp_collision_ {
    bbl_tcp_ctx_s *tcpc;
    bool active; /* true if this leg is our own active connect, false if accepted */

    io_buffer_t read_buf;
    io_buffer_t write_buf;
} bgp_collision_s;

/*
 * BGP Listen Socket
 *
 * One shared listen socket per unique (interface, local address, address
 * family), deduplicated across all configured BGP sessions that share it.
 * Owned independently of any single bgp_session_s.
 */
typedef struct bgp_listen_ {
    uint8_t af;
    bbl_network_interface_s *interface;
    uint32_t ipv4_local_address;
    ipv6addr_t ipv6_local_address;

    bbl_tcp_ctx_s *tcpc;

    struct bgp_listen_ *next;
} bgp_listen_s;

/*
 * BGP Session
 */
typedef struct bgp_session_ {
    uint8_t  af; /* address family */
    uint32_t ipv4_local_address;
    uint32_t ipv4_peer_address;

    ipv6addr_t *ipv6_local_address;
    ipv6addr_t *ipv6_peer_address;

    char *local_address_str;
    char *peer_address_str;

    bgp_config_s *config;
    bbl_network_interface_s *interface;
    bbl_tcp_ctx_s *tcpc;
    bool active; /* is tcpc the connection we dialed out on? */

    bbl_tcp_ctx_s *connecting_tcpc; /* pending active connect() attempt, not yet
                                        adopted as tcpc (may lose a collision race
                                        against an already-progressing passive one) */

    bgp_collision_s *collision; /* non-NULL only while a second connection race is unresolved */
    bool collision_promoted; /* one-shot flag consumed by bgp_read() after a promotion */

    struct timer_ *connect_timer;
    struct timer_ *keepalive_timer;
    struct timer_ *hold_timer;
    struct timer_ *close_timer;

    struct timer_ *update_timer;
    struct timer_ *teardown_timer;

    io_buffer_t read_buf;
    io_buffer_t write_buf;

    bgp_state_t state;

    struct {
        uint32_t as;
        uint32_t id;
        uint16_t hold_time;
        bool as4; /* 4-octet AS capability received */
    } peer;

    struct {
        uint32_t message_rx;
        uint32_t message_tx;
        uint32_t keepalive_rx;
        uint32_t keepalive_tx;
        uint32_t update_rx;
        uint32_t update_tx;
        uint32_t evpn_reach_rx;
        uint32_t evpn_withdraw_rx;
        uint32_t route_reach_rx;
        uint32_t route_withdraw_rx;
    } stats;

    /* Adj-RIB-In (only if learn-routes is enabled) */
    struct {
        hb_tree *ipv4;
        hb_tree *ipv6;
        hashtable2 *attr; /* shared path attribute sets */
        hb_tree *evpn_db; /* EVPN routes */
        uint32_t ipv4_unicast;
        uint32_t ipv4_labeled_unicast;
        uint32_t ipv6_unicast;
        uint32_t ipv6_labeled_unicast;
        uint32_t evpn;
    } rib;

    bgp_raw_update_s *raw_update_start;
    bgp_raw_update_s *raw_update;
    bool raw_update_sending;

    struct timespec established_timestamp;
    struct timespec update_start_timestamp;
    struct timespec update_stop_timestamp;
    struct timespec update_duration;

    bool teardown;
    uint8_t error_code;
    uint8_t error_subcode;
    
    struct bgp_session_ *next; /* pointer to next instance */
} bgp_session_s;

/*
 * BGP Update Attributes
 *
 * Pointers into the received UPDATE message to the
 * path attributes relevant for route learning.
 */
typedef struct bgp_update_ {
    uint8_t *withdrawn; /* IPv4 unicast withdrawn routes */
    uint8_t *nlri; /* IPv4 unicast NLRI */
    uint8_t *origin;
    uint8_t *as_path;
    uint8_t *next_hop;
    uint8_t *med;
    uint8_t *local_pref;
    uint8_t *communities;
    uint8_t *large_communities;
    uint8_t *ext_communities;
    uint8_t *pmsi_tunnel;
    uint16_t withdrawn_len;
    uint16_t nlri_len;
    uint16_t as_path_len;
    uint16_t communities_len;
    uint16_t large_communities_len;
    uint16_t ext_communities_len;
    uint16_t pmsi_tunnel_len;

    /* MP_REACH_NLRI */
    uint8_t *mp_reach;
    uint8_t *mp_reach_nexthop;
    uint8_t *mp_reach_nlri;
    uint16_t mp_reach_afi;
    uint8_t  mp_reach_safi;
    uint8_t  mp_reach_nexthop_len;
    uint16_t mp_reach_nlri_len;

    /* MP_UNREACH_NLRI */
    uint8_t *mp_unreach;
    uint8_t *mp_unreach_nlri;
    uint16_t mp_unreach_afi;
    uint8_t  mp_unreach_safi;
    uint16_t mp_unreach_nlri_len;
} bgp_update_s;

/*
 * BGP RIB Path Attributes
 *
 * Interned per session and shared by all routes with equal
 * attributes. Everything from len to the end of data is the
 * hash key. The AS_PATH is normalized to 4-octet AS numbers.
 */
typedef struct bgp_rib_attr_ {
    uint32_t refcount;
    /* KEY */
    uint16_t len; /* length of data */
    uint8_t  origin;
    uint8_t  flags;
    uint8_t  nexthop_af;
    uint8_t  nexthop[IPV6_ADDR_LEN];
    uint32_t med;
    uint32_t local_pref;
    uint16_t as_path_len;
    uint16_t communities_len;
    uint16_t large_communities_len;
    uint16_t ext_communities_len;
    uint8_t  data[]; /* AS_PATH, communities, large and extended communities */
} __attribute__ ((__packed__)) bgp_rib_attr_s;

#define BGP_RIB_ATTR_ORIGIN         0x01
#define BGP_RIB_ATTR_MED            0x02
#define BGP_RIB_ATTR_LOCAL_PREF     0x04

/*
 * BGP RIB Route (IPv4 or IPv6)
 */
typedef struct bgp_rib_route_ {
    /* KEY */
    uint8_t  safi;
    uint8_t  prefix[IPV6_ADDR_LEN]; /* zero padded for IPv4 */
    uint8_t  prefix_len;
    /* DATA */
    uint32_t label; /* labeled unicast only */
    bgp_rib_attr_s *attr;
} bgp_rib_route_s;

#define BGP_RIB_ROUTE_KEY_LEN       (2 + IPV6_ADDR_LEN)

/*
 * BGP EVPN Route Key
 *
 * Fixed layout, zero padded and compared with memcmp. Only the
 * fields which are part of the route key for the given route
 * type (RFC 7432 section 7, RFC 9136 section 3) are set.
 */
typedef struct bgp_evpn_key_ {
    uint8_t  route_type;
    uint8_t  rd[BGP_RD_LEN];
    uint8_t  esi[BGP_ESI_LEN]; /* type 1 and 4 */
    uint32_t ethernet_tag; /* type 1, 2, 3 and 5 */
    uint8_t  mac[ETH_ADDR_LEN]; /* type 2 */
    uint8_t  ip_af; /* 0, AF_INET or AF_INET6 */
    uint8_t  ip_len; /* host length or type 5 prefix length */
    uint8_t  ip[IPV6_ADDR_LEN];
} __attribute__ ((__packed__)) bgp_evpn_key_s;

/*
 * BGP EVPN Database Entry
 *
 * Entries are never freed while BNG Blaster is running because
 * traffic streams keep references. Withdrawn entries are marked
 * inactive and every change increments the version.
 */
typedef struct bgp_evpn_entry_ {
    bgp_evpn_key_s key;

    bool active;
    uint32_t version;

    uint16_t encap; /* tunnel encapsulation type (RFC 9012), 0 if not signaled */
    uint8_t  labels; /* number of labels in NLRI */
    uint32_t label1; /* MPLS label or VNI */
    uint32_t label2; /* MPLS label or VNI */

    /* Label used for MPLS encapsulated traffic streams (L3 or VPWS). */
    bool     vpn_label_valid;
    uint32_t vpn_label;

    uint8_t  esi[BGP_ESI_LEN];
    uint8_t  gateway_af;
    uint8_t  gateway[IPV6_ADDR_LEN]; /* type 5 */

    uint8_t  nexthop_af;
    uint8_t  nexthop[IPV6_ADDR_LEN];

    struct {
        bool     present;
        uint8_t  flags;
        uint8_t  tunnel_type;
        uint32_t label; /* MPLS label or VNI */
        uint8_t  tunnel_id_af;
        uint8_t  tunnel_id[IPV6_ADDR_LEN];
    } pmsi;

    bool     router_mac_present;
    uint8_t  router_mac[ETH_ADDR_LEN];

    bool     mac_mobility_present;
    bool     sticky;
    uint32_t mac_mobility_seq;

    bool     esi_label_present;
    bool     single_active;
    uint32_t esi_label; /* MPLS label or VNI */

    bool     l2_attr_present; /* EVPN VPWS (RFC 8214) */
    uint16_t l2_flags;
    uint16_t l2_mtu;

    uint8_t  rt_count;
    uint8_t  rt[BGP_EVPN_MAX_RT][8];

    bgp_session_s *source;
} bgp_evpn_entry_s;

#endif