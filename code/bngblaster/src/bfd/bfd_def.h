/*
 * BNG Blaster (BBL) - BFD Definitions
 *
 * Bidirectional Forwarding Detection (RFC 5880, 5881, 5883).
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BFD_DEF_H__
#define __BBL_BFD_DEF_H__

#define BFD_VERSION                     1
#define BFD_SRC_PORT_MIN                49152
#define BFD_SRC_PORT_RANGE              16384
#define BFD_TTL                         255
#define BFD_MAX_LEN                     (BFD_HDR_LEN+BFD_AUTH_SHA1_LEN)

#define BFD_AUTH_NONE                   0
#define BFD_AUTH_SIMPLE                 1
#define BFD_AUTH_KEYED_MD5              2
#define BFD_AUTH_METICULOUS_KEYED_MD5   3
#define BFD_AUTH_KEYED_SHA1             4
#define BFD_AUTH_METICULOUS_KEYED_SHA1  5

#define BFD_AUTH_SIMPLE_MAX_LEN         16
#define BFD_AUTH_MD5_LEN                24 /* auth section length */
#define BFD_AUTH_SHA1_LEN               28 /* auth section length */
#define BFD_MD5_DIGEST_LEN              16
#define BFD_SHA1_DIGEST_LEN             20
#define BFD_AUTH_KEY_MAX_LEN            20

/* Slow start interval used while the session is not Up (RFC 5880 6.8.3). */
#define BFD_SLOW_TX_INTERVAL_US         1000000

#define BFD_DEFAULT_TX_INTERVAL_MS      1000
#define BFD_DEFAULT_RX_INTERVAL_MS      1000
#define BFD_DEFAULT_MULTIPLIER          3
#define BFD_DEFAULT_MULTIHOP_MIN_TTL    254

typedef enum bfd_state_ {
    BFD_STATE_ADMIN_DOWN = 0,
    BFD_STATE_DOWN = 1,
    BFD_STATE_INIT = 2,
    BFD_STATE_UP = 3,
} bfd_state_t;

typedef enum bfd_diag_ {
    BFD_DIAG_NONE = 0,
    BFD_DIAG_DETECTION_TIME_EXPIRED = 1,
    BFD_DIAG_ECHO_FAILED = 2,
    BFD_DIAG_NEIGHBOR_DOWN = 3,
    BFD_DIAG_FORWARDING_PLANE_RESET = 4,
    BFD_DIAG_PATH_DOWN = 5,
    BFD_DIAG_CONCATENATED_PATH_DOWN = 6,
    BFD_DIAG_ADMIN_DOWN = 7,
    BFD_DIAG_REVERSE_CONCATENATED_PATH_DOWN = 8,
} bfd_diag_t;

/* Events reported to BFD clients (e.g. routing protocols). */
typedef enum bfd_event_ {
    BFD_EVENT_UP = 0,
    BFD_EVENT_DOWN, /* Up -> Down, except if the peer signaled AdminDown */
} bfd_event_t;

/* BFD client types (bitmask). */
#define BFD_CLIENT_STATIC               0x01
#define BFD_CLIENT_ISIS                 0x02
#define BFD_CLIENT_OSPFV2               0x04
#define BFD_CLIENT_OSPFV3               0x08
#define BFD_CLIENT_BGP                  0x10
#define BFD_CLIENT_LDP                  0x20

typedef void (*bfd_client_cb)(void *client, bfd_session_s *session, bfd_event_t event);

typedef struct bfd_profile_config_ {
    uint16_t id;
    uint32_t tx_interval; /* desired min TX interval in us */
    uint32_t rx_interval; /* required min RX interval in us */
    uint8_t  multiplier;
    uint8_t  min_ttl; /* multi-hop only */
    bool     min_ttl_set;
    bool     passive;
    uint8_t  auth_type;
    uint8_t  auth_key_id;
    uint8_t  auth_key_len;
    uint8_t  auth_key[BFD_AUTH_KEY_MAX_LEN];
    struct bfd_profile_config_ *next;
} bfd_profile_config_s;

typedef struct bfd_session_config_ {
    char       *network_interface;
    char       *name;
    bool        ipv6;
    bool        multihop;
    uint32_t    local_ipv4;
    uint32_t    peer_ipv4;
    ipv6addr_t  local_ipv6;
    ipv6addr_t  peer_ipv6;
    uint16_t    profile_id;
    struct bfd_session_config_ *next;
} bfd_session_config_s;

typedef struct bfd_client_ {
    uint8_t type; /* BFD_CLIENT_* */
    bool notified;
    void *client;
    bfd_client_cb cb;
    struct bfd_client_ *next;
} bfd_client_s;

/* Session lookup key for packets without your discriminator. */
typedef struct bfd_key_ {
    void       *interface; /* NULL for multi-hop */
    uint8_t     af;
    uint8_t     multihop;
    uint8_t     local[IPV6_ADDR_LEN];
    uint8_t     peer[IPV6_ADDR_LEN];
} bfd_key_s;

struct bfd_session_ {
    uint32_t id;
    char *name; /* optional */
    char *local_str;
    char *peer_str;

    bfd_key_s key;
    bbl_network_interface_s *interface;
    bfd_profile_config_s *profile;

    bool ipv6;
    bool multihop;
    bool passive;
    bool admin_disabled; /* disabled via control command */
    bool deleted;
    bool notify; /* client notification in progress */

    uint32_t local_ipv4;
    uint32_t peer_ipv4;
    ipv6addr_t local_ipv6;
    ipv6addr_t peer_ipv6;

    uint16_t src_port;
    uint8_t  min_ttl;
    uint8_t  peer_mac[ETH_ADDR_LEN];
    bool     peer_mac_learned;

    bfd_state_t state;
    bfd_state_t remote_state;
    uint8_t local_diag;
    uint8_t remote_diag;
    uint32_t local_discr;
    uint32_t remote_discr;
    bool remote_demand;

    /* Configured values (us). */
    uint32_t config_tx_interval;
    uint32_t config_rx_interval;
    uint8_t  multiplier;

    /* Advertised values (us). */
    uint32_t desired_min_tx;
    uint32_t required_min_rx;
    /* Values in use until a poll sequence has terminated (us). */
    uint32_t active_min_tx;
    uint32_t active_min_rx;

    uint32_t remote_min_tx;
    uint32_t remote_min_rx;
    uint8_t  remote_multiplier;

    uint32_t tx_interval; /* negotiated TX interval (us) */
    uint32_t detect_time; /* detection time (us) */

    bool poll; /* poll sequence in progress */
    bool final; /* send final */

    /* Authentication */
    uint8_t  auth_type;
    uint32_t xmit_auth_seq;
    uint32_t rcv_auth_seq;
    bool     rcv_auth_seq_known;
    struct timespec rcv_auth_timestamp;

    struct timer_ *tx_timer;
    struct timer_ *detect_timer;

    bfd_client_s *clients;
    uint8_t client_types;

    struct timespec state_timestamp; /* last state change */

    struct {
        uint64_t tx;
        uint64_t rx;
        uint64_t rx_error;
        uint64_t rx_auth_error;
        uint64_t tx_error;
        uint32_t up;
        uint32_t down;
        uint32_t poll;
        uint32_t timeout;
    } stats;

    struct bfd_session_ *next;
    struct bfd_session_ *prev;
};

/* Global BFD state. */
typedef struct bfd_ctx_ {
    bfd_session_s *sessions;
    bfd_session_s *sessions_tail;
    hb_tree *discr_db;
    hb_tree *key_db;
    uint32_t next_id;
    uint32_t next_discr;
    uint32_t sessions_count;
    uint32_t sessions_up;
    bool teardown;
    struct timer_ *teardown_timer;
    struct {
        uint64_t tx;
        uint64_t rx;
        uint64_t rx_error;
        uint64_t rx_no_session;
        uint32_t up;
        uint32_t down;
        uint32_t timeout;
    } stats;
} bfd_ctx_s;

#endif
