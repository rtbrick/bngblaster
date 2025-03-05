/*
 * BNG Blaster (BBL) - LDP Definitions
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_DEF_H__
#define __BBL_LDP_DEF_H__

/* DEFINITIONS ... */

#define LDP_PORT                                    646
#define LDP_IDENTIFIER_LEN                          6U
#define LDP_IDENTIFIER_STR_LEN                      sizeof("255.255.255.255:6500")
#define LDP_MAX_PDU_LEN_INIT                        4096U
#define LDP_MIN_PDU_LEN                             10
#define LDP_MIN_MSG_LEN                             8
#define LDP_MIN_TLV_LEN                             4

#define LDP_BUF_SIZE                                256*1024

#define LDP_MESSAGE_TYPE_NOTIFICATION               0x0001
#define LDP_MESSAGE_TYPE_HELLO                      0x0100
#define LDP_MESSAGE_TYPE_INITIALIZATION             0x0200
#define LDP_MESSAGE_TYPE_KEEPALIVE                  0x0201
#define LDP_MESSAGE_TYPE_ADDRESS                    0x0300
#define LDP_MESSAGE_TYPE_ADDRESS_WITHDRAW           0x0301
#define LDP_MESSAGE_TYPE_LABEL_MAPPING              0x0400
#define LDP_MESSAGE_TYPE_LABEL_REQUEST              0x0401
#define LDP_MESSAGE_TYPE_LABEL_WITHDRAW             0x0402
#define LDP_MESSAGE_TYPE_LABEL_RELEASE              0x0403
#define LDP_MESSAGE_TYPE_ABORT_REQUEST              0x0404

#define LDP_TLV_TYPE_MASK                           0x3FFF
#define LDP_TLV_TYPE_FEC                            0x0100
#define LDP_TLV_TYPE_ADDRESS_LIST                   0x0101
#define LDP_TLV_TYPE_HOP_COUNT                      0x0103
#define LDP_TLV_TYPE_PATH_VECTOR                    0x0104
#define LDP_TLV_TYPE_GENERIC_LABEL                  0x0200
#define LDP_TLV_TYPE_STATUS                         0x0300
#define LDP_TLV_TYPE_EXTENDED_STATUS                0x0301
#define LDP_TLV_TYPE_RETURNED_PDU                   0x0302
#define LDP_TLV_TYPE_RETURNED_MESSAGE               0x0303
#define LDP_TLV_TYPE_COMMON_HELLO_PARAMETERS        0x0400
#define LDP_TLV_TYPE_IPV4_TRANSPORT_ADDRESS         0x0401
#define LDP_TLV_TYPE_CONFIG_SEQ_NUMBER              0x0402
#define LDP_TLV_TYPE_IPV6_TRANSPORT_ADDRESS         0x0403
#define LDP_TLV_TYPE_COMMON_SESSION_PARAMETERS      0x0500
#define LDP_TLV_TYPE_LABEL_REQUEST_ID               0x0600
#define LDP_TLV_TYPE_DUAL_STACK_CAPABILITY          0x0701

#define LDP_TLV_LEN_MIN                             4
#define LDP_FEC_LEN_MIN                             4
#define LDP_FEC_ELEMENT_TYPE_PREFIX                 2
#define LDP_STATUS_LEN_MIN                          10

#define LDP_STATUS_SUCCESS                          0x00000000
#define LDP_STATUS_BAD_IDENTIFIER                   0x00000001
#define LDP_STATUS_BAD_VERSION                      0x00000002
#define LDP_STATUS_BAD_PDU_LEN                      0x00000003
#define LDP_STATUS_UNKNOWN_MSG_TYPE                 0x00000004
#define LDP_STATUS_BAD_MSG_LEN                      0x00000005
#define LDP_STATUS_UNKNOWN_TLV_TYPE                 0x00000006
#define LDP_STATUS_BAD_TLV_LEN                      0x00000007
#define LDP_STATUS_BAD_TLV_VALUE                    0x00000008
#define LDP_STATUS_HOLD_TIMER_EXPIRED               0x00000009
#define LDP_STATUS_KEEPALIVE_TIMER_EXPIRED          0x00000014

#define LDP_STATUS_SHUTDOWN                         0x0000000A
#define LDP_STATUS_INTERNAL_ERROR                   0x00000019

#define LDP_STATUS_FATAL_ERROR                      0x80000000
#define LDP_STATUS_FORWARD                          0x40000000

#define LDP_DEFAULT_KEEPALIVE_TIME                  15
#define LDP_DEFAULT_HOLD_TIME                       15
#define LDP_DEFAULT_TEARDOWN_TIME                   5

typedef enum ldp_state_ {
    LDP_CLOSED,
    LDP_IDLE,
    LDP_LISTEN,
    LDP_CONNECT,
    LDP_INITIALIZED,
    LDP_OPENREC,
    LDP_OPENSENT,
    LDP_OPERATIONAL,
    LDP_CLOSING,
    LDP_ERROR
} ldp_state_t;

typedef enum ldp_event_ {
    LDP_EVENT_START,
    LDP_EVENT_RX_INITIALIZED,
    LDP_EVENT_RX_KEEPALIVE,
} ldp_event_t;

typedef enum ldp_adjacency_state_ {
    LDP_ADJACENCY_STATE_DOWN   = 0,
    LDP_ADJACENCY_STATE_UP     = 1
} ldp_adjacency_state;    

typedef struct ldp_instance_ ldp_instance_s;
typedef struct ldp_session_ ldp_session_s;
typedef struct ldp_adjacency_ ldp_adjacency_s;

/*
 * LDP database entry
 */
typedef struct ldp_db_entry_ {
    iana_afi_t afi;
    bool active;
    union {
        ipv4_prefix ipv4;
        ipv6_prefix ipv6;
    } prefix;
    uint32_t label;
    uint32_t version;
    ldp_session_s *source;
} ldp_db_entry_s;

/*
 * LDP RAW Update File
 */
typedef struct ldp_raw_update_ {
    const char *file;

    uint8_t *buf;
    uint32_t len;
    uint32_t pdu; /* PDU counter */
    uint32_t messages; /* Message counter*/

    /* Pointer to next instance */
    struct ldp_raw_update_ *next;
} ldp_raw_update_s;

/*
 * LDP Instance Configuration.
 */
typedef struct ldp_config_ {

    uint16_t id; /* LDP instance identifier */
    uint32_t lsr_id;

    bool prefer_ipv4_transport;
    bool no_ipv4_transport;

    uint32_t   ipv4_transport_address;
    ipv6addr_t ipv6_transport_address;

    const char *lsr_id_str;
    const char *hostname;

    uint16_t keepalive_time;
    uint16_t hold_time;
    uint16_t teardown_time;
    uint8_t  tos; /* IPv4 TOS or IPv6 TC */

    char *raw_update_file;

    /* Pointer to next instance. */
    struct ldp_config_ *next; 
} ldp_config_s;

/*
 * LDP Session.
 */
typedef struct ldp_session_ {
    ldp_instance_s *instance;
    bbl_network_interface_s *interface;
    bbl_tcp_ctx_s *tcpc;
    bbl_tcp_ctx_s *listen_tcpc;

    struct timer_ *connect_timer;
    struct timer_ *keepalive_timer;
    struct timer_ *keepalive_timeout_timer;
    struct timer_ *close_timer;

    struct timer_ *update_timer;
    struct timer_ *teardown_timer;

    io_buffer_t read_buf;
    io_buffer_t write_buf;

    uint32_t pdu_start_idx;
    uint32_t msg_start_idx;
    uint32_t tlv_start_idx;
    uint32_t message_id;
    uint32_t error_code;

    bool decode_error;
    bool active;
    ldp_state_t state;
    uint32_t state_transitions;
    uint16_t max_pdu_len;
    uint16_t keepalive_time;

    bool ipv6; /* True for IPv6 transport session. */
    struct {
        ipv6addr_t ipv6_address;
        uint32_t ipv4_address;
        uint32_t lsr_id;
        uint16_t label_space_id;
        uint16_t keepalive_time;
        uint16_t max_pdu_len;
    } local;

    struct {
        ipv6addr_t ipv6_address;
        uint32_t ipv4_address;
        uint32_t lsr_id;
        uint16_t label_space_id;
        uint16_t keepalive_time;
        uint16_t max_pdu_len;
    } peer;

    struct {
        uint32_t pdu_rx;
        uint32_t pdu_tx;
        uint32_t message_rx;
        uint32_t message_tx;
        uint32_t keepalive_rx;
        uint32_t keepalive_tx;
    } stats;

    ldp_raw_update_s *raw_update_start;
    ldp_raw_update_s *raw_update;
    bool raw_update_sending;

    struct timespec operational_timestamp;
    struct timespec update_start_timestamp;
    struct timespec update_stop_timestamp;

    bool teardown;

    /* Pointer to next peer of 
     * corresponding instance. */
    struct ldp_session_ *next;
} ldp_session_s;

/*
 * LDP Adjacency.
 */
typedef struct ldp_adjacency_ {
    bbl_network_interface_s *interface;
    ldp_instance_s *instance;

    bool hello_ipv4;
    bool hello_ipv6;
    bool prefer_ipv4_transport;

    struct timer_ *hello_timer;
    struct timer_ *hold_timer;

    uint16_t hold_time;

    ldp_adjacency_state state;
    uint32_t state_transitions;

    /* Pointer to next adjacency of 
     * corresponding instance with. */
    struct ldp_adjacency_ *next;
} ldp_adjacency_s;

/*
 * LDP Instance
 */
typedef struct ldp_instance_ {
    ldp_config_s *config;

    bool teardown;
    
    struct timer_ *teardown_timer;

    ldp_adjacency_s *adjacencies;
    ldp_session_s *sessions;

    struct {
        hb_tree *ipv4;
        hb_tree *ipv6;
    } db; /* Label database. */

    /* Pointer to next instance. */
    struct ldp_instance_ *next;
} ldp_instance_s;

#endif