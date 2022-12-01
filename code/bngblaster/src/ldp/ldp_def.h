/*
 * BNG Blaster (BBL) - LDP Definitions
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_DEF_H__
#define __BBL_LDP_DEF_H__

/* DEFINITIONS ... */

#define LDP_PORT                                    646
#define LDP_IDENTIFIER_LEN                          6U
#define LDP_MAX_PDU_LEN_INIT                        4096U

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

#define LDP_TLV_LEN_MIN                             4

#define LDP_DEFAULT_HELLO_INTERVAL                  10
#define LDP_DEFAULT_HOLD_TIME                    30
#define LDP_DEFAULT_TEARDOWN_TIME                   5

typedef enum ldp_state_ {
    LDP_NON_EXISTENT,
    LDP_INITIALIZED,
    LDP_OPENREC,
    LDP_OPENSENT,
    LDP_OPERATIONAL,
} ldp_state_t;

typedef struct ldp_instance_ ldp_instance_s;
typedef struct ldp_session_ ldp_session_s;
typedef struct ldp_adjacency_ ldp_adjacency_s;

/*
 * LDP Type-Length-Value (TLV). 
 */
typedef struct ldp_tlv_ {
    bool u_bit; /* Unknown TLV bit. */
    bool f_bit; /* Forward unknown TLV bit. */
    uint16_t type;
    uint16_t len;
    uint8_t *value;
    struct ldp_tlv_ *next;
} ldp_tlv_s;

/*
 * LDP Message which contains
 * one or more LDP TLV.
 */
typedef struct ldp_message_ {
    bool u_bit; /* Unknown message bit. */
    uint16_t type;
    uint32_t msg_id;
    ldp_tlv_s *tlv;
    struct ldp_message_ *next;
} ldp_message_s;

/*
 * LDP Protocol Data Unit (PDU) which contains 
 * one or more LDP messages.
 */
typedef struct ldp_pdu_ {
    uint16_t version;
    uint16_t len;
    uint32_t lsr_id;
    uint16_t label_space_id;
    ldp_message_s *message;
} ldp_pdu_s;

/*
 * LDP Instance Configuration.
 */
typedef struct ldp_config_ {

    uint16_t id; /* LDP instance identifier */
    uint32_t lsr_id;
    uint32_t ipv4_transport_address;
    const char *lsr_id_str;
    const char *hostname;

    bool overload;

    uint16_t hello_interval;
    uint16_t hold_time;
    uint16_t teardown_time;

    /* Pointer to next instance. */
    struct ldp_config_ *next; 
} ldp_config_s;

/*
 * LDP Session.
 */
typedef struct ldp_session_ {
    struct {
        uint32_t ipv4_address;
        uint32_t lsr_id;
        uint16_t label_space_id;
        uint16_t hold_time;
    } local;

    struct {
        uint32_t ipv4_address;
        uint32_t lsr_id;
        uint16_t label_space_id;
        uint16_t hold_time;
    } peer;

    struct {
        uint32_t message_rx;
        uint32_t message_tx;
        uint32_t keepalive_rx;
        uint32_t keepalive_tx;
    } stats;

    struct {
        bool e_bit; /* Fatal error bit. */
        bool f_bit; /* Forward bit. */
        uint32_t code;
        uint16_t msg_type;
    } status;

    uint16_t max_pdu_len;

    ldp_instance_s *instance;
    ldp_state_t state;

    io_buffer_t read_buf;
    io_buffer_t write_buf;

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
    ldp_session_s *session;

    struct timer_ *hello_timer;

    /* Pointer to next adjacency of 
     * corresponding instance with. */
    struct ldp_adjacency_ *next;
} ldp_adjacency_s;

/*
 * LDP Instance
 */
typedef struct ldp_instance_ {
    ldp_config_s *config;

    bool overload;
    bool teardown;
    
    struct timer_ *teardown_timer;

    ldp_adjacency_s *adjacencies;
    ldp_session_s *sessions;

    hb_tree *ldb; /* Label database. */

    /* Pointer to next instance. */
    struct ldp_instance_ *next;
} ldp_instance_s;

#endif