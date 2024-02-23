/*
 * BNG Blaster (BBL) - IS-IS Definitions
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_DEF_H__
#define __BBL_ISIS_DEF_H__

/* DEFINITIONS ... */

#define ISIS_PROTOCOL_IDENTIFIER        0x83

#define ISIS_HDR_LEN_COMMON             8
#define ISIS_HDR_LEN_P2P_HELLO          12
#define ISIS_HDR_LEN_CSNP               25
#define ISIS_HDR_LEN_PSNP               9
#define ISIS_HDR_LEN_LSP                19

#define ISIS_OFFSET_HDR_LEN             1
#define ISIS_OFFSET_HDR_SYSTEM_ID_LEN   3

#define ISIS_OFFSET_P2P_HELLO_LEVEL     8
#define ISIS_OFFSET_P2P_HELLO_SYSTEM_ID 9
#define ISIS_OFFSET_P2P_HELLO_HOLD_TIME 15
#define ISIS_OFFSET_P2P_HELLO_LEN       17

#define ISIS_OFFSET_CSNP_LEN            8
#define ISIS_OFFSET_CSNP_SOURCE_ID      10
#define ISIS_OFFSET_CSNP_LSP_START      17
#define ISIS_OFFSET_CSNP_LSP_END        25

#define ISIS_OFFSET_PSNP_LEN            8
#define ISIS_OFFSET_PSNP_SOURCE_ID      10

#define ISIS_OFFSET_LSP_LEN             8
#define ISIS_OFFSET_LSP_LIFETIME        10
#define ISIS_OFFSET_LSP_ID              12
#define ISIS_OFFSET_LSP_SEQ             20
#define ISIS_OFFSET_LSP_CHECKSUM        24

#define ISIS_MAX_AREA_LEN               13
#define ISIS_MAX_AREA_LEN_WITHOUT_AFI   12
#define ISIS_MAX_AREA_LEN_WITHOUT_AFI2B 6

#define ISIS_MAX_AREA_STR_LEN           38

#define ISIS_SOURCE_ID_LEN              7
#define ISIS_SYSTEM_ID_LEN              6
#define ISIS_SYSTEM_ID_STR_LEN          15

#define ISIS_LSP_ID_STR_LEN             21
#define ISIS_LSP_ENTRY_LEN              16

#define ISIS_LEVELS                     2
#define ISIS_LEVEL_1                    1
#define ISIS_LEVEL_1_IDX                0
#define ISIS_LEVEL_2                    2
#define ISIS_LEVEL_2_IDX                1

#define ISIS_DEFAULT_HELLO_INTERVAL     10
#define ISIS_DEFAULT_CSNP_INTERVAL      30
#define ISIS_DEFAULT_HOLD_TIME          30
#define ISIS_DEFAULT_LSP_LIFETIME_MIN   330
#define ISIS_DEFAULT_LSP_LIFETIME       65535
#define ISIS_DEFAULT_LSP_RETRY_IVL      5
#define ISIS_DEFAULT_LSP_REFRESH_IVL    300
#define ISIS_DEFAULT_LSP_TX_IVL_MS      10
#define ISIS_DEFAULT_LSP_WINDOWS_SIZE   1

#define ISIS_DEFAULT_TEARDOWN_TIME      5

#define ISIS_LSP_GC_INTERVAL            30
#define ISIS_LSP_GC_DELETE_MAX          256

#define ISIS_PROTOCOLS_MAX              2
#define ISIS_PROTOCOL_IPV4              0xcc
#define ISIS_PROTOCOL_IPV6              0x8e

#define ISIS_LSP_PAYLOAD_BUF_LEN        2048

#define ISIS_LSP_OVERLOAD_BIT           0x04

#define ISIS_MAX_PDU_LEN_RX             1497 /* 1500-3 byte LLC */
#define ISIS_MAX_PDU_LEN                1492

#define ISIS_MD5_DIGEST_LEN             16

typedef struct isis_config_ isis_config_s;
typedef struct isis_instance_ isis_instance_s;
typedef struct isis_adjacency_ isis_adjacency_s;
typedef struct isis_adjacency_p2p_ isis_adjacency_p2p_s;

/* ENUMS ... */

typedef enum isis_adjacency_state_ {
    ISIS_ADJACENCY_STATE_DOWN   = 0,
    ISIS_ADJACENCY_STATE_UP     = 1
} isis_adjacency_state;    

typedef enum isis_p2p_adjacency_state_ {
    ISIS_P2P_ADJACENCY_STATE_UP     = 0,
    ISIS_P2P_ADJACENCY_STATE_INIT   = 1,
    ISIS_P2P_ADJACENCY_STATE_DOWN   = 2
} isis_p2p_adjacency_state;

typedef enum isis_auth_type_{
    ISIS_AUTH_NONE              = 0,
    ISIS_AUTH_CLEARTEXT         = 1,
    ISIS_AUTH_HMAC_MD5          = 54  
} __attribute__ ((__packed__)) isis_auth_type;

typedef enum isis_lsp_source_{
    ISIS_SOURCE_SELF,       /* Self originated LSP */
    ISIS_SOURCE_ADJACENCY,  /* LSP learned from neighbors */
    ISIS_SOURCE_EXTERNAL    /* LSP injected externally (e.g. MRT file, ...) */
} isis_lsp_source;

typedef enum isis_pdu_type_ {
    ISIS_PDU_L1_HELLO   = 15,
    ISIS_PDU_L2_HELLO   = 16,
    ISIS_PDU_P2P_HELLO  = 17,
    ISIS_PDU_L1_LSP     = 18,
    ISIS_PDU_L2_LSP     = 20,
    ISIS_PDU_L1_CSNP    = 24,
    ISIS_PDU_L2_CSNP    = 25,
    ISIS_PDU_L1_PSNP    = 26,
    ISIS_PDU_L2_PSNP    = 27,
} isis_pdu_type;

/* IS-IS TLV Codepoints
 * https://www.iana.org/assignments/isis-tlv-codepoints/isis-tlv-codepoints.xhtml
 */
typedef enum isis_tlv_type_ {   
    ISIS_TLV_AREA_ADDRESSES         = 1,
    ISIS_TLV_PADDING                = 8,
    ISIS_TLV_LSP_ENTRIES            = 9,
    ISIS_TLV_AUTH                   = 10,
    ISIS_TLV_EXT_REACHABILITY       = 22,
    ISIS_TLV_PROTOCOLS              = 129,
    ISIS_TLV_IPV4_INT_ADDRESS       = 132,
    ISIS_TLV_TE_ROUTER_ID           = 134,
    ISIS_TLV_EXT_IPV4_REACHABILITY  = 135,
    ISIS_TLV_HOSTNAME               = 137,
    ISIS_TLV_IPV6_INT_ADDRESS       = 232,
    ISIS_TLV_IPV6_REACHABILITY      = 236,
    ISIS_TLV_P2P_ADJACENCY_STATE    = 240,
    ISIS_TLV_ROUTER_CAPABILITY      = 242
} isis_tlv_type;

/* STRUCTURES ... */

typedef struct isis_tlv_ {
    uint8_t  type;
    uint8_t  len;
    uint8_t  value[];
} __attribute__ ((__packed__)) isis_tlv_s;

typedef struct isis_sub_tlv_ {
    uint8_t  type;
    uint8_t  len;
    uint8_t *value;
    struct isis_sub_tlv_ *next;
} isis_sub_tlv_t;

typedef struct isis_lsp_entry_ {
    uint16_t  lifetime;
    uint64_t  lsp_id;
    uint32_t  seq;
    uint16_t  checksum;
} __attribute__ ((__packed__)) isis_lsp_entry_s;

typedef struct isis_area_ {
    const char *str;
    uint8_t     len;
    uint8_t    *value;
} isis_area_s;

typedef struct isis_external_connection_ {
    uint8_t  system_id[ISIS_SYSTEM_ID_LEN];

    struct {
        uint32_t metric;
    } level[ISIS_LEVELS];

    struct isis_external_connection_ *next;
} isis_external_connection_s;

/*
 * IS-IS Instance Configuration
 */
typedef struct isis_config_ {

    uint16_t id; /* IS-IS instance identifier */

    bool                overload;
    uint8_t             level;

    isis_auth_type      level1_auth;
    char               *level1_key;
    bool                level1_auth_hello;
    bool                level1_auth_csnp;
    bool                level1_auth_psnp;

    isis_auth_type      level2_auth;
    char               *level2_key;
    bool                level2_auth_hello;
    bool                level2_auth_csnp;
    bool                level2_auth_psnp;

    uint16_t            lsp_refresh_interval;
    uint16_t            lsp_lifetime;
    uint16_t            hello_interval;
    uint16_t            hold_time;
    uint16_t            teardown_time;

    const char         *hostname;
    const char         *router_id_str;
    ipv4addr_t          router_id;
    const char         *system_id_str;
    uint8_t             system_id[ISIS_SYSTEM_ID_LEN];

    isis_area_s        *area;
    uint8_t             area_count;

    bool                protocol_ipv4;
    bool                protocol_ipv6;
    bool                hello_padding;

    uint16_t            lsp_tx_window_size; /* LSP TX window size */
    uint16_t            lsp_tx_interval;    /* LSP TX interval in MS (default 10ms) */
    uint16_t            lsp_retry_interval; /* LSP retry interval in seconds (default 5s) */
    uint16_t            csnp_interval;      /* CSNP interval in seconds (default 5s) */

    uint32_t            sr_base;
    uint32_t            sr_range;
    uint32_t            sr_node_sid;
    
    /* External */
    bool external_purge;
    bool external_auto_refresh;
    char *external_mrt_file;
    struct isis_external_connection_ *external_connection;

    /* Pointer to next instance */
    struct isis_config_ *next; 
} isis_config_s;

typedef struct isis_peer_ {
    uint8_t  level;
    uint8_t  system_id[ISIS_SYSTEM_ID_LEN];
    uint16_t hold_time;
    char    *hostname;
} isis_peer_s;

typedef struct isis_adjacency_ {
    bbl_network_interface_s *interface;
    isis_instance_s *instance;
    isis_peer_s *peer;

    /* Pointer to next adjacency of 
     * corresponding instance with 
     * same level. */
    struct isis_adjacency_ *next; 

    hb_tree         *flood_tree;
    hb_tree         *psnp_tree;

    struct timer_   *timer_tx;
    struct timer_   *timer_retry;
    struct timer_   *timer_csnp;
    struct timer_   *timer_csnp_next;
    struct timer_   *timer_psnp_next;
    struct timer_   *timer_hold;

    bool timer_psnp_started;

    uint8_t  level;
    uint8_t  state;
    uint16_t window_size;

    uint32_t metric;
    uint64_t csnp_start;

    struct {
        uint32_t hello_rx;
        uint32_t hello_tx;
        uint32_t csnp_rx;
        uint32_t csnp_tx;
        uint32_t psnp_rx;
        uint32_t psnp_tx;
        uint32_t lsp_rx;
        uint32_t lsp_tx;
    } stats;

} isis_adjacency_s;

typedef struct isis_adjacency_p2p_ {
    bbl_network_interface_s *interface;
    isis_instance_s *instance;
    isis_peer_s *peer;
    
    uint8_t level;
    uint8_t state;

    struct {
        uint32_t hello_rx;
        uint32_t hello_tx;
    } stats;

} isis_adjacency_p2p_s;

typedef struct isis_instance_ {
    isis_config_s  *config;
    bool            overload;

    bool            teardown;
    struct timer_  *timer_teardown;
    struct timer_  *timer_lsp_gc;

    struct {
        hb_tree *lsdb;
        isis_adjacency_s *adjacency;
        uint8_t self_lsp_fragment;
    } level[ISIS_LEVELS];

    struct isis_instance_ *next; /* pointer to next instance */
} isis_instance_s;

/*
 * IS-IS PDU context
 */
typedef struct isis_pdu_ {
    uint8_t  pdu_type;
    uint8_t  auth_type;
    uint8_t  auth_data_len;
    uint16_t auth_data_offset;
    uint16_t tlv_offset;

    uint16_t cur; /* current position */

    uint8_t  pdu[ISIS_MAX_PDU_LEN];
    uint16_t pdu_len;
} isis_pdu_s;

typedef struct isis_lsp_ {

    uint64_t id; /* LSP-ID */
    uint64_t csnp_scan;
    uint8_t  level;

    isis_instance_s *instance;

    struct {
        isis_lsp_source type;
        isis_adjacency_s *adjacency;
    } source;

    /* LSP receive timestamp for 
     * remaining lifetime calculation. */
    struct timespec timestamp;

    struct timer_ *timer_lifetime;
    struct timer_ *timer_refresh;

    uint32_t refcount;
    bool expired;
    bool deleted;

    uint32_t seq; /* Sequence number */
    uint16_t lifetime; /* Remaining lifetime */

    char *auth_key;

    isis_pdu_s pdu;
} isis_lsp_s;

/* IS-IS LSP flood entry */
typedef struct isis_flood_entry_ {
    isis_lsp_s     *lsp;
    bool            wait_ack;
    uint32_t        tx_count;
    struct timespec tx_timestamp;
} isis_flood_entry_s;

typedef struct isis_lsp_flap_ {
    uint64_t id; /* LSP-ID */

    isis_instance_s *instance;
    isis_pdu_s pdu;

    bool free;
    struct timer_ *timer;

    struct isis_lsp_flap_ *next;
} isis_lsp_flap_s;

#endif