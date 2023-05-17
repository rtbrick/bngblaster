/*
 * BNG Blaster (BBL) - OSPF Definitions
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_DEF_H__
#define __BBL_OSPF_DEF_H__

/* DEFINITIONS ... */

#define OSPF_DEFAULT_HELLO_INTERVAL     10
#define OSPF_LSA_TYPES                  12

#define OSPF_HDR_LEN_MIN                12
#define OSPF_PDU_LEN_MIN                16
#define OSPF_PDU_LEN_MAX                UINT16_MAX

#define OSPF_DEFAULT_TEARDOWN_TIME      5

#define OSPF_LSA_GC_INTERVAL            30

#define OSPF_OFFSET_VERSION             0
#define OSPF_OFFSET_TYPE                1
#define OSPF_OFFSET_PACKET_LEN          2
#define OSPF_OFFSET_ROUTER_ID           4
#define OSPF_OFFSET_AREA_ID             8
#define OSPF_OFFSET_CHECKSUM            12

#define OSPFV2_OFFSET_AUTH_TYPE         14
#define OSPFV2_OFFSET_AUTH_DATA         16
#define OSPFV2_OFFSET_PACKET            24

#define OSPFV3_OFFSET_INSTANCE_ID       14
#define OSPFV3_OFFSET_PACKET            16


typedef struct ospf_config_ ospf_config_s;
typedef struct ospf_instance_ ospf_instance_s;
typedef struct ospf_adjacency_ ospf_adjacency_s;
typedef struct ospf_adjacency_p2p_ ospf_adjacency_p2p_s;

/* ENUMS ... */

typedef enum ospf_adjacency_state_ {
    OSPF_ADJACENCY_STATE_DOWN   = 0,
    OSPF_ADJACENCY_STATE_UP     = 1
} ospf_adjacency_state;    

typedef enum ospf_p2p_adjacency_state_ {
    OSPF_P2P_ADJACENCY_STATE_UP     = 0,
    OSPF_P2P_ADJACENCY_STATE_INIT   = 1,
    OSPF_P2P_ADJACENCY_STATE_DOWN   = 2
} ospf_p2p_adjacency_state;

typedef enum ospf_auth_type_ {
    OSPF_AUTH_NONE              = 0,
    OSPF_AUTH_CLEARTEXT         = 1,
    OSPF_AUTH_MD5               = 2
} __attribute__ ((__packed__)) ospf_auth_type;

typedef enum ospf_lsp_source_ {
    OSPF_SOURCE_SELF,       /* Self originated LSA */
    OSPF_SOURCE_ADJACENCY,  /* LSA learned from neighbors */
    OSPF_SOURCE_EXTERNAL    /* LSA injected externally (e.g. MRT file, ...) */
} ospf_lsp_source;

typedef enum ospf_pdu_type_ {
    OSPF_PDU_L1_HELLO   = 15,
    OSPF_PDU_L2_HELLO   = 16,
    OSPF_PDU_P2P_HELLO  = 17,
    OSPF_PDU_L1_LSP     = 18,
    OSPF_PDU_L2_LSP     = 20,
    OSPF_PDU_L1_CSNP    = 24,
    OSPF_PDU_L2_CSNP    = 25,
    OSPF_PDU_L1_PSNP    = 26,
    OSPF_PDU_L2_PSNP    = 27,
} ospf_pdu_type;

typedef enum ospf_lsa_type_ {
    OSPF_LSA_TYPE_1     = 1,
    OSPF_LSA_TYPE_2     = 2,
    OSPF_LSA_TYPE_3     = 3,
    OSPF_LSA_TYPE_4     = 4,
    OSPF_LSA_TYPE_5     = 5,
    OSPF_LSA_TYPE_6     = 6,
    OSPF_LSA_TYPE_7     = 7,
    OSPF_LSA_TYPE_8     = 8,
    OSPF_LSA_TYPE_9     = 9,
    OSPF_LSA_TYPE_10    = 10,
    OSPF_LSA_TYPE_11    = 11,
    OSPF_LSA_TYPE_MAX,
} ospf_lsa_type;

typedef enum ospf_lsa_scope_ {
    OSPF_LSA_SCOPE_LINK_LOCAL   = 0x0,
    OSPF_LSA_SCOPE_AREA         = 0x2,
    OSPF_LSA_SCOPE_AS           = 0x4
} ospf_lsa_scope;

/* STRUCTURES ... */

/*
 * OSPF PDU context
 */
typedef struct ospf_pdu_ {
    uint8_t  version;
    uint8_t  type;
    uint32_t router_id;
    uint32_t area_id;
    uint16_t checksum;

    uint8_t  auth_type;
    uint8_t  auth_data_len;
    uint16_t auth_data_offset;
    uint16_t packet_offset;

    uint16_t cur; /* current position */

    uint8_t *pdu;
    uint16_t pdu_len;
} ospf_pdu_s;

typedef struct ospf_lsa_entry_ {
    uint16_t  lifetime;
    uint64_t  lsp_id;
    uint32_t  seq;
    uint16_t  checksum;
} __attribute__ ((__packed__)) isis_lsa_entry_s;

typedef struct ospf_external_connection_ {
    const char         *router_id_str;
    ipv4addr_t          router_id;
    uint32_t            metric;
    struct ospf_external_connection_ *next;
} ospf_external_connection_s;

/*
 * OSPF Instance Configuration
 */
typedef struct ospf_config_ {

    uint16_t id; /* OSPF instance identifier */
    uint8_t  version; /* OSPF version (default 2) */

    const char         *area_str;
    ipv4addr_t          area;

    const char         *router_id_str;
    ipv4addr_t          router_id;

    bool                overload;

    ospf_auth_type      auth_type;
    char               *auth_key;

    uint16_t            hello_interval;
    uint16_t            teardown_time;

    const char         *hostname;

    char *external_mrt_file;
    struct ospf_external_connection_ *external_connection;

    /* Pointer to next instance */
    struct ospf_config_ *next; 
} ospf_config_s;

typedef struct ospf_adjacency_ {
    bbl_network_interface_s *interface;
    ospf_instance_s *instance;

    /* Pointer to next adjacency of 
     * corresponding instance with 
     * same level. */
    struct ospf_adjacency_ *next; 

    hb_tree         *flood_tree;

    struct timer_   *timer_tx;
    struct timer_   *timer_retry;

    uint8_t  state;
    uint16_t window_size;

    uint32_t metric;

    struct {
        uint32_t hello_rx;
        uint32_t hello_tx;
    } stats;

} ospf_adjacency_s;

typedef struct ospf_adjacency_p2p_ {
    bbl_network_interface_s *interface;
    ospf_instance_s *instance;
    
    uint8_t level;
    uint8_t state;

    struct {
        uint32_t hello_rx;
        uint32_t hello_tx;
    } stats;

} ospf_adjacency_p2p_s;

typedef struct ospf_instance_ {
    ospf_config_s  *config;
    bool            overload;

    bool            teardown;
    struct timer_  *timer_teardown;
    struct timer_  *timer_lsa_gc;

    struct {
        hb_tree *db;
    } lsdb[OSPF_LSA_TYPES];

    ospf_adjacency_s *adjacency;

    struct ospf_instance_ *next; /* pointer to next instance */
} ospf_instance_s;

#endif