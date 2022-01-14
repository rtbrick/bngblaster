/*
 * BNG Blaster (BBL) - IS-IS Functions
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_ISIS_H__
#define __BBL_ISIS_H__

#define ISIS_PROTOCOL_IDENTIFIER        0x83
#define ISIS_MIN_HDR_LEN                8

#define ISIS_PDU_L1_HELLO               15
#define ISIS_PDU_L2_HELLO               16
#define ISIS_PDU_P2P_HELLO              17
#define ISIS_PDU_L1_LSP                 18
#define ISIS_PDU_L2_LSP                 20
#define ISIS_PDU_L1_CSNP                24
#define ISIS_PDU_L2_CSNP                25
#define ISIS_PDU_L1_PSNP                26
#define ISIS_PDU_L2_PSNP                27

#define ISIS_TLV_AREA                   1
#define ISIS_TLV_PROTOCOLS              129
#define ISIS_TLV_IPV4_INT_ADDRESS       132
#define ISIS_TLV_IPV6_INT_ADDRESS       232
#define ISIS_TLV_P2P_ADJACENCY_STATE    240

#define ISIS_MAX_AREA_LEN               13
#define ISIS_MAX_AREA_LEN_WITHOUT_AFI   12
#define ISIS_MAX_AREA_LEN_WITHOUT_AFI2B 6

#define ISIS_MAX_AREA_STR_LEN           38

#define ISIS_SYSTEM_ID_LEN              6
#define ISIS_SYSTEM_ID_STR_LEN          15

#define ISIS_LEVEL_1                    1
#define ISIS_LEVEL_2                    2

#define ISIS_ADJACENCY_STATE_UP         0
#define ISIS_ADJACENCY_STATE_INIT       1
#define ISIS_ADJACENCY_STATE_DOWN       2

#define ISIS_DEFAULT_HELLO_INTERVAL     10
#define ISIS_DEFAULT_HOLDING_TIME       30
#define ISIS_DEFAULT_LSP_LIFETIME       65535

#define ISIS_PROTOCOL_IPV4              0xcc
#define ISIS_PROTOCOL_IPV6              0x8e

typedef struct bbl_isis_area_ {
    const char *str;
    uint8_t    len;
    uint8_t    value[ISIS_MAX_AREA_LEN];
} bbl_isis_area_t;

typedef enum {
    ISIS_AUTH_MD5
} bbl_isis_auth_type;

/*
 * IS-IS Instance
 */
typedef struct bbl_isis_config_ {
    
    uint16_t id; /* IS-IS instance identifier */

    bool            overload;

    uint8_t         level;

    bool            protocol_ipv4;
    bool            protocol_ipv6;

    bbl_isis_auth_type  level1_auth;
    char           *level1_key;
    bbl_isis_auth_type  level2_auth;
    char           *level2_key;

    uint16_t        hello_interval;
    uint16_t        holding_time;
    uint16_t        lsp_lifetime;

    const char     *hostname;

    const char     *router_id_str;
    uint32_t        router_id;

    const char     *system_id_str;
    uint8_t         system_id[ISIS_SYSTEM_ID_LEN];

    bbl_isis_area_t    *area;
    uint8_t         area_count;

    void *next; /* pointer to next instance */
} bbl_isis_config_t;

typedef struct bbl_isis_instance_ {

    bbl_isis_config_t  *config;

    uint8_t         fsm_state;
    bool            overload;

    struct {
        uint32_t hello_rx;
        uint32_t hello_tx;
    } stats;

    void *next; /* pointer to next instance */
} bbl_isis_instance_t;

typedef struct bbl_isis_adjacency_ {
    uint8_t level;
    uint8_t adjacency_state;
    
    struct {
        uint8_t      level;
        uint8_t      adjacency_state;
        uint8_t      system_id[ISIS_SYSTEM_ID_LEN];
        bbl_isis_area_t *area;
        uint8_t      area_count;
        bool         protocol_ipv4;
        bool         protocol_ipv6;
        uint32_t     ipv4_interface_address;
        ipv6addr_t   ipv6_interface_address;
    } peer;

    struct {
        uint32_t hello_rx;
        uint32_t hello_tx;
    } stats;
} bbl_isis_adjacency_t;

bool
bbl_isis_init(bbl_ctx_s *ctx);

bool
bbl_isis_str_to_area(const char *str, bbl_isis_area_t *area);

char *
bbl_bbl_isis_area_to_str(bbl_isis_area_t *area);

bool
bbl_isis_str_to_system_id(const char *str, uint16_t *system_id);

char *
bbl_isis_system_id_to_str(uint16_t *system_id);

protocol_error_t
bbl_isis_encode_p2p_hello(bbl_interface_s *interface, 
                          uint8_t *buf, uint16_t *len, 
                          bbl_ethernet_header_t *eth);

void
bbl_isis_handler_rx(bbl_ethernet_header_t *eth, bbl_interface_s *interface);

json_t *
bbl_isis_interface_json(bbl_interface_s *interface);
#endif