/*
 * BNG Blaster (BBL) - IS-IS Helper Functions
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

const char *
isis_level_string(uint8_t level) {
    switch(level) {
        case 1: return "L1";
        case 2: return "L2";
        case 3: return "L1L2";
        default: return "INVALID";
    }
}

const char *
isis_p2p_adjacency_state_string(uint8_t state) {
    switch(state) {
        case ISIS_P2P_ADJACENCY_STATE_UP: return "Up";
        case ISIS_P2P_ADJACENCY_STATE_INIT: return "Init";
        case ISIS_P2P_ADJACENCY_STATE_DOWN: return "Down";
        default: return "INVALID";
    }
}

const char *
isis_adjacency_state_string(uint8_t state) {
    switch(state) {
        case ISIS_ADJACENCY_STATE_DOWN: return "Up";
        case ISIS_ADJACENCY_STATE_UP: return "Down";
        default: return "INVALID";
    }
}

const char *
isis_pdu_type_string(uint8_t type) {
    switch(type) {
        case ISIS_PDU_L1_HELLO: return "L1-Hello";
        case ISIS_PDU_L2_HELLO: return "L2-Hello";
        case ISIS_PDU_P2P_HELLO: return "P2P-Hello";
        case ISIS_PDU_L1_LSP: return "L1-LSP";
        case ISIS_PDU_L2_LSP: return "L2-LSP";
        case ISIS_PDU_L1_CSNP: return "L1-CSNP";
        case ISIS_PDU_L2_CSNP: return "L2-CSNP";
        case ISIS_PDU_L1_PSNP: return "L1-PSNP";
        case ISIS_PDU_L2_PSNP: return "L2-PSNP";
        default: return "UNKNOWN";
    }
}

/**
 * isis_str_to_area
 * 
 * This function populates an area 
 * structure from a given area string
 * like "49.0001/24". 
 * 
 * @param str area string
 * @param area area structure
 * @return true if successfull
 */
bool
isis_str_to_area(const char *str, isis_area_t *area) {
    
    int len = 0;
    uint16_t *a;
    char *ptr;

    if(!area->value) {
        area->value = calloc(1, ISIS_MAX_AREA_LEN);
    }
    a = (uint16_t*)&area->value[1];
    sscanf(str, "%hhx.%hx.%hx.%hx.%hx.%hx.%hx", 
           area->value, 
           &a[0], &a[1], &a[2], 
           &a[3], &a[4], &a[5]);

    for(int i = 0; i < ISIS_MAX_AREA_LEN_WITHOUT_AFI2B; i++) {
        a[i] = htobe16(a[i]);
    }
    memcpy(area->value+1, a, ISIS_MAX_AREA_LEN_WITHOUT_AFI);

    ptr = strchr(str, '/');
    if(!ptr) {
        return false;
    }
    sscanf(ptr, "/%d", &len);

    /* The area length must be a multiple 
     * of 8 between 8 and 104. */
    if(len < 8 || len > 104 || len % 8) {
        return false;
    }
    
    area->str = str;
    area->len = BITS_TO_BYTES(len);
    return true;
}

/**
 * isis_area_to_str
 * 
 * Format an IS-IS area as string 
 * in one of 4 static buffers.
 * 
 * @param area area structure
 * @return IS-IS area string
 */
char *
isis_area_to_str(isis_area_t *area) {
    static char buffer[4][ISIS_MAX_AREA_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 3;

    uint16_t *a =  (uint16_t*)&area->value[1];
    int offset;
    int i;

    offset = snprintf(ret, ISIS_MAX_AREA_STR_LEN, "%x", area->value[0]);
    for(i=0; i<ISIS_MAX_AREA_LEN_WITHOUT_AFI2B; i++) {
        offset += snprintf(&ret[offset], ISIS_MAX_AREA_STR_LEN - offset, 
                           ".%04x", be16toh(a[i]));
    }
    snprintf(&ret[offset], ISIS_MAX_AREA_STR_LEN - offset, "/%d", (area->len * 8));    
    
    return ret;
}

/**
 * isis_str_to_system_id
 *
 * @param str system-id string
 * @param system_id system-id
 * @return true if successfull
 */
bool
isis_str_to_system_id(const char *str, uint8_t *system_id) {    
    sscanf(str, "%hx.%hx.%hx", 
           &((uint16_t*)system_id)[0], 
           &((uint16_t*)system_id)[1], 
           &((uint16_t*)system_id)[2]);

    for(uint8_t i = 0; i < (ISIS_SYSTEM_ID_LEN/sizeof(uint16_t)); i++) {
        ((uint16_t*)system_id)[i] = htobe16(((uint16_t*)system_id)[i]);
    }

    return true;
}

/**
 * isis_system_id_to_str
 *
 * Format an IS-IS system-id as string 
 * in one of 4 static buffers.
 *
 * @param system_id IS-IS system-id (6 bytes)
 * @return IS-IS system-id string
 */
char *
isis_system_id_to_str (uint8_t *system_id)
{
    static char buffer[4][ISIS_SYSTEM_ID_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 3;

    snprintf(ret, ISIS_SYSTEM_ID_STR_LEN, "%04x.%04x.%04x",
             be16toh(((uint16_t*)system_id)[0]), 
             be16toh(((uint16_t*)system_id)[1]), 
             be16toh(((uint16_t*)system_id)[2]));

    return ret;
}

/**
 * isis_lsp_id_to_str
 *
 * Format an IS-IS lsp-id as string 
 * in one of 4 static buffers.
 *
 * @param lsp_id IS-IS lsp-id (8 bytes)
 * @return IS-IS lsp-id string
 */
char *
isis_lsp_id_to_str(uint64_t *lsp_id)
{
    static char buffer[4][ISIS_LSP_ID_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 3;

    snprintf(ret, ISIS_LSP_ID_STR_LEN, "%04x.%04x.%04x.%02x-%02x",
             ((uint16_t*)lsp_id)[3], 
             ((uint16_t*)lsp_id)[2], 
             ((uint16_t*)lsp_id)[1], 
             ((uint8_t*)lsp_id)[1],
             ((uint8_t*)lsp_id)[0]);

    return ret;
}