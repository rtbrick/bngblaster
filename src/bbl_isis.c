/*
 * BNG Blaster (BBL) - IS-IS Functions
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"

uint8_t g_isis_mac_hello[] = {0x09, 0x00, 0x2b, 0x00, 0x00, 0x05};

/**
 * bbl_isis_init
 * 
 * Init 
 * 
 * @param ctx global context
 */
bool
bbl_isis_init(bbl_ctx_s *ctx) {

    bbl_isis_config_t *config = ctx->config.isis_config;
    bbl_isis_instance_t *instance = NULL;

    while(config) {
        LOG(ISIS, "Init IS-IS instance %u\n", config->id);
        if(instance) {
            instance->next = calloc(1, sizeof(bbl_isis_instance_t));
            instance = instance->next;
        } else {
            instance = calloc(1, sizeof(bbl_isis_instance_t));
            ctx->isis_instances = instance;
        }
        instance->config = config;
        config = config->next;
    }
    return true;
}

/**
 * bbl_isis_str_to_area
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
bbl_isis_str_to_area(const char *str, bbl_isis_area_t *area) {
    
    int len = 0;
    char *ptr;

    uint16_t *a = (uint16_t*)&area->value[1];
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
 * bbl_isis_str_to_area
 * 
 * This function the string representation
 * of the given area structure. This string
 * must be freed after use (strdup).
 * 
 * @param area area structure
 * @return area string
 */
char *
bbl_bbl_isis_area_to_str(bbl_isis_area_t *area) {
    char str[ISIS_MAX_AREA_STR_LEN] = {0};
    uint16_t *a =  (uint16_t*)&area->value[1];
    int offset; 
    int i;

    offset = snprintf(str, ISIS_MAX_AREA_STR_LEN, "%x", area->value[0]);
    for(i=0; i<ISIS_MAX_AREA_LEN_WITHOUT_AFI2B; i++) {
        offset += snprintf(&str[offset], ISIS_MAX_AREA_STR_LEN - offset, 
                           ".%04x", be16toh(a[i]));
    }
    snprintf(&str[offset], ISIS_MAX_AREA_STR_LEN - offset, "/%d", (area->len * 8));    
    return strdup(str);
}

/**
 * bbl_isis_str_to_area
 *
 * @param str system-id string
 * @param system_id system-id
 * @return true if successfull
 */
bool
bbl_isis_str_to_system_id(const char *str, uint16_t *system_id) {    
    sscanf(str, "%hx.%hx.%hx", 
           &system_id[0], &system_id[1], &system_id[2]);

    for(uint8_t i = 0; i < (ISIS_SYSTEM_ID_LEN/sizeof(uint16_t)); i++) {
        system_id[i] = htobe16(system_id[i]);
    }

    return true;
}

/**
 * bbl_isis_system_id_to_str
 * 
 * This function the string representation
 * of the given system-id. This string
 * must be freed after use (strdup).
 * 
 * @param system_id system-id
 * @return system-id string
 */
char *
bbl_isis_system_id_to_str(uint16_t *system_id) {
    char str[ISIS_SYSTEM_ID_STR_LEN] = {0};
    snprintf(str, ISIS_SYSTEM_ID_STR_LEN, "%04x.%04x.%04x",
             be16toh(system_id[0]), 
             be16toh(system_id[1]), 
             be16toh(system_id[2]));
    return strdup(str);
}

void
bbl_isis_hello_timeout (timer_s *timer)
{
    bbl_interface_s *interface = timer->data;
    interface->send_requests |= BBL_IF_SEND_ISIS_HELLO;
}


/**
 * bbl_isis_encode_p2p_hello
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
bbl_isis_encode_p2p_hello(bbl_interface_s *interface, 
                          uint8_t *buf, uint16_t *len, 
                          bbl_ethernet_header_t *eth) {

    bbl_isis_t isis = {0};
    bbl_isis_adjacency_t *adjacency = interface->isis.adjacency;
    bbl_isis_config_t *config = interface->isis.instance->config;
    
    /* Start next timer ... */
    timer_add(&interface->ctx->timer_root, &interface->timer_isis_hello, 
              "ISIS hello", config->hello_interval, 0, interface, 
              &bbl_isis_hello_timeout);

    eth->type = ISIS_PROTOCOL_IDENTIFIER;
    eth->next = &isis;
    eth->dst = g_isis_mac_hello;
    isis.type = ISIS_PDU_P2P_HELLO;
    isis.level = adjacency->level;
    isis.holding_time = config->holding_time;
    isis.p2p_adjacency_state = &adjacency->adjacency_state;
    isis.system_id = config->system_id;
    isis.system_id_len = ISIS_SYSTEM_ID_LEN;
    isis.area = config->area;
    isis.area_count = config->area_count;
    if(config->protocol_ipv4) {
        isis.protocol_ipv4 = true;
        isis.ipv4_interface_address = &interface->ip;
        isis.ipv4_interface_address_len = sizeof(interface->ip);
    }
    if(config->protocol_ipv6) {
        isis.protocol_ipv6 = true;
        isis.ipv6_interface_address = &interface->ip6.address;
        isis.ipv6_interface_address_len = sizeof(interface->ip6.address);
    }

    adjacency->stats.hello_tx++;
    return encode_ethernet(buf, len, eth);
}

static void
bbl_isis_p2p_hello_handler_rx(bbl_ethernet_header_t *eth, bbl_isis_t *isis, bbl_interface_s *interface) {
    bbl_isis_adjacency_t *adjacency = interface->isis.adjacency;
    
    UNUSED(eth);
    adjacency->stats.hello_rx++;
    if(isis->p2p_adjacency_state) {
        adjacency->peer.adjacency_state = *isis->p2p_adjacency_state;
        switch (*isis->p2p_adjacency_state) {
            case ISIS_ADJACENCY_STATE_UP:
                adjacency->adjacency_state = ISIS_ADJACENCY_STATE_UP;
                break;
            case ISIS_ADJACENCY_STATE_INIT:
                adjacency->adjacency_state = ISIS_ADJACENCY_STATE_UP;
                break;
            case ISIS_ADJACENCY_STATE_DOWN:
                adjacency->adjacency_state = ISIS_ADJACENCY_STATE_INIT;
                break;
            default:
                break;
        }
    }
    if(isis->system_id && isis->system_id_len == ISIS_SYSTEM_ID_LEN) {
        memcpy(adjacency->peer.system_id, isis->system_id, ISIS_SYSTEM_ID_LEN);
    }
    if(isis->ipv4_interface_address) {
        adjacency->peer.ipv4_interface_address = *isis->ipv4_interface_address;
    }
    if(isis->ipv6_interface_address) {
        memcpy(adjacency->peer.ipv6_interface_address, isis->ipv6_interface_address, sizeof(ipv6addr_t));
    }
}

/**
 * bbl_isis_handler_rx
 *
 * This function handles IS-IS packets received on network interfaces.
 *
 * @param eth pointer to ethernet header structure of received packet
 * @param interface pointer to interface on which packet was received
 */
void
bbl_isis_handler_rx(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_isis_t *isis = eth->next;
    switch (isis->type) {
        case ISIS_PDU_P2P_HELLO:
            return bbl_isis_p2p_hello_handler_rx(eth, isis, interface);
        default:
            break;
    }
    return;
}

static const char *
isis_adjacency_state_string(uint8_t state) {
    switch(state) {
        case ISIS_ADJACENCY_STATE_UP: return "Up";
        case ISIS_ADJACENCY_STATE_INIT: return "Init";
        case ISIS_ADJACENCY_STATE_DOWN: return "Down";
        default: return "INVALID";
    }
}

json_t *
bbl_isis_interface_json(bbl_interface_s *interface)
{
    bbl_isis_instance_t *instance = interface->isis.instance;
    bbl_isis_adjacency_t *adjacency = interface->isis.adjacency;
    return json_pack("{ss si si ss}",
                     "name", interface->name,
                     "instance-id", instance->config->id,
                     "level", adjacency->level,
                     "adjacency-state", isis_adjacency_state_string(adjacency->adjacency_state));
}