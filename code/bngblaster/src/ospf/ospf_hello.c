/*
 * BNG Blaster (BBL) - IS-IS P2P Hello
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

/**
 * ospf_hello_v2_encode
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
ospf_hello_v2_encode(bbl_network_interface_s *interface, 
                     uint8_t *buf, uint16_t *len, 
                     bbl_ethernet_header_s *eth)
{
    protocol_error_t result;

    bbl_ipv4_s ipv4 = {0};
    bbl_ospf_s ospf = {0};

    ospf_pdu_s pdu = {0};
    uint8_t pdu_buf[OSPF_TX_BUF_LEN];

    ospf_interface_s *ospf_interface = interface->ospf_interface;
    ospf_neighbor_s  *ospf_neighbor = ospf_interface->neighbors;
    ospf_instance_s  *ospf_instance = ospf_interface->instance;

    uint8_t options = 0;

    ospf_pdu_init(&pdu, OSPF_PDU_HELLO, OSPF_VERSION_2);
    pdu.pdu = pdu_buf;
    pdu.pdu_buf_len = OSPF_TX_BUF_LEN;

    /* OSPFv2 header */
    ospf_pdu_add_u8(&pdu, OSPF_VERSION_2);
    ospf_pdu_add_u8(&pdu, pdu.pdu_type);
    ospf_pdu_add_u16(&pdu, 0); /* skip length */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->router_id); /* Router ID */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->area); /* Area ID */
    ospf_pdu_add_u16(&pdu, 0); /* skip checksum */

    /* Authentication */
    ospf_pdu_add_u16(&pdu, OSPF_AUTH_NONE);
    ospf_pdu_zero_bytes(&pdu, OSPFV2_AUTH_DATA_LEN);

    /* OSPFv2 hello packet */
    ospf_pdu_add_ipv4(&pdu, ipv4_len_to_mask(interface->ip.len));
    ospf_pdu_add_u16(&pdu, ospf_instance->config->hello_interval);
    options |= OSPF_OPTION_E_BIT;
    ospf_pdu_add_u8(&pdu, options);
    ospf_pdu_add_u8(&pdu, ospf_instance->config->router_priority);
    ospf_pdu_add_u32(&pdu, ospf_instance->config->dead_interval);
    switch(ospf_interface->type) {
        case OSPF_INTERFACE_P2P:
        case OSPF_INTERFACE_VIRTUAL:
            ospf_pdu_zero_bytes(&pdu, 2*IPV4_ADDR_LEN);
            break;
        default:
            ospf_pdu_add_ipv4(&pdu, ospf_interface->dr);
            ospf_pdu_add_ipv4(&pdu, ospf_interface->bdr);
            break;
    }

    while(ospf_neighbor) {
        ospf_pdu_add_ipv4(&pdu, ospf_neighbor->router_id);
        ospf_neighbor = ospf_neighbor->next;
    }
    ospf_pdu_update_len(&pdu);
    ospf_pdu_update_checksum(&pdu);

    /* Build packet ... */
    eth->type = ETH_TYPE_IPV4;
    eth->next = &ipv4;
    eth->dst = (uint8_t*)all_ospf_routers_mac;
    ipv4.dst = IPV4_MC_ALL_OSPF_ROUTERS;
    ipv4.src = interface->ip.address;
    ipv4.ttl = 1;
    ipv4.protocol = PROTOCOL_IPV4_OSPF;
    ipv4.next = &ospf;
    ospf.version = pdu.pdu_version;
    ospf.type = pdu.pdu_type;
    ospf.pdu = pdu.pdu;
    ospf.pdu_len = pdu.pdu_len;
    result = encode_ethernet(buf, len, eth);
    if(result == PROTOCOL_SUCCESS) {
        LOG(PACKET, "OSPFv2 TX %s on interface %s\n",
            ospf_pdu_type_string(ospf.type), interface->name);
        ospf_interface->stats.hello_tx++;
    }
    return result;
}

/**
 * ospf_hello_v3_encode
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
ospf_hello_v3_encode(bbl_network_interface_s *interface, 
                     uint8_t *buf, uint16_t *len, 
                     bbl_ethernet_header_s *eth)
{
    UNUSED(interface);
    UNUSED(buf);
    UNUSED(len);
    UNUSED(eth);
    return PROTOCOL_SUCCESS;
}

void
ospf_hello_timeout(timer_s *timer)
{
    ospf_neighbor_s *ospf_neighbor = timer->data;

    LOG(OSPF, "OSPFv%u neighbor %s timeout on interface %s\n",
        ospf_neighbor->version,
        format_ipv4_address(&ospf_neighbor->router_id), 
        ospf_neighbor->interface->interface->name);

    ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_DOWN);
}

/**
 * ospf_hello_rx
 *
 * @param ospf_interface receive interface
 * @param ospf_neighbor receive OSPF neighbor
 * @param pdu received OSPF PDU
 */
void
ospf_hello_rx(ospf_interface_s *ospf_interface, 
              ospf_neighbor_s *ospf_neighbor, 
              ospf_pdu_s *pdu)
{
    bbl_network_interface_s *interface = ospf_interface->interface;
    ospf_instance_s  *ospf_instance = ospf_interface->instance;

    uint32_t ip;

    bool is2way = false;

    uint32_t options;

    uint16_t hello_interval;
    uint32_t dead_interval;

    ospf_interface->stats.hello_rx++;

    if(ospf_interface->version == OSPF_VERSION_2) {
        if(pdu->pdu_len < OSPFV2_HELLO_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        if(!(ospf_interface->type == OSPF_INTERFACE_P2P ||
             ospf_interface->type == OSPF_INTERFACE_VIRTUAL)) {
            ip = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_NETMASK);
            if(ipv4_mask_to_len(ip) != interface->ip.len) {
                ospf_rx_error(interface, pdu, "netmask");
                return;
            }
        }
        hello_interval = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_INTERVAL));
        options = *OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_OPTIONS);
        dead_interval = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_DEAD_INTERVAL));
        OSPF_PDU_CURSOR_SET(pdu, OSPFV2_OFFSET_HELLO_NBR);
    } else {
        if(pdu->pdu_len < OSPFV3_HELLO_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        options = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_OPTIONS-1) & 0xFFFFFF);
        hello_interval = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_INTERVAL));
        dead_interval = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_DEAD_INTERVAL));
        OSPF_PDU_CURSOR_SET(pdu, OSPFV3_OFFSET_HELLO_NBR);
    }

    if(hello_interval != ospf_instance->config->hello_interval) {
        ospf_rx_error(interface, pdu, "hello-interval");
        return;
    }
    if(dead_interval != ospf_instance->config->dead_interval) {
        ospf_rx_error(interface, pdu, "dead-interval");
        return;
    }
    
    while((OSPF_PDU_CURSOR_GET(pdu)+IPV4_ADDR_LEN) <= pdu->packet_len) {
        ip = *(uint32_t*)OSPF_PDU_CURSOR(pdu);
        if(ip == ospf_instance->config->router_id) {
            is2way = true;
        }
        OSPF_PDU_CURSOR_INC(pdu, IPV4_ADDR_LEN);
    }

    if(!ospf_neighbor) {
        ospf_neighbor = ospf_neigbor_new(ospf_interface, pdu);
        ospf_neighbor->next = ospf_interface->neighbors;
        ospf_interface->neighbors = ospf_neighbor;
        if(ospf_interface->version == OSPF_VERSION_2) {
            ospf_interface->interface->send_requests |= BBL_IF_SEND_OSPFV2_HELLO;
        } else {
            ospf_interface->interface->send_requests |= BBL_IF_SEND_OSPFV3_HELLO;
        }
    } 

    if(ospf_neighbor->state == OSPF_NBSTATE_DOWN) {
        ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_INIT);
    }

    /* Reset inactivity timer */
    timer_add(&g_ctx->timer_root, &ospf_neighbor->timer_inactivity, "OSPF",
              ospf_instance->config->dead_interval, 0, ospf_neighbor, &ospf_hello_timeout);
    timer_no_smear(ospf_neighbor->timer_inactivity);

    if(is2way) {
        if(ospf_neighbor->state == OSPF_NBSTATE_INIT) {
            switch(ospf_interface->state) {
                case OSPF_IFSTATE_P2P:
                case OSPF_IFSTATE_BACKUP:
                case OSPF_IFSTATE_DR:
                    ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
                    break;
                case OSPF_IFSTATE_DR_OTHER:
                    if(pdu->router_id == ospf_interface->dr ||
                    pdu->router_id == ospf_interface->bdr) {
                        ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
                    } else {
                        ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_2WAY);
                    }
                    break;
                default:
                    break;
            }
        }
    } else {
        ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_INIT);
    }

    UNUSED(options);
}