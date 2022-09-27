/*
 * BNG Blaster (BBL) - LI Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

const char*
bbl_li_direction_string(uint8_t direction)
{
    switch(direction) {
        case 2: return "downstream";
        case 3: return "upstream";
        default: return "invalid";
    }
}

const char*
bbl_li_packet_type_string(uint8_t packet_type)
{
    switch(packet_type) {
        case 5: return "ipv4";
        case 6: return "ipv6";
        case 7: return "ethernet";
        default: return "unkown";
    }
}

const char*
bbl_li_sub_packet_type_string(uint8_t sub_packet_type)
{
    switch(sub_packet_type) {
        case 1: return "single-tagged";
        case 2: return "double-tagged";
        case 3: return "untagged";
        default: return "unkown";
    }
}

/**
 * bbl_qmx_li_handler_rx
 *
 * @param interface receiving interface
 * @param eth received ethernet header
 * @param qmx_li received LI header
 */
void
bbl_qmx_li_handler_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth, bbl_qmx_li_s *qmx_li) {
    bbl_ipv4_s *ipv4 = (bbl_ipv4_s*)eth->next;
    bbl_udp_s *udp = (bbl_udp_s*)ipv4->next;
    bbl_ethernet_header_s *inner_eth;
    bbl_pppoe_session_s *inner_pppoe;
    bbl_ipv4_s *inner_ipv4 = NULL;
    bbl_ipv6_s *inner_ipv6 = NULL;
    bbl_li_flow_t *li_flow;

    dict_insert_result result;
    void **search = NULL;

    UNUSED(eth);

    search = dict_search(g_ctx->li_flow_dict, &qmx_li->header);
    if(search) {
        li_flow = *search;
    } else {
        /* New flow ... */
        li_flow = calloc(1, sizeof(bbl_li_flow_t));
        li_flow->src_ipv4 = ipv4->src;
        li_flow->dst_ipv4 = ipv4->dst;
        li_flow->src_port = udp->src;
        li_flow->dst_port = udp->dst;
        li_flow->direction = qmx_li->direction;
        li_flow->packet_type = qmx_li->packet_type;
        li_flow->sub_packet_type = qmx_li->sub_packet_type;
        li_flow->liid = qmx_li->liid;
        result = dict_insert(g_ctx->li_flow_dict, &qmx_li->header);
        if (!result.inserted) {
            free(li_flow);
            return;
        }
        *result.datum_ptr = li_flow;
    }

    interface->stats.li_rx++;
    li_flow->packets_rx++;
    li_flow->bytes_rx += qmx_li->payload_len;

    inner_eth = (bbl_ethernet_header_s*)qmx_li->next;
    if(inner_eth->type == ETH_TYPE_PPPOE_SESSION) {
        inner_pppoe = (bbl_pppoe_session_s*)inner_eth->next;
        if(inner_pppoe->protocol == PROTOCOL_IPV4) {
            inner_ipv4 = (bbl_ipv4_s*)inner_pppoe->next;
        } else if(inner_pppoe->protocol == PROTOCOL_IPV6) {
            inner_ipv6 = (bbl_ipv6_s*)inner_pppoe->next;
        }
    } else if(inner_eth->type == ETH_TYPE_IPV4) {
        inner_ipv4 = (bbl_ipv4_s*)eth->next;
    } else if(inner_eth->type == PROTOCOL_IPV6) {
        inner_ipv6 = (bbl_ipv6_s*)eth->next;
    }

    if(inner_ipv4) {
        li_flow->packets_rx_ipv4++;
        switch(inner_ipv4->protocol) {
            case PROTOCOL_IPV4_TCP:
                li_flow->packets_rx_ipv4_tcp++;
                break;
            case PROTOCOL_IPV4_UDP:
                li_flow->packets_rx_ipv4_udp++;
                break;
            case PROTOCOL_IPV4_INTERNAL:
                li_flow->packets_rx_ipv4_internal++;
                break;
            default:
                break;
        }
    } else if (inner_ipv6) {
        li_flow->packets_rx_ipv6++;
        switch(inner_ipv6->protocol) {
            case IPV6_NEXT_HEADER_TCP:
                li_flow->packets_rx_ipv6_tcp++;
                break;
            case IPV6_NEXT_HEADER_UDP:
                li_flow->packets_rx_ipv6_udp++;
                break;
            case IPV6_NEXT_HEADER_INTERNAL:
                li_flow->packets_rx_ipv6_internal++;
                break;
            case IPV6_NEXT_HEADER_NO:
                li_flow->packets_rx_ipv6_no_next_header++;
                break;
            default:
                break;
        }
    }
}