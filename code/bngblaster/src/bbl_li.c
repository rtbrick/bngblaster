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
        if(!result.inserted) {
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
    } else if(inner_ipv6) {
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

/* Control Socket Commands */

int
bbl_li_ctrl_flows(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *flows, *flow;
    bbl_li_flow_t *li_flow;
    struct dict_itor *itor;

    flows = json_array();
    itor = dict_itor_new(g_ctx->li_flow_dict);
    dict_itor_first(itor);
    for (; dict_itor_valid(itor); dict_itor_next(itor)) {
        li_flow = (bbl_li_flow_t*)*dict_itor_datum(itor);
        if(li_flow) {
            flow = json_pack("{ss si ss si ss ss ss si si si si si si si si si si si si}",
                                "source-address", format_ipv4_address(&li_flow->src_ipv4),
                                "source-port", li_flow->src_port,
                                "destination-address", format_ipv4_address(&li_flow->dst_ipv4),
                                "destination-port", li_flow->dst_port,
                                "direction", bbl_li_direction_string(li_flow->direction),
                                "packet-type", bbl_li_packet_type_string(li_flow->packet_type),
                                "sub-packet-type", bbl_li_sub_packet_type_string(li_flow->sub_packet_type),
                                "liid", li_flow->liid,
                                "bytes-rx", li_flow->bytes_rx,
                                "packets-rx", li_flow->packets_rx,
                                "packets-rx-ipv4", li_flow->packets_rx_ipv4,
                                "packets-rx-ipv4-tcp", li_flow->packets_rx_ipv4_tcp,
                                "packets-rx-ipv4-udp", li_flow->packets_rx_ipv4_udp,
                                "packets-rx-ipv4-host-internal", li_flow->packets_rx_ipv4_internal,
                                "packets-rx-ipv6", li_flow->packets_rx_ipv6,
                                "packets-rx-ipv6-tcp", li_flow->packets_rx_ipv6_tcp,
                                "packets-rx-ipv6-udp", li_flow->packets_rx_ipv6_udp,
                                "packets-rx-ipv6-host-internal", li_flow->packets_rx_ipv6_internal,
                                "packets-rx-ipv6-no-next-header", li_flow->packets_rx_ipv6_no_next_header);
            json_array_append(flows, flow);
        }
    }
    dict_itor_free(itor);
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "li-flows", flows);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(flows);
    }
    return result;
}