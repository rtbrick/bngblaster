/*
 * BNG Blaster (BBL) - LI Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_logging.h"

/** 
 * bbl_l2tp_handler_rx 
 *
 * This function handles all received L2TPv2 traffic. 
 * 
 * @param eth Received ethernet packet. 
 * @param l2tp L2TP header of received ethernet packet. 
 * @param interface Receiving interface. 
 */
void
bbl_qmx_li_handler_rx(bbl_ethernet_header_t *eth, bbl_qmx_li_t *qmx_li, bbl_interface_s *interface) {
    bbl_ctx_s *ctx = interface->ctx;
    bbl_ipv4_t *ipv4 = (bbl_ipv4_t*)eth->next;
    bbl_li_flow_t *li_flow; 

    bbl_ethernet_header_t *inner_eth;
    bbl_pppoe_session_t *inner_pppoe;
    bbl_ipv4_t *inner_ipv4 = NULL;

    dict_insert_result result;
    void **search = NULL;

    UNUSED(eth);

    search = dict_search(ctx->li_flow_dict, &qmx_li->header);
    if(search) {
        li_flow = *search;
    } else {
        /* New flow ... */
        li_flow = calloc(1, sizeof(bbl_li_flow_t));
        li_flow->direction = qmx_li->direction;
        li_flow->packet_type = qmx_li->packet_type;
        li_flow->sub_packet_type = qmx_li->sub_packet_type;
        li_flow->liid = qmx_li->liid;
        result = dict_insert(ctx->li_flow_dict, &qmx_li->header);
        if (!result.inserted) {
            free(li_flow);
            return;
        }
        *result.datum_ptr = li_flow;
    }

    interface->stats.li_rx++;
    li_flow->packets_rx++;
    li_flow->bytes_rx += qmx_li->payload_len;

    inner_eth = (bbl_ethernet_header_t*)qmx_li->next;
    if(inner_eth->type == ETH_TYPE_PPPOE_SESSION) {
        inner_pppoe = (bbl_pppoe_session_t*)inner_eth->next;
        if(inner_pppoe->protocol == PROTOCOL_IPV4) {
            inner_ipv4 = (bbl_ipv4_t*)inner_pppoe->next;

        }
    } else if(inner_eth->type == ETH_TYPE_IPV4) {
        inner_ipv4 = (bbl_ipv4_t*)eth->next;
    }

    if(inner_ipv4) {
        li_flow->packets_rx_ipv4++;
        switch(ipv4->protocol) {
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
    }
}
