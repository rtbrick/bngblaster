/*
 * BNG Blaster (BBL) - LDP Hello
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

/**
 * ldp_hello_encode
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
ldp_hello_encode(bbl_network_interface_s *interface, 
                 uint8_t *buf, uint16_t *len, 
                 bbl_ethernet_header_s *eth)
{
    protocol_error_t result;

    bbl_ipv4_s ipv4 = {0};
    bbl_udp_s udp = {0};
    bbl_ldp_hello_s ldp = {0};

    ldp_adjacency_s *adjacency = interface->ldp_adjacency;
    ldp_instance_s  *instance  = adjacency->instance;
    ldp_config_s    *config    = instance->config;

    /* Build packet ... */
    eth->type = ETH_TYPE_IPV4;
    eth->next = &ipv4;
    eth->dst = (uint8_t*)all_routers_mac;
    ipv4.dst = IPV4_MC_ALL_ROUTERS;
    ipv4.src = interface->ip.address;
    ipv4.ttl = 1;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.router_alert_option = true;
    ipv4.next = &udp;
    udp.src = LDP_PORT;
    udp.dst = LDP_PORT;
    udp.protocol = UDP_PROTOCOL_LDP;
    udp.next = &ldp;
    ldp.lsr_id = config->lsr_id;
    ldp.hold_time = config->hold_time;
    ldp.ipv4_transport_address = config->ipv4_transport_address;
    result = encode_ethernet(buf, len, eth);
    if(result == PROTOCOL_SUCCESS) {
        LOG(DEBUG, "LDP TX hello on interface %s\n", interface->name);
        adjacency->interface->stats.ldp_udp_tx++;
    }
    return result;
}

void
ldp_hello_job(timer_s *timer)
{
    ldp_adjacency_s *adjacency = timer->data;
    bbl_network_interface_s *interface = adjacency->interface;
    interface->send_requests |= BBL_IF_SEND_LDP_HELLO;
}

/**
 * ldp_hello_start
 *
 * @param config LDP configuration
 * @param adjacency LDP adjacency
 */
void
ldp_hello_start(ldp_adjacency_s *adjacency) 
{
    time_t hello_interval = adjacency->hold_time/3U;
    if(!hello_interval) {
        hello_interval = 1;
    }
    timer_add_periodic(&g_ctx->timer_root, &adjacency->hello_timer, 
                       "LDP Hello", hello_interval, 0, adjacency, 
                       &ldp_hello_job);
}

void
ldp_hello_hold_timeout_job(timer_s *timer)
{
    ldp_adjacency_s *adjacency = timer->data;

    if(adjacency->state == LDP_ADJACENCY_STATE_DOWN) {
        return;
    }

    adjacency->state = LDP_ADJACENCY_STATE_DOWN;
    LOG(LDP, "LDP hold timeout on interface %s\n", adjacency->interface->name);
}

static void
ldp_hello_restart_hold_timeout(ldp_adjacency_s *adjacency)
{
    adjacency->state = LDP_ADJACENCY_STATE_UP;
    timer_add(&g_ctx->timer_root, &adjacency->hold_timer, 
              "LDP HOLD TIMEOUT", adjacency->hold_time, 0, adjacency, &ldp_hello_hold_timeout_job);
}

/**
 * ldp_hello_rx
 *
 * This function handles all received LDP hello packets.
 *
 * @param interface receiving interface
 * @param eth received ethernet header
 * @param ipv4 received ipv4 header
 * @param ldp LDP header of received packet
 */
void 
ldp_hello_rx(bbl_network_interface_s *interface, 
             bbl_ethernet_header_s *eth,
             bbl_ipv4_s *ipv4,
             bbl_ldp_hello_s *ldp)
{
    ldp_adjacency_s *adjacency = interface->ldp_adjacency;
    ldp_instance_s  *instance;
    ldp_session_s   *session;

    UNUSED(eth);

    interface->stats.ldp_udp_rx++;
    if(!adjacency) {
        return;
    }

    instance = adjacency->instance;
    session = instance->sessions;

    if(ldp->hold_time > 0 && ldp->hold_time < adjacency->hold_time) {
        adjacency->hold_time = ldp->hold_time;
        ldp_hello_start(adjacency);
    }
    ldp_hello_restart_hold_timeout(adjacency);

    while(session) {
        if(session->peer.lsr_id == ldp->lsr_id && 
           session->peer.label_space_id == ldp->label_space_id) {
            if(session->state == LDP_CLOSED) {
                break;
            } else {
                return;
            }
        }
        session = session->next;
    }

    /* Init LDP session. */
    ldp_session_init(session, adjacency, ipv4, ldp);
}