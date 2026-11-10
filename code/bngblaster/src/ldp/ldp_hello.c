/*
 * BNG Blaster (BBL) - LDP Hello
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

/**
 * ldp_hello_ipv4_encode
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
ldp_hello_ipv4_encode(bbl_network_interface_s *interface, 
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
    ipv4.tos = config->tos;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = LDP_PORT;
    udp.dst = LDP_PORT;
    udp.protocol = UDP_PROTOCOL_LDP;
    udp.next = &ldp;
    ldp.lsr_id = config->lsr_id;
    ldp.hold_time = config->hold_time;
    ldp.ipv4_transport_address = config->ipv4_transport_address;
    if(adjacency->hello_ipv6) {
        if(adjacency->prefer_ipv4_transport) {
            ldp.dual_stack_capability = 4;
        } else {
            ldp.dual_stack_capability = 6;
        }
    }
    result = encode_ethernet(buf, len, eth);
    if(result == PROTOCOL_SUCCESS) {
        LOG(PACKET, "LDP TX IPv4 hello on interface %s\n", interface->name);
            adjacency->interface->stats.ldp_udp_tx++;
    }
    return result;
}

protocol_error_t
ldp_hello_ipv6_encode(bbl_network_interface_s *interface, 
                      uint8_t *buf, uint16_t *len, 
                      bbl_ethernet_header_s *eth)
{
    protocol_error_t result;

    bbl_ipv6_s ipv6 = {0};
    bbl_udp_s udp = {0};
    bbl_ldp_hello_s ldp = {0};
    uint8_t mac[ETH_ADDR_LEN];
    
    ldp_adjacency_s *adjacency = interface->ldp_adjacency;
    ldp_instance_s  *instance  = adjacency->instance;
    ldp_config_s    *config    = instance->config;

    /* Build packet ... */
    ipv6_multicast_mac(ipv6_multicast_all_routers, mac);
    eth->dst = mac;
    eth->type = ETH_TYPE_IPV6;
    eth->next = &ipv6;
    ipv6.dst = (void*)ipv6_multicast_all_routers;
    ipv6.src = interface->ip6_ll;
    ipv6.protocol = IPV6_NEXT_HEADER_UDP;
    ipv6.next = &udp;
    ipv6.ttl = 255;
    ipv6.tos = config->tos;
    udp.src = LDP_PORT;
    udp.dst = LDP_PORT;
    udp.protocol = UDP_PROTOCOL_LDP;
    udp.next = &ldp;
    ldp.lsr_id = config->lsr_id;
    ldp.hold_time = config->hold_time;
    ldp.ipv6_transport_address = &config->ipv6_transport_address;
    if(adjacency->hello_ipv4) {
        if(adjacency->prefer_ipv4_transport) {
            ldp.dual_stack_capability = 4;
        } else {
            ldp.dual_stack_capability = 6;
        }
    }
    result = encode_ethernet(buf, len, eth);
    if(result == PROTOCOL_SUCCESS) {
        LOG(PACKET, "LDP TX IPv6 hello on interface %s\n", interface->name);
            adjacency->interface->stats.ldp_udp_tx++;
    }
    return result;
}

/**
 * ldp_hello_targeted_encode
 *
 * Encode the next pending unicast targeted hello of this interface,
 * the send request is kept until all pending hellos are sent.
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
ldp_hello_targeted_encode(bbl_network_interface_s *interface,
                          uint8_t *buf, uint16_t *len,
                          bbl_ethernet_header_s *eth)
{
    protocol_error_t result;

    bbl_ipv4_s ipv4 = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_udp_s udp = {0};
    bbl_ldp_hello_s ldp = {0};

    ldp_instance_s  *instance  = g_ctx->ldp_instances;
    ldp_adjacency_s *adjacency = NULL;
    ldp_adjacency_s *next;
    ldp_config_s    *config;

    /* Search the first and second pending targeted hello. */
    while(instance) {
        next = instance->adjacencies;
        while(next) {
            if(next->targeted && next->targeted_hello_pending &&
               next->interface == interface) {
                if(adjacency) break;
                adjacency = next;
            }
            next = next->next;
        }
        if(next) break;
        instance = instance->next;
    }
    if(!next) {
        interface->send_requests &= ~BBL_IF_SEND_LDP_TARGETED_HELLO;
    }
    if(!adjacency) {
        return EMPTY;
    }
    adjacency->targeted_hello_pending = false;
    config = adjacency->instance->config;

    /* Build packet ... */
    udp.src = LDP_PORT;
    udp.dst = LDP_PORT;
    udp.protocol = UDP_PROTOCOL_LDP;
    udp.next = &ldp;
    ldp.lsr_id = config->lsr_id;
    ldp.hold_time = config->targeted_hold_time;
    ldp.targeted = true;
    ldp.request_targeted = adjacency->targeted_configured;
    if(!config->no_ipv4_transport && ipv6_addr_not_zero(&config->ipv6_transport_address)) {
        /* Dual-stack LSR (RFC 7552). */
        ldp.dual_stack_capability = adjacency->prefer_ipv4_transport ? 4 : 6;
    }
    if(adjacency->hello_ipv6) {
        eth->type = ETH_TYPE_IPV6;
        eth->next = &ipv6;
        eth->dst = interface->gateway6_mac;
        ipv6.dst = (uint8_t*)&adjacency->peer_ipv6_address;
        ipv6.src = (uint8_t*)&adjacency->local_ipv6_address;
        ipv6.ttl = 255;
        ipv6.tos = config->tos;
        ipv6.protocol = IPV6_NEXT_HEADER_UDP;
        ipv6.next = &udp;
        ldp.ipv6_transport_address = &config->ipv6_transport_address;
    } else {
        eth->type = ETH_TYPE_IPV4;
        eth->next = &ipv4;
        eth->dst = interface->gateway_mac;
        ipv4.dst = adjacency->peer_ipv4_address;
        ipv4.src = adjacency->local_ipv4_address;
        ipv4.ttl = 255;
        ipv4.tos = config->tos;
        ipv4.protocol = PROTOCOL_IPV4_UDP;
        ipv4.next = &udp;
        ldp.ipv4_transport_address = config->ipv4_transport_address;
    }
    result = encode_ethernet(buf, len, eth);
    if(result == PROTOCOL_SUCCESS) {
        LOG(PACKET, "LDP TX targeted hello to %s on interface %s\n",
            ldp_targeted_peer_address(adjacency), interface->name);
        interface->stats.ldp_udp_tx++;
        adjacency->hello_tx++;
    }
    return result;
}

/* Unicast hellos can't be sent before the gateway is resolved. */
static bool
ldp_hello_targeted_resolved(ldp_adjacency_s *adjacency)
{
    if(adjacency->hello_ipv6) {
        return adjacency->interface->icmpv6_nd_resolved;
    }
    return adjacency->interface->arp_resolved;
}

static void
ldp_hello_send_requests(ldp_adjacency_s *adjacency)
{
    bbl_network_interface_s *interface = adjacency->interface;
    if(adjacency->targeted) {
        if(ldp_hello_targeted_resolved(adjacency)) {
            adjacency->targeted_hello_pending = true;
            interface->send_requests |= BBL_IF_SEND_LDP_TARGETED_HELLO;
        }
        return;
    }
    if(adjacency->hello_ipv4) {
        interface->send_requests |= BBL_IF_SEND_LDP_HELLO_IPV4;
    }
    if(adjacency->hello_ipv6) {
        interface->send_requests |= BBL_IF_SEND_LDP_HELLO_IPV6;
    }
}

void
ldp_hello_job(timer_s *timer)
{
    ldp_adjacency_s *adjacency = timer->data;
    if(adjacency->instance->teardown) {
        timer->periodic = false;
        return;
    }
    if(adjacency->targeted_wait_resolve && ldp_hello_targeted_resolved(adjacency)) {
        /* Send first hello and continue with the regular interval. */
        ldp_hello_start(adjacency);
        return;
    }
    ldp_hello_send_requests(adjacency);
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
    adjacency->targeted_wait_resolve = false;
    if(adjacency->targeted && !ldp_hello_targeted_resolved(adjacency)) {
        adjacency->targeted_wait_resolve = true;
        hello_interval = 1;
    }
    ldp_hello_send_requests(adjacency);
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
    adjacency->state_transitions++;
    adjacency->state = LDP_ADJACENCY_STATE_DOWN;
    if(adjacency->targeted) {
        LOG(LDP, "LDP targeted hold timeout for %s\n",
            ldp_targeted_peer_address(adjacency));
        if(!adjacency->targeted_configured) {
            /* Remove an accepted peer which no longer sends hellos. */
            ldp_targeted_adjacency_free(adjacency);
        }
    } else {
        LOG(LDP, "LDP hold timeout on interface %s\n", adjacency->interface->name);
    }
}

static void
ldp_hello_restart_hold_timeout(ldp_adjacency_s *adjacency)
{
    if(adjacency->state == LDP_ADJACENCY_STATE_DOWN) {
        adjacency->state_transitions++;
        adjacency->state = LDP_ADJACENCY_STATE_UP;
        if(adjacency->targeted) {
            LOG(LDP, "LDP targeted adjacency with %s\n",
                ldp_targeted_peer_address(adjacency));
        } else {
            LOG(LDP, "LDP adjacency on interface %s\n", adjacency->interface->name);
        }
    }
    timer_add(&g_ctx->timer_root, &adjacency->hold_timer, 
              "LDP HOLD TIMEOUT", adjacency->hold_time, 0, adjacency, &ldp_hello_hold_timeout_job);
}

/**
 * ldp_hello_session
 *
 * Search the session for a received hello. Link and targeted
 * adjacencies to the same peer share one session, whose hello
 * hold timer is restarted with every hello of the peer.
 *
 * @return true if a new session should be initialised, with the
 *         closed session to reuse or NULL
 */
static bool
ldp_hello_session(ldp_adjacency_s *adjacency,
                  bbl_ldp_hello_s *ldp,
                  ldp_session_s **_session)
{
    ldp_session_s *session = adjacency->instance->sessions;

    *_session = NULL;
    while(session) {
        if(session->peer.lsr_id == ldp->lsr_id && 
           session->peer.label_space_id == ldp->label_space_id) {
            if(session->state == LDP_CLOSED) {
                *_session = session;
                return true;
            } else {
                ldp_session_hello(session, adjacency->hold_time);
                return false;
            }
        }
        session = session->next;
    }
    return true;
}

/**
 * ldp_hello_transport
 *
 * Check the dual-stack capability TLV (RFC 7552 section 6.1), which is
 * ignored by single-stack instances. A dual-stack instance establishes
 * the session only with the hellos of the preferred transport and
 * ignores peers with another preference.
 *
 * @param adjacency LDP adjacency
 * @param ldp received LDP hello
 * @param family address family of the hello (4 or 6)
 * @return true if the session should be initialised with this hello
 */
static bool
ldp_hello_transport(ldp_adjacency_s *adjacency, bbl_ldp_hello_s *ldp, uint8_t family)
{
    ldp_config_s *config = adjacency->instance->config;
    uint8_t local;

    if(config->no_ipv4_transport || !ipv6_addr_not_zero(&config->ipv6_transport_address) ||
       !ldp->dual_stack_capability) {
        return true;
    }
    local = config->prefer_ipv4_transport ? 4 : 6;
    if(ldp->dual_stack_capability != local) {
        LOG(LDP, "LDP transport connection mismatch with %s (local %u, peer %u)\n",
            format_ipv4_address(&ldp->lsr_id), local, ldp->dual_stack_capability);
        return false;
    }
    return family == local;
}

/**
 * ldp_hello_link_hold_time
 *
 * The hold time is the minimum of the local and the currently
 * received hold time, with zero as default (RFC 5036 section 2.5.5).
 */
static void
ldp_hello_link_hold_time(ldp_adjacency_s *adjacency, bbl_ldp_hello_s *ldp)
{
    uint16_t hold_time = adjacency->instance->config->hold_time;
    uint16_t received = ldp->hold_time ? ldp->hold_time : LDP_DEFAULT_HOLD_TIME;

    if(received < hold_time) {
        hold_time = received;
    }
    if(hold_time != adjacency->hold_time) {
        adjacency->hold_time = hold_time;
        ldp_hello_start(adjacency);
    }
}

/**
 * ldp_hello_targeted_adjacency
 *
 * Targeted hellos are matched by source address to a configured
 * targeted neighbor, sent to its source or the transport address.
 * Hellos sent to the transport address are accepted from any peer
 * if enabled, replied from the transport address.
 *
 * @param interface receiving interface
 * @param ipv6 true for IPv6 hellos
 * @param src hello source address
 * @param dst hello destination address
 * @return targeted adjacency or NULL if hello is ignored
 */
static ldp_adjacency_s *
ldp_hello_targeted_adjacency(bbl_network_interface_s *interface,
                             bool ipv6, void *src, void *dst)
{
    ldp_instance_s  *instance = g_ctx->ldp_instances;
    ldp_instance_s  *accept = NULL;
    ldp_adjacency_s *adjacency;
    ldp_config_s    *config;
    ldp_targeted_neighbor_config_s neighbor = {0};
    bool transport;

    while(instance) {
        config = instance->config;
        if(ipv6) {
            if(!ipv6_addr_not_zero(&config->ipv6_transport_address)) {
                instance = instance->next;
                continue;
            }
            transport = memcmp(&config->ipv6_transport_address, dst, sizeof(ipv6addr_t)) == 0;
        } else {
            if(config->no_ipv4_transport) {
                instance = instance->next;
                continue;
            }
            transport = config->ipv4_transport_address == *(uint32_t*)dst;
        }
        if(transport && !accept) {
            accept = instance;
        }
        adjacency = instance->adjacencies;
        while(adjacency) {
            if(adjacency->targeted && adjacency->hello_ipv6 == ipv6) {
                if(ipv6) {
                    if(memcmp(&adjacency->peer_ipv6_address, src, sizeof(ipv6addr_t)) == 0 &&
                       (transport || memcmp(&adjacency->local_ipv6_address, dst, sizeof(ipv6addr_t)) == 0)) {
                        return adjacency;
                    }
                } else {
                    if(adjacency->peer_ipv4_address == *(uint32_t*)src &&
                       (transport || adjacency->local_ipv4_address == *(uint32_t*)dst)) {
                        return adjacency;
                    }
                }
            }
            adjacency = adjacency->next;
        }
        instance = instance->next;
    }
    if(!(accept && accept->config->targeted_hello_accept && !accept->teardown)) {
        LOG(PACKET, "LDP RX targeted hello from %s ignored\n",
            ipv6 ? format_ipv6_address(src) : format_ipv4_address(src));
        return NULL;
    }
    neighbor.ipv6 = ipv6;
    if(ipv6) {
        memcpy(&neighbor.ipv6_address, src, sizeof(ipv6addr_t));
    } else {
        neighbor.ipv4_address = *(uint32_t*)src;
    }
    return ldp_targeted_adjacency_add(accept, interface, &neighbor, false);
}

/**
 * ldp_hello_targeted_rx
 *
 * @param adjacency targeted adjacency of the received hello
 * @param ldp LDP header of received packet
 */
static void
ldp_hello_targeted_rx(ldp_adjacency_s *adjacency,
                      bbl_ldp_hello_s *ldp)
{
    LOG(PACKET, "LDP RX targeted hello from %s on interface %s\n",
        ldp_targeted_peer_address(adjacency), adjacency->interface->name);
    adjacency->hello_rx++;

    /* A hold time of zero means default (45 seconds), the hold time is
     * the minimum of the local and the received one (RFC 5036 section 2.5.5). */
    uint16_t hold_time = adjacency->instance->config->targeted_hold_time;
    uint16_t received = ldp->hold_time ? ldp->hold_time : LDP_DEFAULT_TARGETED_HOLD_TIME;
    if(received < hold_time) {
        hold_time = received;
    }
    if(hold_time != adjacency->hold_time || !adjacency->hello_timer) {
        adjacency->hold_time = hold_time;
        ldp_hello_start(adjacency);
    }
    ldp_hello_restart_hold_timeout(adjacency);
}

/**
 * ldp_hello_ipv4_rx
 *
 * This function handles all received LDP hello packets.
 *
 * @param interface receiving interface
 * @param eth received ethernet header
 * @param ipv4 received ipv4 header
 * @param ldp LDP header of received packet
 */
void 
ldp_hello_ipv4_rx(bbl_network_interface_s *interface, 
                  bbl_ethernet_header_s *eth,
                  bbl_ipv4_s *ipv4,
                  bbl_ldp_hello_s *ldp)
{
    ldp_adjacency_s *adjacency = interface->ldp_adjacency;
    ldp_session_s   *session;

    interface->stats.ldp_udp_rx++;
    if(ldp->targeted) {
        if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
            return;
        }
        adjacency = ldp_hello_targeted_adjacency(interface, false, &ipv4->src, &ipv4->dst);
        if(!adjacency || adjacency->instance->teardown) {
            return;
        }
        ldp_hello_targeted_rx(adjacency, ldp);
    } else {
        if(!(adjacency && adjacency->hello_ipv4) || adjacency->instance->teardown) {
            return;
        }
        LOG(PACKET, "LDP RX IPv4 hello on interface %s\n", interface->name);
        ldp_hello_link_hold_time(adjacency, ldp);
        ldp_hello_restart_hold_timeout(adjacency);
    }

    if(!ldp_hello_session(adjacency, ldp, &session)) {
        return;
    }
    if(!ldp_hello_transport(adjacency, ldp, 4)) {
        return;
    }
    /* Init LDP session. */
    ldp_session_ipv4_init(session, adjacency, ipv4, ldp);
}

/**
 * ldp_hello_ipv6_rx
 *
 * This function handles all received LDP hello packets.
 *
 * @param interface receiving interface
 * @param eth received ethernet header
 * @param ipv6 received ipv6 header
 * @param ldp LDP header of received packet
 */
void 
ldp_hello_ipv6_rx(bbl_network_interface_s *interface, 
                  bbl_ethernet_header_s *eth,
                  bbl_ipv6_s *ipv6,
                  bbl_ldp_hello_s *ldp)
{
    ldp_adjacency_s *adjacency = interface->ldp_adjacency;
    ldp_session_s   *session;

    interface->stats.ldp_udp_rx++;
    if(ldp->targeted) {
        if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
            return;
        }
        adjacency = ldp_hello_targeted_adjacency(interface, true, ipv6->src, ipv6->dst);
        if(!adjacency || adjacency->instance->teardown) {
            return;
        }
        ldp_hello_targeted_rx(adjacency, ldp);
    } else {
        if(!(adjacency && adjacency->hello_ipv6) || adjacency->instance->teardown) {
            return;
        }
        LOG(PACKET, "LDP RX IPv6 hello on interface %s\n", interface->name);
        ldp_hello_link_hold_time(adjacency, ldp);
        ldp_hello_restart_hold_timeout(adjacency);
    }

    if(!ldp_hello_session(adjacency, ldp, &session)) {
        return;
    }
    if(!ldp_hello_transport(adjacency, ldp, 6)) {
        return;
    }
    /* Init LDP session. */
    ldp_session_ipv6_init(session, adjacency, ipv6, ldp);
}
