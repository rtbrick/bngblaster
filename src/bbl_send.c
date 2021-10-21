/*
 * BNG Blaster (BBL) - Direct Send Functions
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_session.h"

bool
bbl_send_init_interface(bbl_interface_s *interface, uint16_t size)
{
    interface->send.ring = malloc(size * sizeof(bbl_send_slot_t));
    if(!interface->send.ring) {
        return false;
    }
    interface->send.size  = size;
    interface->send.read  = 0;
    interface->send.write = 0;
    interface->send.next  = 1;
    return true;
}

bool
bbl_send_is_empty(bbl_interface_s *interface)
{
    if(interface->send.read == interface->send.write) {
        return true;
    }
    return false;
}

bool
bbl_send_is_full(bbl_interface_s *interface)
{
    if(interface->send.read == interface->send.next) {
        return true;
    }
    return false;
}

/**
 * @brief Receive packet from interface send 
 * buffer and copy to target buffer (buf).
 * 
 * @param interface interface
 * @param buf target buffer
 * @return number of bytes copied
 */
uint16_t
bbl_send_from_buffer(bbl_interface_s *interface, uint8_t *buf) 
{
    bbl_send_slot_t *slot; 

    if(interface->send.read == interface->send.write) {
        return 0;
    }

    slot = interface->send.ring + interface->send.read;
    memcpy(buf, slot->packet, slot->packet_len);

    interface->send.read++;
    if(interface->send.read == interface->send.size) {
        interface->send.read = 0;
    }
    return slot->packet_len;
}

/**
 * @brief Encode packet to interface send 
 * buffer.
 * 
 * @param interface interface
 * @param eth ethernet structure
 * @return bbl_send_result_t 
 */
bbl_send_result_t
bbl_send_to_buffer(bbl_interface_s *interface, bbl_ethernet_header_t *eth) 
{
    bbl_send_slot_t *slot; 

    if(interface->send.read == interface->send.next) {
        return BBL_SEND_FULL;
    }
    slot = interface->send.ring + interface->send.write;
    slot->packet_len = 0;
    if(encode_ethernet(slot->packet, &slot->packet_len, eth) == PROTOCOL_SUCCESS) {
        interface->send.write = interface->send.next++;
        if(interface->send.next == interface->send.size) {
            interface->send.next = 0;
        }
        return BBL_SEND_OK;
    } else {
        return BBL_SEND_ENCODE_ERROR;
    }
}

static void
swap_eth_src_dst(bbl_ethernet_header_t *eth) 
{
    uint8_t *dst = eth->dst;
    eth->dst = eth->src;
    eth->src = dst;
}

static void
swap_ipv4_src_dst(bbl_ipv4_t *ipv4) 
{
    uint32_t dst = ipv4->dst;
    ipv4->dst = ipv4->src;
    ipv4->src = dst;
}

static void
update_eth(bbl_interface_s *interface, 
           bbl_session_s *session, 
           bbl_ethernet_header_t *eth) 
{
    if(session) {
        swap_eth_src_dst(eth);
        eth->src = session->client_mac;
        eth->qinq = session->access_config->qinq;
        eth->vlan_outer = session->vlan_key.outer_vlan_id;
        eth->vlan_inner = session->vlan_key.inner_vlan_id;
        eth->vlan_three = session->access_third_vlan;
    } else {
        eth->dst = eth->src;
        eth->src = interface->mac;
        if(interface->vlan) {
            eth->vlan_outer = interface->vlan;
        }
    }
}

bbl_send_result_t 
bbl_send_arp_reply(bbl_interface_s *interface,
                  bbl_session_s *session,
                  bbl_ethernet_header_t *eth, 
                  bbl_arp_t *arp)
{
    update_eth(interface, session, eth);
    arp->code = ARP_REPLY;
    arp->sender = interface->mac;
    arp->sender_ip = arp->target_ip;
    arp->target = interface->gateway_mac;
    arp->target_ip = interface->gateway;
    return bbl_send_to_buffer(interface, eth);
}

bbl_send_result_t 
bbl_send_icmpv6_na(bbl_interface_s *interface,
                  bbl_session_s *session,
                  bbl_ethernet_header_t *eth, 
                  bbl_ipv6_t *ipv6, 
                  bbl_icmpv6_t *icmpv6)
{
    update_eth(interface, session, eth);
    ipv6->dst = ipv6->src;
    if(session) {
        ipv6->src = session->ipv6_address;
    } else {
        ipv6->src = interface->ip6.address;
    }
    ipv6->ttl = 255;
    icmpv6->type = IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT;
    icmpv6->mac = interface->mac;
    icmpv6->other = false;
    icmpv6->data = NULL;
    icmpv6->data_len = 0;
    icmpv6->dns1 = NULL;
    icmpv6->dns2 = NULL;
    return bbl_send_to_buffer(interface, eth);
}

bbl_send_result_t 
bbl_send_icmp_reply(bbl_interface_s *interface,
                   bbl_session_s *session,
                   bbl_ethernet_header_t *eth, 
                   bbl_ipv4_t *ipv4, 
                   bbl_icmp_t *icmp)
{
    update_eth(interface, session, eth);
    swap_ipv4_src_dst(ipv4);
    ipv4->ttl = 64;
    icmp->type = ICMP_TYPE_ECHO_REPLY;
    return bbl_send_to_buffer(interface, eth);
}