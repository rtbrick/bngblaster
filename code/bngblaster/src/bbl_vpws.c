/*
 * BNG Blaster (BBL) - EVPN VPWS Services
 *
 * Reply to ARP, IPv6 neighbor solicitation and ICMP/ICMPv6 echo
 * requests received within EVPN VPWS services (vpws-arp) using
 * the labels, control word and customer VLAN tags of the
 * corresponding PE to CE traffic stream.
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

static int
bbl_vpws_compare(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof(bbl_vpws_key_s));
}

/**
 * bbl_vpws_add
 *
 * Add an EVPN VPWS network stream with vpws-arp enabled
 * to the VPWS database of its network interface.
 *
 * @param stream EVPN VPWS network stream
 * @return true on success
 */
bool
bbl_vpws_add(bbl_stream_s *stream)
{
    bbl_stream_config_s *config = stream->config;
    bbl_network_interface_s *interface = stream->tx_network_interface;
    bbl_vpws_key_s key = {0};
    bbl_vpws_s *vpws;
    bbl_stream_s *last;
    dict_insert_result result;
    void **search;

    if(!interface) {
        return false;
    }
    if(!interface->vpws_db) {
        interface->vpws_db = hb_tree_new((dict_compare_func)bbl_vpws_compare);
        if(!interface->vpws_db) {
            return false;
        }
    }

    key.vlan = config->vpws_vlan;
    key.inner_vlan = config->vpws_inner_vlan;
    if(stream->sub_type == BBL_SUB_TYPE_IPV4) {
        key.af = AF_INET;
        memcpy(key.ip, &config->ipv4_network_address, IPV4_ADDR_LEN);
    } else {
        key.af = AF_INET6;
        memcpy(key.ip, config->ipv6_network_address, IPV6_ADDR_LEN);
    }

    search = hb_tree_search(interface->vpws_db, &key);
    if(search) {
        /* Multiple streams per service share the learned MAC. */
        vpws = *search;
        last = vpws->stream;
        while(last->vpws_next) {
            last = last->vpws_next;
        }
        last->vpws_next = stream;
        return true;
    }

    vpws = calloc(1, sizeof(bbl_vpws_s));
    if(!vpws) {
        return false;
    }
    vpws->key = key;
    vpws->stream = stream;
    result = hb_tree_insert(interface->vpws_db, &vpws->key);
    if(!result.inserted) {
        free(vpws);
        return false;
    }
    *result.datum_ptr = vpws;
    return true;
}

static bbl_vpws_s *
bbl_vpws_lookup(bbl_network_interface_s *interface, bbl_ethernet_header_s *inner,
                uint8_t af, void *ip)
{
    bbl_vpws_key_s key = {0};
    void **search;

    key.vlan = inner->vlan_outer;
    key.inner_vlan = inner->vlan_inner;
    key.af = af;
    memcpy(key.ip, ip, af == AF_INET ? IPV4_ADDR_LEN : IPV6_ADDR_LEN);
    search = hb_tree_search(interface->vpws_db, &key);
    if(search) {
        return *search;
    }
    return NULL;
}

/* Learn the customer MAC for all streams of the service
 * without configured destination-mac. */
static void
bbl_vpws_learn(bbl_vpws_s *vpws, uint8_t *mac)
{
    bbl_stream_s *stream = vpws->stream;
    uint32_t version;

    while(stream) {
        if(!stream->config->destination_mac_overwrite &&
           (stream->vpws_mac_version == 0 ||
            memcmp(stream->vpws_mac, mac, ETH_ADDR_LEN) != 0)) {
            memcpy(stream->vpws_mac, mac, ETH_ADDR_LEN);
            version = stream->vpws_mac_version + 1;
            if(version == 0) version = 1;
            __atomic_store_n(&stream->vpws_mac_version, version, __ATOMIC_RELEASE);
            LOG(DEBUG, "VPWS stream %s learned MAC %s\n",
                stream->config->name, format_mac_address(mac));
        }
        stream = stream->vpws_next;
    }
}

static bool
bbl_vpws_rx_arp(bbl_network_interface_s *interface, bbl_ethernet_header_s *inner)
{
    bbl_arp_s *arp = (bbl_arp_s*)inner->next;
    bbl_vpws_s *vpws;
    uint32_t target_ip;

    if(arp->code != ARP_REQUEST) {
        return false;
    }
    vpws = bbl_vpws_lookup(interface, inner, AF_INET, &arp->target_ip);
    if(!vpws) {
        return false;
    }
    bbl_vpws_learn(vpws, arp->sender);

    target_ip = arp->target_ip;
    inner->dst = arp->sender;
    arp->code = ARP_REPLY;
    arp->target = arp->sender;
    arp->target_ip = arp->sender_ip;
    arp->sender = vpws->stream->tx_network_interface->mac;
    arp->sender_ip = target_ip;
    bbl_stream_vpws_send(vpws->stream, inner);
    return true;
}

static bool
bbl_vpws_rx_ipv4(bbl_network_interface_s *interface, bbl_ethernet_header_s *inner)
{
    bbl_ipv4_s *ipv4 = (bbl_ipv4_s*)inner->next;
    bbl_icmp_s *icmp;
    bbl_vpws_s *vpws;
    uint32_t dst;

    if(ipv4->protocol != PROTOCOL_IPV4_ICMP) {
        return false;
    }
    icmp = (bbl_icmp_s*)ipv4->next;
    if(icmp->type != ICMP_TYPE_ECHO_REQUEST) {
        return false;
    }
    vpws = bbl_vpws_lookup(interface, inner, AF_INET, &ipv4->dst);
    if(!vpws) {
        return false;
    }
    bbl_vpws_learn(vpws, inner->src);

    dst = ipv4->dst;
    inner->dst = inner->src;
    ipv4->dst = ipv4->src;
    ipv4->src = dst;
    ipv4->ttl = 64;
    icmp->type = ICMP_TYPE_ECHO_REPLY;
    bbl_stream_vpws_send(vpws->stream, inner);
    return true;
}

static bool
bbl_vpws_rx_ipv6(bbl_network_interface_s *interface, bbl_ethernet_header_s *inner)
{
    bbl_ipv6_s *ipv6 = (bbl_ipv6_s*)inner->next;
    bbl_icmpv6_s *icmpv6;
    bbl_vpws_s *vpws;
    uint8_t *dst;
    uint8_t mac[ETH_ADDR_LEN];

    if(ipv6->protocol != IPV6_NEXT_HEADER_ICMPV6) {
        return false;
    }
    icmpv6 = (bbl_icmpv6_s*)ipv6->next;
    if(icmpv6->type == IPV6_ICMPV6_NEIGHBOR_SOLICITATION) {
        vpws = bbl_vpws_lookup(interface, inner, AF_INET6, icmpv6->prefix.address);
        if(!vpws) {
            return false;
        }
        icmpv6->flags = 0;
        if(ipv6_addr_not_zero((ipv6addr_t*)ipv6->src)) {
            bbl_vpws_learn(vpws, inner->src);
            inner->dst = inner->src;
            ipv6->dst = ipv6->src;
        } else {
            /* Duplicate address detection (RFC 4861 section 7.2.4). */
            ipv6_multicast_mac(ipv6_multicast_all_nodes, mac);
            inner->dst = mac;
            ipv6->dst = (void*)ipv6_multicast_all_nodes;
            icmpv6->flags = IPV6_ICMPV6_NA_FLAG_OVERRIDE;
        }
        ipv6->src = icmpv6->prefix.address;
        ipv6->ttl = 255;
        icmpv6->type = IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT;
        icmpv6->mac = vpws->stream->tx_network_interface->mac;
        icmpv6->data = NULL;
        icmpv6->data_len = 0;
        icmpv6->dns1 = NULL;
        icmpv6->dns2 = NULL;
    } else if(icmpv6->type == IPV6_ICMPV6_ECHO_REQUEST) {
        vpws = bbl_vpws_lookup(interface, inner, AF_INET6, ipv6->dst);
        if(!vpws) {
            return false;
        }
        bbl_vpws_learn(vpws, inner->src);

        dst = ipv6->dst;
        inner->dst = inner->src;
        ipv6->dst = ipv6->src;
        ipv6->src = dst;
        ipv6->ttl = 255;
        icmpv6->type = IPV6_ICMPV6_ECHO_REPLY;
    } else {
        return false;
    }
    bbl_stream_vpws_send(vpws->stream, inner);
    return true;
}

static bool
bbl_vpws_rx_inner(bbl_network_interface_s *interface, bbl_ethernet_header_s *inner)
{
    switch(inner->type) {
        case ETH_TYPE_ARP:
            return bbl_vpws_rx_arp(interface, inner);
        case ETH_TYPE_IPV4:
            return bbl_vpws_rx_ipv4(interface, inner);
        case ETH_TYPE_IPV6:
            return bbl_vpws_rx_ipv6(interface, inner);
        default:
            return false;
    }
}

/**
 * bbl_vpws_rx
 *
 * Handle Ethernet over MPLS frames received on network interfaces
 * which are not traffic stream packets.
 *
 * @param interface receiving network interface
 * @param eth outer ethernet header (type ETH_TYPE_ETH)
 * @return true if handled
 */
bool
bbl_vpws_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth)
{
    if(!(interface->vpws_db && eth->next)) {
        return false;
    }
    if(bbl_vpws_rx_inner(interface, (bbl_ethernet_header_s*)eth->next)) {
        return true;
    }
    /* Ambiguous control word, the service lookup decides. */
    if(eth->next_cw) {
        return bbl_vpws_rx_inner(interface, (bbl_ethernet_header_s*)eth->next_cw);
    }
    return false;
}
