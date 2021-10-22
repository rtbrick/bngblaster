/*
 * BNG Blaster (BBL) - Streams
 *
 * Christian Giese, March 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_session.h"
#include "bbl_stream.h"
#include "bbl_stats.h"
#include "bbl_io.h"

extern volatile bool g_teardown;
extern bool g_init_phase;
extern bool g_traffic;

static bool
bbl_stream_can_send(bbl_stream *stream) {
    bbl_session_s *session = stream->session;
    
    if(g_init_phase) {
        return false;
    }

    if(stream->config->stream_group_id == 0) {
        /* RAW stream */
        return true;
    }
    if(session && session->session_state == BBL_ESTABLISHED) {
        if(session->access_type == ACCESS_TYPE_PPPOE) {
            if(session->l2tp && session->l2tp_session == NULL) {
                goto FREE;
            }
            switch (stream->config->type) {
                case STREAM_IPV4:
                    if(session->ipcp_state == BBL_PPP_OPENED) {
                        return true;
                    }
                    break;
                case STREAM_IPV6:
                    if(session->ip6cp_state == BBL_PPP_OPENED &&
                       session->icmpv6_ra_received &&
                       *(uint64_t*)session->ipv6_address) {
                        return true;
                    }
                    break;
                case STREAM_IPV6PD:
                    if(session->ip6cp_state == BBL_PPP_OPENED &&
                       session->icmpv6_ra_received &&
                       *(uint64_t*)session->delegated_ipv6_address &&
                       session->dhcpv6_state >= BBL_DHCP_BOUND) {
                        return true;
                    }
                    break;
                default:
                    break;
            }
        } else if (session->access_type == ACCESS_TYPE_IPOE) {
            switch (stream->config->type) {
                case STREAM_IPV4:
                    if(session->ip_address) {
                        return true;
                    }
                    break;
                case STREAM_IPV6:
                    if(*(uint64_t*)session->ipv6_address &&
                       session->icmpv6_ra_received) {
                        return true;
                    }
                    break;
                case STREAM_IPV6PD:
                    if(*(uint64_t*)session->delegated_ipv6_address &&
                       session->icmpv6_ra_received &&
                       session->dhcpv6_state >= BBL_DHCP_BOUND) {
                        return true;
                    }
                    break;
                default:
                    break;
            }
        }
    }
FREE:
    /* Free of packet if not ready to send */
    if(stream->buf) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
    }
    return false;
}

bool
bbl_stream_build_access_pppoe_packet(bbl_stream *stream) {

    bbl_ctx_s *ctx = stream->interface->ctx;
    bbl_session_s *session = stream->session;
    bbl_stream_config *config = stream->config;

    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    /* *
     * The corresponding network interfaces will be selected
     * in the following order:
     * - "network-interface" from stream section
     * - "network-interface" from access interface section
     * - first network interface from network section (default)
     */
    bbl_interface_s *network_if;
    if(config->network_interface) {
        network_if = bbl_get_network_interface(ctx, config->network_interface);
    } else {
        network_if = session->network_interface;
    }
    if(!network_if) {
        return false;
    }

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_outer_priority = config->vlan_priority;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_inner_priority = config->vlan_priority;
    eth.vlan_three = session->access_third_vlan;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    bbl.flow_id = stream->flow_id;
    bbl.direction = BBL_DIRECTION_UP;

    switch (stream->config->type) {
        case STREAM_IPV4:
            pppoe.protocol = PROTOCOL_IPV4;
            pppoe.next = &ipv4;
            /* Source address */
            ipv4.src = session->ip_address;
            /* Destination address */
            if(stream->config->ipv4_destination_address) {
                ipv4.dst = stream->config->ipv4_destination_address;
            } else {
                if(stream->config->ipv4_network_address) {
                    ipv4.dst = stream->config->ipv4_network_address;
                } else {
                    ipv4.dst = network_if->ip;
                }
            }
            ipv4.ttl = 64;
            ipv4.tos = config->priority;
            ipv4.protocol = PROTOCOL_IPV4_UDP;
            ipv4.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV4;
            if (config->length > 76) {
                bbl.padding = config->length - 76;
            }
            break;
        case STREAM_IPV6:
        case STREAM_IPV6PD:
            pppoe.protocol = PROTOCOL_IPV6;
            pppoe.next = &ipv6;
            /* Source address */
            if(stream->config->type == STREAM_IPV6) {
                ipv6.src = session->ipv6_address;
            } else {
                ipv6.src = session->delegated_ipv6_address;
            }
            /* Destination address */
            if(*(uint64_t*)stream->config->ipv6_destination_address) {
                ipv6.dst = stream->config->ipv6_destination_address;
            } else {
                if(*(uint64_t*)stream->config->ipv6_network_address) {
                    ipv6.dst = stream->config->ipv6_network_address;
                } else {
                    ipv6.dst = network_if->ip6.address;
                }
            }
            ipv6.src = session->ipv6_address;
            ipv6.ttl = 64;
            ipv6.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        default:
            return false;
    }

    buf_len = config->length + 64;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}


bool
bbl_stream_build_a10nsp_pppoe_packet(bbl_stream *stream) {

    bbl_ctx_s *ctx = stream->interface->ctx;
    bbl_session_s *session = stream->session;
    bbl_a10nsp_session_t *a10nsp_session = session->a10nsp_session;
    bbl_stream_config *config = stream->config;

    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    bbl_interface_s *a10nsp_if = bbl_get_a10nsp_interface(ctx, config->a10nsp_interface);
    if(!(a10nsp_if && a10nsp_session)) {
        return false;
    }

    if(stream->direction == STREAM_DIRECTION_UP) {
        bbl.direction = BBL_DIRECTION_UP;
        eth.dst = session->server_mac;
        eth.src = session->client_mac;
        eth.qinq = session->access_config->qinq;
        eth.vlan_outer = session->vlan_key.outer_vlan_id;
    } else {
        bbl.direction = BBL_DIRECTION_DOWN;
        eth.dst = session->client_mac;
        eth.src = session->server_mac;
        eth.qinq = a10nsp_if->qinq;
        eth.vlan_outer = a10nsp_session->s_vlan;
    }
    eth.vlan_outer_priority = config->vlan_priority;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_inner_priority = config->vlan_priority;
    eth.vlan_three = session->access_third_vlan;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    bbl.flow_id = stream->flow_id;

    switch (stream->config->type) {
        case STREAM_IPV4:
            pppoe.protocol = PROTOCOL_IPV4;
            pppoe.next = &ipv4;
            /* Source address */
            ipv4.src = session->ip_address;
            /* Destination address */
            if(stream->config->ipv4_destination_address) {
                ipv4.dst = stream->config->ipv4_destination_address;
            } else {
                if(stream->config->ipv4_network_address) {
                    ipv4.dst = stream->config->ipv4_network_address;
                } else {
                    ipv4.dst = A10NSP_IP_LOCAL;
                }
            }
            ipv4.ttl = 64;
            ipv4.tos = config->priority;
            ipv4.protocol = PROTOCOL_IPV4_UDP;
            ipv4.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV4;
            if (config->length > 76) {
                bbl.padding = config->length - 76;
            }
            break;
        case STREAM_IPV6:
        case STREAM_IPV6PD:
            pppoe.protocol = PROTOCOL_IPV6;
            pppoe.next = &ipv6;
            /* Source address */
            if(stream->config->type == STREAM_IPV6) {
                ipv6.src = session->ipv6_address;
            } else {
                ipv6.src = session->delegated_ipv6_address;
            }
            /* Destination address */
            if(*(uint64_t*)stream->config->ipv6_destination_address) {
                ipv6.dst = stream->config->ipv6_destination_address;
            } else {
                if(*(uint64_t*)stream->config->ipv6_network_address) {
                    ipv6.dst = stream->config->ipv6_network_address;
                } else {
                    ipv6.dst = session->link_local_ipv6_address;
                }
            }
            ipv6.src = session->link_local_ipv6_address;
            ipv6.ttl = 64;
            ipv6.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        default:
            return false;
    }

    buf_len = config->length + 64;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}

bool
bbl_stream_build_access_ipoe_packet(bbl_stream *stream) {

    bbl_ctx_s *ctx = stream->interface->ctx;
    bbl_session_s *session = stream->session;
    bbl_stream_config *config = stream->config;

    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    /* *
     * The corresponding network interfaces will be selected
     * in the following order:
     * - "network-interface" from stream section
     * - "network-interface" from access interface section
     * - first network interface from network section (default)
     */
    bbl_interface_s *network_if;
    if(config->network_interface) {
        network_if = bbl_get_network_interface(ctx, config->network_interface);
    } else {
        network_if = session->network_interface;
    }
    if(!network_if) {
        return false;
    }

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_outer_priority = config->vlan_priority;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_inner_priority = config->vlan_priority;
    eth.vlan_three = session->access_third_vlan;

    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    bbl.flow_id = stream->flow_id;
    bbl.direction = BBL_DIRECTION_UP;

    switch (stream->config->type) {
        case STREAM_IPV4:
            eth.type = ETH_TYPE_IPV4;
            eth.next = &ipv4;
            /* Source address */
            ipv4.src = session->ip_address;
            /* Destination address */
            if(stream->config->ipv4_destination_address) {
                ipv4.dst = stream->config->ipv4_destination_address;
            } else {
                if(stream->config->ipv4_network_address) {
                    ipv4.dst = stream->config->ipv4_network_address;
                } else {
                    ipv4.dst = network_if->ip;
                }
            }
            ipv4.ttl = 64;
            ipv4.tos = config->priority;
            ipv4.protocol = PROTOCOL_IPV4_UDP;
            ipv4.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV4;
            if (config->length > 76) {
                bbl.padding = config->length - 76;
            }
            break;
        case STREAM_IPV6:
        case STREAM_IPV6PD:
            eth.type = ETH_TYPE_IPV6;
            eth.next = &ipv6;
            /* Source address */
            if(stream->config->type == STREAM_IPV6) {
                ipv6.src = session->ipv6_address;
            } else {
                ipv6.src = session->delegated_ipv6_address;
            }
            /* Destination address */
            if(*(uint64_t*)stream->config->ipv6_destination_address) {
                ipv6.dst = stream->config->ipv6_destination_address;
            } else {
                if(*(uint64_t*)stream->config->ipv6_network_address) {
                    ipv6.dst = stream->config->ipv6_network_address;
                } else {
                    ipv6.dst = network_if->ip6.address;
                }
            }
            ipv6.src = session->ipv6_address;
            ipv6.ttl = 64;
            ipv6.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        default:
            return false;
    }

    buf_len = config->length + 64;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}

bool
bbl_stream_build_network_packet(bbl_stream *stream) {

    bbl_session_s *session = stream->session;
    bbl_stream_config *config = stream->config;

    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    uint8_t mac[ETH_ADDR_LEN] = {0};

    bbl_interface_s *network_if = stream->interface;

    eth.dst = network_if->gateway_mac;
    eth.src = network_if->mac;
    eth.vlan_outer = network_if->vlan;
    eth.vlan_outer_priority = config->vlan_priority;
    eth.vlan_inner = 0;

    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    if(session) {
        bbl.session_id = session->session_id;
        bbl.ifindex = session->interface->ifindex;
        bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
        bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    }
    bbl.flow_id = stream->flow_id;
    bbl.direction = BBL_DIRECTION_DOWN;
    switch (stream->config->type) {
        case STREAM_IPV4:
            eth.type = ETH_TYPE_IPV4;
            eth.next = &ipv4;
            /* Source address */
            if(stream->config->ipv4_network_address) {
                ipv4.src = stream->config->ipv4_network_address;
            } else {
                ipv4.src = network_if->ip;
            }
            /* Destination address */
            if(stream->config->ipv4_destination_address) {
                ipv4.dst = stream->config->ipv4_destination_address;
                /* All IPv4 multicast addresses start with 1110 */
                if((ipv4.dst & htobe32(0xf0000000)) == htobe32(0xe0000000)) {
                    /* Generate multicast destination MAC */
                    *(uint32_t*)(&mac[2]) = ipv4.dst;
                    mac[0] = 0x01;
                    mac[2] = 0x5e;
                    mac[3] &= 0x7f;
                    eth.dst = mac;
                    bbl.type = BBL_TYPE_MULTICAST;
                    bbl.mc_source = ipv4.src;
                    bbl.mc_group = ipv4.dst;
                }
            } else {
                if(session) {
                    ipv4.dst = session->ip_address;
                } else {
                    return false;
                }
            }
            ipv4.ttl = 64;
            ipv4.tos = config->priority;
            ipv4.protocol = PROTOCOL_IPV4_UDP;
            ipv4.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV4;
            if (config->length > 76) {
                bbl.padding = config->length - 76;
            }
            break;
        case STREAM_IPV6:
        case STREAM_IPV6PD:
            eth.type = ETH_TYPE_IPV6;
            eth.next = &ipv6;
            /* Source address */
            if(*(uint64_t*)stream->config->ipv6_network_address) {
                ipv6.src = stream->config->ipv6_network_address;
            } else {
                ipv6.src = network_if->ip6.address;
            }
            /* Destination address */
            if(*(uint64_t*)stream->config->ipv6_destination_address) {
                ipv6.dst = stream->config->ipv6_destination_address;
            } else {
                if(session) {
                    if(stream->config->type == STREAM_IPV6) {
                        ipv6.dst = session->ipv6_address;
                    } else {
                        ipv6.dst = session->delegated_ipv6_address;
                    }
                } else {
                    return false;
                }
            }
            ipv6.ttl = 64;
            ipv6.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        default:
            return false;
    }

    buf_len = config->length + 64;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}

bool
bbl_stream_build_l2tp_packet(bbl_stream *stream) {

    bbl_session_s *session = stream->session;
    bbl_stream_config *config = stream->config;

    bbl_l2tp_session_t *l2tp_session = stream->session->l2tp_session;
    bbl_l2tp_tunnel_t *l2tp_tunnel = l2tp_session->tunnel;
    
    struct bbl_interface_ *interface = l2tp_tunnel->interface;
    
    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t l2tp_ipv4 = {0};
    bbl_udp_t l2tp_udp = {0};
    bbl_l2tp_t l2tp = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.vlan_inner = 0;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &l2tp_ipv4;
    l2tp_ipv4.dst = l2tp_tunnel->peer_ip;
    l2tp_ipv4.src = l2tp_tunnel->server->ip;
    l2tp_ipv4.ttl = 64;
    l2tp_ipv4.tos = config->priority;
    l2tp_ipv4.protocol = PROTOCOL_IPV4_UDP;
    l2tp_ipv4.next = &l2tp_udp;
    l2tp_udp.src = L2TP_UDP_PORT;
    l2tp_udp.dst = L2TP_UDP_PORT;
    l2tp_udp.protocol = UDP_PROTOCOL_L2TP;
    l2tp_udp.next = &l2tp;
    l2tp.type = L2TP_MESSAGE_DATA;
    l2tp.tunnel_id = l2tp_tunnel->peer_tunnel_id;
    l2tp.session_id = l2tp_session->peer_session_id;
    l2tp.protocol = PROTOCOL_IPV4;
    l2tp.with_length = l2tp_tunnel->server->data_lenght;
    l2tp.with_offset = l2tp_tunnel->server->data_offset;
    l2tp.next = &ipv4;
    ipv4.dst = session->ip_address;
    ipv4.src = l2tp_tunnel->server->ip;
    ipv4.ttl = 64;
    ipv4.tos = config->priority;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    bbl.flow_id = stream->flow_id;
    bbl.direction = BBL_DIRECTION_DOWN;
    bbl.sub_type = BBL_SUB_TYPE_IPV4;
    if (config->length > 76) {
        bbl.padding = config->length - 76;
    }

    buf_len = config->length + 128;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}

bool
bbl_stream_build_packet(bbl_stream *stream) {
    if(stream->config->stream_group_id == 0) {
        /* RAW stream */
        return bbl_stream_build_network_packet(stream);
    }
    if(stream->session) {
        if(stream->session->access_type == ACCESS_TYPE_PPPOE) {
            if(stream->session->l2tp_session) {
                if(stream->direction == STREAM_DIRECTION_UP) {
                    return bbl_stream_build_access_pppoe_packet(stream);
                } else {
                    return bbl_stream_build_l2tp_packet(stream);
                }
            } else if(stream->session->a10nsp_session) {
                return bbl_stream_build_a10nsp_pppoe_packet(stream);
            } else {
                switch (stream->config->type) {
                    case STREAM_IPV4:
                    case STREAM_IPV6:
                    case STREAM_IPV6PD:
                        if(stream->direction == STREAM_DIRECTION_UP) {
                            return bbl_stream_build_access_pppoe_packet(stream);
                        } else {
                            return bbl_stream_build_network_packet(stream);
                        }
                    default:
                        break;
                }
            }
        } else if (stream->session->access_type == ACCESS_TYPE_IPOE) {
            if(stream->session->a10nsp_session) {
                return false;
            } else {
                if(stream->direction == STREAM_DIRECTION_UP) {
                    return bbl_stream_build_access_ipoe_packet(stream);
                } else {
                    return bbl_stream_build_network_packet(stream);
                }
            }
        }
    }
    return false;
}

void *
bbl_stream_tx_thread (void *thread_data) {

    bbl_stream_thread *thread = thread_data;
    bbl_interface_s *interface = thread->interface;

    bbl_stream *stream = NULL;

    struct timespec send_windwow    = {0};
    struct timespec now             = {0};
    struct timespec sleep           = {0};
    struct timespec rem             = {0};

    double d;
    uint64_t packets;
    uint64_t packets_expected;

    struct sockaddr_ll addr = {0};
    int fd_tx;
    int qdisc_bypass = 1;

    /* Open new TX socket for thread. */
    fd_tx = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
    if (fd_tx == -1) {
        if (errno == EPERM) {
            LOG(ERROR, "socket() for interface %s Permission denied: Are you root?\n", interface->name);
            return NULL;
        }
        LOG(ERROR, "socket() TX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return NULL;
    }
    addr.sll_family = PF_PACKET;
    addr.sll_ifindex = interface->ifindex;
    addr.sll_protocol = 0;
    if (bind(fd_tx, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        LOG(ERROR, "bind() TX error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        return NULL;
    }
    if (setsockopt(fd_tx, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass)) == -1) {
        LOG(ERROR, "Setting qdisc bypass error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return NULL;
    }

    while(true) {
        if(!thread->active || g_teardown) {
            break;
        }

        /* Get next stream ... */
        if(stream && stream->thread_next) {
            stream = stream->thread_next;
        } else {
            /* End of stream list reached... */
            stream = thread->stream;
            if(sleep.tv_nsec) {
                nanosleep(&sleep, &rem);
            }
            sleep.tv_nsec = 1000 * MSEC; /* 1s */
        }

        packets = 0;
        if(!bbl_stream_can_send(stream)) {
            /* Close send window */
            stream->send_window_packets = 0;
            continue;
        }
        if(!stream->buf) {
            if(!bbl_stream_build_packet(stream)) {
                LOG(ERROR, "Failed to build packet for stream %s\n", stream->config->name);
                continue;
            }
        }

        if(!g_traffic || (stream->session && !stream->session->stream_traffic)) {
            /* Close send window */
            stream->send_window_packets = 0;
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        if(stream->send_window_packets == 0) {
            /* Open new send window */
            stream->send_window_start.tv_sec = now.tv_sec;
            stream->send_window_start.tv_nsec = now.tv_nsec;
            packets = 1;
        } else {
            timespec_sub(&send_windwow, &now, &stream->send_window_start);
            packets_expected = send_windwow.tv_sec * stream->config->pps;
            d = (send_windwow.tv_nsec / 1000000000.0);
            packets_expected += d * stream->config->pps;

            if(packets_expected > stream->send_window_packets) {
                packets = packets_expected - stream->send_window_packets;
            }
        }

        /* Update BBL header fields */
        *(uint32_t*)(stream->buf + (stream->tx_len - 8)) = now.tv_sec;
        *(uint32_t*)(stream->buf + (stream->tx_len - 4)) = now.tv_nsec;
        while(packets) {
            *(uint64_t*)(stream->buf + (stream->tx_len - 16)) = stream->flow_seq;
            /* Send packet ... */
            if (sendto(fd_tx, stream->buf, stream->tx_len, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll)) <0 ) {
                LOG(IO, "Sendto failed with errno: %i\n", errno);
                thread->sendto_failed++;

                /* Wait 1ms after send error ... */
                sleep.tv_nsec = 1 * MSEC;
                nanosleep(&sleep, &rem);

                /* Update BBL header fields after sleep */
                clock_gettime(CLOCK_MONOTONIC, &now);
                *(uint32_t*)(stream->buf + (stream->tx_len - 8)) = now.tv_sec;
                *(uint32_t*)(stream->buf + (stream->tx_len - 4)) = now.tv_nsec;
            } else {
                stream->send_window_packets++;
                stream->flow_seq++;
                packets--;

                /* Update counters */
                thread->packets_tx++;
                thread->bytes_tx += stream->tx_len;
                stream->packets_tx++;
            }
        }
        sleep.tv_nsec = 1000; /* 0.001ms */
        nanosleep(&sleep, &rem);
        sleep.tv_nsec = 0;
    }
    return NULL;
}

void
bbl_stream_tx_thread_counter_sync (bbl_stream_thread *thread) {
    bbl_interface_s *interface = thread->interface;

    bbl_stream *stream = thread->stream;
    bbl_session_s *session;

    uint64_t packets_tx;
    uint64_t bytes_tx;
    uint64_t delta_packets;
    uint64_t delta_bytes;

    packets_tx = thread->packets_tx;
    delta_packets = packets_tx - thread->packets_tx_last_sync;
    bytes_tx = thread->bytes_tx;
    delta_bytes = bytes_tx - thread->bytes_tx_last_sync;

    interface->stats.packets_tx += delta_packets;
    interface->stats.bytes_tx += delta_bytes;
    
    thread->packets_tx_last_sync = packets_tx;
    thread->bytes_tx_last_sync = bytes_tx;

    packets_tx = thread->sendto_failed;
    delta_packets = packets_tx - thread->sendto_failed_last_sync;
    interface->stats.sendto_failed += delta_packets;

    if(thread->sessions) {
        while(stream) {
            if(stream->session) {
                session = stream->session;
    
                packets_tx = stream->packets_tx;
                delta_packets = packets_tx - stream->packets_tx_last_sync;
                delta_bytes = delta_packets * stream->tx_len;

                if(stream->direction == STREAM_DIRECTION_UP) {
                    session->stats.packets_tx += delta_packets;
                    session->stats.bytes_tx += delta_bytes;
                    session->stats.accounting_packets_tx += delta_packets;
                    session->stats.accounting_bytes_tx += delta_bytes;
                } else {
                    if(session->l2tp_session) {
                        interface->stats.l2tp_data_tx++;
                        session->l2tp_session->tunnel->stats.data_tx++;
                        session->l2tp_session->stats.data_tx++;
                        session->l2tp_session->stats.data_ipv4_tx++;
                    }
                }
                stream->packets_tx_last_sync = packets_tx;
            }
            stream = stream->thread_next;
        }
    }
}

void
bbl_stream_tx_thread_counter_sync_timer (timer_s *timer) {
    bbl_stream_thread *thread = timer->data;
    bbl_stream_tx_thread_counter_sync(thread);
}

static bbl_stream_thread *
bbl_stream_thread_create(uint8_t thread_group, bbl_stream *stream) {
    bbl_stream_thread *thread;

    if(thread_group) {
        LOG(INFO, "Create stream TX thread-group %u\n", thread_group);
    } else {
        LOG(INFO, "Create stream TX thread for stream %s\n", stream->config->name);
    }
    thread = calloc(1, sizeof(bbl_stream_thread));
    thread->thread_group = thread_group;
    thread->interface = stream->interface;
    return thread;
}

/**
 * This function will add a stream to an existing
 * thread or create a new thread based on thread 
 * group. 
 * 
 * @param ctx global context
 * @param thread_group thread group
 * @param stream traffic stream
 */
static void
bbl_stream_add_to_thread(bbl_ctx_s *ctx, uint8_t thread_group, bbl_stream *stream) {

    bbl_stream_thread *thread;

    /* Search for existing thread group or create a new one */
    if(ctx->stream_thread) {
        thread = ctx->stream_thread;
        while(true) {
            /* The thread group zero means that this stream 
             * requests a dedicated thread. The scope of thread 
             * groups is per interface. */
            if(thread_group && thread->thread_group == thread_group &&
               thread->interface == stream->interface) {
                break;
            }
            if(thread->next) {
                thread = thread->next;
            } else {
                /* Create new thread */
                thread->next = bbl_stream_thread_create(thread_group, stream);
                thread = thread->next;
                break;
            }
        }
    } else {
        /* Create first thread */
        thread = bbl_stream_thread_create(thread_group, stream);
        ctx->stream_thread = thread;
    }

    /* Append stream to thread */
    if(thread->stream) {
        thread->stream_tail->thread_next = stream;
    } else {
        /* First stream in thread */
        thread->stream = stream;
    }
    thread->stream_tail = stream;

    if(stream->session) {
        thread->sessions = true;
    }
    thread->stream_count++;
}

/**
 * This function starts all stream threads.
 * 
 * @param ctx global context
 * @return true if success and false if failed
 */
bool
bbl_stream_start_threads(bbl_ctx_s *ctx) {
    
    bbl_stream_thread *thread = ctx->stream_thread;

    while(thread) {
        if(thread->thread_group) {
            LOG(INFO, "Start stream TX thread-group %u\n", thread->thread_group);
        } else {
            LOG(INFO, "Start stream TX thread for stream %s\n", thread->stream->config->name);
        }
        thread->active = true;
        timer_add_periodic(&ctx->timer_root, &thread->sync_timer, "Stream TX Thread", 1, 0, thread, &bbl_stream_tx_thread_counter_sync_timer);
        pthread_create(&thread->thread_id, NULL, bbl_stream_tx_thread, (void *)thread);
        thread = thread->next;
    }
    return true;
}

/**
 * This function stops all stream threads.
 * 
 * @param ctx global context
 */
void
bbl_stream_stop_threads(bbl_ctx_s *ctx) {
    
    bbl_stream_thread *thread = ctx->stream_thread;
    while(thread) {
        if(thread->active) {
            if(thread->thread_group) {
                LOG(INFO, "Stop stream TX thread-group %u\n", thread->thread_group);
            } else {
                LOG(INFO, "Stop stream TX thread for stream %s\n", thread->stream->config->name);
            }
            /* Mark thread as inactive and stop counter sync job */
            thread->active = false;
            timer_del(thread->sync_timer);
            /* Wait for thread to be stopped */
            pthread_join(thread->thread_id, NULL);
            /* Do final counter sync */
            bbl_stream_tx_thread_counter_sync(thread);
        }
        thread = thread->next;
    }
}

void
bbl_stream_tx_job (timer_s *timer) {

    bbl_stream *stream = timer->data;
    bbl_session_s *session = stream->session;
    bbl_interface_s *interface = stream->interface;

    struct timespec send_windwow;
    struct timespec now;

    double d;
    uint64_t packets = 1;
    uint64_t packets_expected;

    if(!bbl_stream_can_send(stream)) {
        stream->send_window_packets = 0;
        return;
    }
    if(!stream->buf) {
        if(!bbl_stream_build_packet(stream)) {
            LOG(ERROR, "Failed to build packet for stream %s\n", stream->config->name);
            return;
        }
    }

    if(!g_traffic || (session && !session->stream_traffic)) {
        /* Close send window */
        stream->send_window_packets = 0;
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    if(stream->send_window_packets == 0) {
        /* Open new send window */
        stream->send_window_start.tv_sec = now.tv_sec;
        stream->send_window_start.tv_nsec = now.tv_nsec;
    } else {
        timespec_sub(&send_windwow, &now, &stream->send_window_start);
        packets_expected = send_windwow.tv_sec * stream->config->pps;
        d = (send_windwow.tv_nsec / 1000000000.0);
        packets_expected += d * stream->config->pps;

        if(packets_expected > stream->send_window_packets) {
            packets = packets_expected - stream->send_window_packets;
        }
        if(packets > interface->ctx->config.io_stream_max_ppi) {
            packets = interface->ctx->config.io_stream_max_ppi;
        }
    }

    /* Update BBL header fields */
    *(uint32_t*)(stream->buf + (stream->tx_len - 8)) = now.tv_sec;
    *(uint32_t*)(stream->buf + (stream->tx_len - 4)) = now.tv_nsec;
    while(packets) {
        *(uint64_t*)(stream->buf + (stream->tx_len - 16)) = stream->flow_seq;
        /* Send packet ... */
        if(!bbl_io_send(interface, stream->buf, stream->tx_len)) {
            return;
        }
        stream->send_window_packets++;
        stream->packets_tx++;
        stream->flow_seq++;
        packets--;
        if(session) {
            if(stream->direction == STREAM_DIRECTION_UP) {
                session->stats.packets_tx++;
                session->stats.bytes_tx += stream->tx_len;
                session->stats.accounting_packets_tx++;
                session->stats.accounting_bytes_tx += stream->tx_len;
            } else {
                if(session->l2tp_session) {
                    interface->stats.l2tp_data_tx++;
                    session->l2tp_session->tunnel->stats.data_tx++;
                    session->l2tp_session->stats.data_tx++;
                    session->l2tp_session->stats.data_ipv4_tx++;
                }
            }
        }
    }
}

void
bbl_stream_rate_job (timer_s *timer) {
    bbl_stream *stream = timer->data;
    bbl_compute_avg_rate(&stream->rate_packets_tx, stream->packets_tx);
    bbl_compute_avg_rate(&stream->rate_packets_rx, stream->packets_rx);
}

bool
bbl_stream_add(bbl_ctx_s *ctx, bbl_access_config_s *access_config, bbl_session_s *session) {

    bbl_stream_config *config;
    bbl_stream *stream;
    bbl_stream *session_stream;

    dict_insert_result result;

    time_t timer_sec = 0;
    long timer_nsec  = 0;

    config = ctx->config.stream_config;

    /* *
     * The corresponding network interfaces will be selected
     * in the following order:
     * - "network-interface" from stream section
     * - "network-interface" from access interface section
     * - first network interface from network section (default)
     */
    bbl_interface_s *network_if;
    if(config->network_interface) {
        network_if = bbl_get_network_interface(ctx, config->network_interface);
    } else if(config->a10nsp_interface) {
        network_if = bbl_get_a10nsp_interface(ctx, config->a10nsp_interface);
    } else {
        network_if = session->network_interface;
    }
    if(!network_if) {
        return false;
    }

    while(config) {
        if(config->stream_group_id == access_config->stream_group_id) {
            if(!network_if) {
                LOG(ERROR, "Failed to add stream because of missing network interface\n");
                return false;
            }

            timer_nsec = SEC / config->pps;
            timer_sec = timer_nsec / 1000000000;
            timer_nsec = timer_nsec % 1000000000;

            if(config->direction & STREAM_DIRECTION_UP) {
                stream = calloc(1, sizeof(bbl_stream));
                stream->flow_id = ctx->flow_id++;
                stream->flow_seq = 1;
                stream->config = config;
                stream->direction = STREAM_DIRECTION_UP;
                stream->interface = session->interface;
                stream->session = session;
                stream->tx_interval = timer_sec * 1e9 + timer_nsec;
                result = dict_insert(ctx->stream_flow_dict, &stream->flow_id);
                if (!result.inserted) {
                    LOG(ERROR, "Failed to insert stream %s\n", config->name);
                    free(stream);
                    return false;
                }
                *result.datum_ptr = stream;
                if(session->stream) {
                    session_stream = session->stream;
                    while(session_stream->next) {
                        session_stream = session_stream->next;
                    }
                    session_stream->next = stream;
                } else {
                    session->stream = stream;
                }
                if(config->threaded) {
                    bbl_stream_add_to_thread(ctx, config->thread_group, stream);
                } else {
                    timer_add_periodic(&ctx->timer_root, &stream->timer, config->name, timer_sec, timer_nsec, stream, &bbl_stream_tx_job);
                }
                timer_add_periodic(&ctx->timer_root, &stream->timer_rate, "Rate Computation", 1, 0, stream, &bbl_stream_rate_job);
                ctx->stats.stream_traffic_flows++;
                LOG(DEBUG, "Traffic stream %s added in upstream with %lf PPS (timer: %lu sec %lu nsec)\n", config->name, config->pps, timer_sec, timer_nsec);
            }
            if(config->direction & STREAM_DIRECTION_DOWN) {
                stream = calloc(1, sizeof(bbl_stream));
                stream->flow_id = ctx->flow_id++;
                stream->flow_seq = 1;
                stream->config = config;
                stream->direction = STREAM_DIRECTION_DOWN;
                stream->interface = network_if;
                stream->session = session;
                stream->tx_interval = timer_sec * 1e9 + timer_nsec;
                result = dict_insert(ctx->stream_flow_dict, &stream->flow_id);
                if (!result.inserted) {
                    LOG(ERROR, "Failed to insert stream %s\n", config->name);
                    free(stream);
                    return false;
                }
                *result.datum_ptr = stream;
                if(session->stream) {
                    session_stream = session->stream;
                    while(session_stream->next) {
                        session_stream = session_stream->next;
                    }
                    session_stream->next = stream;
                } else {
                    session->stream = stream;
                }
                if(config->threaded) {
                    bbl_stream_add_to_thread(ctx, config->thread_group, stream);
                } else {
                    timer_add_periodic(&ctx->timer_root, &stream->timer, config->name, timer_sec, timer_nsec, stream, &bbl_stream_tx_job);
                }
                timer_add_periodic(&ctx->timer_root, &stream->timer_rate, "Rate Computation", 1, 0, stream, &bbl_stream_rate_job);
                ctx->stats.stream_traffic_flows++;
                LOG(DEBUG, "Traffic stream %s added in downstream with %lf PPS (timer %lu sec %lu nsec)\n", config->name, config->pps, timer_sec, timer_nsec);
            }
        }
        config = config->next;
    }

    return true;
}

bool
bbl_stream_raw_add(bbl_ctx_s *ctx) {

    bbl_stream_config *config;
    bbl_stream *stream;
    bbl_interface_s *network_if;

    dict_insert_result result;

    time_t timer_sec = 0;
    long timer_nsec  = 0;

    config = ctx->config.stream_config;

    while(config) {
        if(config->stream_group_id == 0) {
            network_if = bbl_get_network_interface(ctx, config->network_interface);
            if(!network_if) {
                return false;
            }

            timer_nsec = SEC / config->pps;
            timer_sec = timer_nsec / 1000000000;
            timer_nsec = timer_nsec % 1000000000;

            if(config->direction & STREAM_DIRECTION_DOWN) {
                stream = calloc(1, sizeof(bbl_stream));
                stream->flow_id = ctx->flow_id++;
                stream->flow_seq = 1;
                stream->config = config;
                stream->direction = STREAM_DIRECTION_DOWN;
                stream->interface = network_if;
                stream->tx_interval = timer_sec * 1e9 + timer_nsec;
                result = dict_insert(ctx->stream_flow_dict, &stream->flow_id);
                if (!result.inserted) {
                    LOG(ERROR, "Failed to insert stream %s\n", config->name);
                    free(stream);
                    return false;
                }
                *result.datum_ptr = stream;
                if(config->threaded) {
                    bbl_stream_add_to_thread(ctx, config->thread_group, stream);
                } else {
                    timer_add_periodic(&ctx->timer_root, &stream->timer, config->name, timer_sec, timer_nsec, stream, &bbl_stream_tx_job);
                }
                timer_add_periodic(&ctx->timer_root, &stream->timer_rate, "Rate Computation", 1, 0, stream, &bbl_stream_rate_job);
                ctx->stats.stream_traffic_flows++;
                LOG(DEBUG, "RAW traffic stream %s added in downstream with %lf PPS (timer %lu sec %lu nsec)\n", config->name, config->pps, timer_sec, timer_nsec);
            }
        }
        config = config->next;
    }

    return true;
}

json_t *
bbl_stream_json(bbl_stream *stream) 
{
    json_t *root = NULL;

    if(!stream) {
        return NULL;
    }

    root = json_pack("{ss* ss si si si si si si si si si si si si si si si si si si sf sf sf}",
        "name", stream->config->name,
        "direction", stream->direction == STREAM_DIRECTION_UP ? "upstream" : "downstream",
        "flow-id", stream->flow_id,
        "rx-first-seq", stream->rx_first_seq,
        "rx-last-seq", stream->rx_last_seq,
        "rx-tos-tc", stream->rx_priority,
        "rx-outer-vlan-pbit", stream->rx_outer_vlan_pbit,
        "rx-inner-vlan-pbit", stream->rx_inner_vlan_pbit,
        "rx-len", stream->rx_len,
        "tx-len", stream->tx_len,
        "rx-packets", stream->packets_rx,
        "tx-packets", stream->packets_tx,
        "rx-loss", stream->loss,
        "rx-delay-nsec-min", stream->min_delay_ns,
        "rx-delay-nsec-max", stream->max_delay_ns,
        "rx-pps", stream->rate_packets_rx.avg,
        "tx-pps", stream->rate_packets_tx.avg,
        "tx-bps-l2", stream->rate_packets_tx.avg * stream->tx_len * 8,
        "rx-bps-l2", stream->rate_packets_rx.avg * stream->rx_len * 8,
        "rx-bps-l3", stream->rate_packets_rx.avg * stream->config->length * 8,
        "tx-mbps-l2", (double)(stream->rate_packets_tx.avg * stream->tx_len * 8) / 1000000.0,
        "rx-mbps-l2", (double)(stream->rate_packets_rx.avg * stream->rx_len * 8) / 1000000.0,
        "rx-mbps-l3", (double)(stream->rate_packets_rx.avg * stream->config->length * 8) / 1000000.0);

    return root;
}