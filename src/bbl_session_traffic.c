/*
 * BNG Blaster (BBL) - DHCPv6
 *
 * Christian Giese, May 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_session.h"

extern bool g_traffic;

void
bbl_session_traffic_ipv4(timer_s *timer)
{
    bbl_session_s *session = timer->data;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ipcp_state != BBL_PPP_OPENED) {
            return;
        }
        if(session->l2tp && session->l2tp_session == NULL) {
            return;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return;
        }
    }
    if(g_traffic && session->session_traffic) {
        session->send_requests |= BBL_SEND_SESSION_IPV4;
        bbl_session_tx_qnode_insert(session);
        session->network_send_requests |= BBL_SEND_SESSION_IPV4;
        bbl_session_network_tx_qnode_insert(session);
    }
}

void
bbl_session_traffic_ipv6(timer_s *timer)
{
    bbl_session_s *session = timer->data;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ip6cp_state != BBL_PPP_OPENED) {
            return;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return;
        }
    }
    if(g_traffic && session->session_traffic) {
        if(session->ipv6_prefix.len) {
            session->send_requests |= BBL_SEND_SESSION_IPV6;
            session->network_send_requests |= BBL_SEND_SESSION_IPV6;
        }
        bbl_session_tx_qnode_insert(session);
        bbl_session_network_tx_qnode_insert(session);
    }
}

void
bbl_session_traffic_ipv6pd(timer_s *timer)
{
    bbl_session_s *session = timer->data;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ip6cp_state != BBL_PPP_OPENED) {
            return;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return;
        }
    }
    if(g_traffic && session->session_traffic) {
        if(session->delegated_ipv6_prefix.len) {
            session->send_requests |= BBL_SEND_SESSION_IPV6PD;
            session->network_send_requests |= BBL_SEND_SESSION_IPV6PD;
        }
        bbl_session_tx_qnode_insert(session);
        bbl_session_network_tx_qnode_insert(session);
    }
}

static bool
bbl_session_traffic_add_ipv4_l2tp(bbl_ctx_s *ctx, bbl_session_s *session,
                                  struct bbl_interface_ *network_if)
{
    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t l2tp_ipv4 = {0};
    bbl_udp_t l2tp_udp = {0};
    bbl_l2tp_t l2tp = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};
    uint8_t *buf;
    uint16_t len = 0;

    bbl_l2tp_session_t *l2tp_session = session->l2tp_session;
    bbl_l2tp_tunnel_t *l2tp_tunnel = l2tp_session->tunnel;

    if(!session->network_ipv4_tx_packet_template) {
        session->network_ipv4_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
    }
    buf = session->network_ipv4_tx_packet_template;

    eth.dst = network_if->gateway_mac;
    eth.src = network_if->mac;
    eth.vlan_outer = network_if->vlan;
    eth.vlan_inner = 0;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &l2tp_ipv4;
    l2tp_ipv4.dst = l2tp_tunnel->peer_ip;
    l2tp_ipv4.src = l2tp_tunnel->server->ip;
    l2tp_ipv4.ttl = 64;
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
    session->network_ipv4_tx_seq = 1;
    if(!session->network_ipv4_tx_flow_id) {
        ctx->stats.session_traffic_flows++;
        session->session_traffic_flows++;
    }
    session->network_ipv4_tx_flow_id = ctx->flow_id++;
    bbl.flow_id = session->network_ipv4_tx_flow_id;
    bbl.direction = BBL_DIRECTION_DOWN;
    bbl.sub_type = BBL_SUB_TYPE_IPV4;

    if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
        return false;
    }
    session->network_ipv4_tx_packet_len = len;
    return true;
}

static bool
bbl_session_traffic_add_ipv4_a10nsp(bbl_ctx_s *ctx, bbl_session_s *session,
                                    struct bbl_interface_ *a10nsp_if)
{
    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv4_t ip = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};
    uint8_t *buf;
    uint16_t len = 0;

    bbl_a10nsp_session_t *a10nsp_session = session->a10nsp_session;

    if(!session->network_ipv4_tx_packet_template) {
        session->network_ipv4_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
    }
    buf = session->network_ipv4_tx_packet_template;

    eth.dst = session->client_mac;
    eth.src = a10nsp_if->mac;
    eth.vlan_outer = a10nsp_session->s_vlan;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.qinq = a10nsp_if->qinq;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV4;
        pppoe.next = &ip;
    } else {
        /* IPoE */
        eth.type = ETH_TYPE_IPV4;
        eth.next = &ip;
    }
    ip.dst = session->ip_address;
    ip.src = A10NSP_IP_LOCAL;
    ip.ttl = 64;
    ip.protocol = PROTOCOL_IPV4_UDP;
    ip.next = &udp;
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    session->network_ipv4_tx_seq = 1;
    if(!session->network_ipv4_tx_flow_id) {
        ctx->stats.session_traffic_flows++;
        session->session_traffic_flows++;
    }
    session->network_ipv4_tx_flow_id = ctx->flow_id++;
    bbl.flow_id = session->network_ipv4_tx_flow_id;
    bbl.direction = BBL_DIRECTION_DOWN;
    bbl.sub_type = BBL_SUB_TYPE_IPV4;
    if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
        return false;
    }
    session->network_ipv4_tx_packet_len = len;
    return true;
}

static bool
bbl_session_traffic_add_ipv4(bbl_ctx_s *ctx, bbl_session_s *session)
{
    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv4_t ip = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};
    uint8_t *buf;
    uint16_t len = 0;

    bbl_interface_s *network_if;

    if(session->l2tp_session) {
        network_if = session->l2tp_session->tunnel->interface;
    } else {
        network_if = session->network_interface;
    }
    if(!network_if) {
        return false;
    }

    /* Init BBL Session Key */
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.sub_type = BBL_SUB_TYPE_IPV4;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;

    /* Prepare Access (Session) to Network Packet */
    if(!session->access_ipv4_tx_packet_template) {
        session->access_ipv4_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
    }
    buf = session->access_ipv4_tx_packet_template;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV4;
        pppoe.next = &ip;
    } else {
        /* IPoE */
        eth.type = ETH_TYPE_IPV4;
        eth.next = &ip;
    }
    if(session->l2tp_session) {
        ip.dst = L2TP_IPCP_IP_LOCAL;
    } else if (session->a10nsp_session) {
        ip.dst = A10NSP_IP_LOCAL;
    } else {
        ip.dst = network_if->ip;
    }
    ip.src = session->ip_address;
    ip.offset = IPV4_DF;
    ip.ttl = 64;
    ip.protocol = PROTOCOL_IPV4_UDP;
    ip.next = &udp;
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    session->access_ipv4_tx_seq = 1;
    if(!session->access_ipv4_tx_flow_id) {
        ctx->stats.session_traffic_flows++;
        session->session_traffic_flows++;
    }
    session->access_ipv4_tx_flow_id = ctx->flow_id++;
    bbl.flow_id = session->access_ipv4_tx_flow_id;
    bbl.direction = BBL_DIRECTION_UP;

    if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
        return false;
    }
    session->access_ipv4_tx_packet_len = len;

    if(session->l2tp_session) {
        return bbl_session_traffic_add_ipv4_l2tp(ctx, session, network_if);
    } else if (session->a10nsp_session) {
        return bbl_session_traffic_add_ipv4_a10nsp(ctx, session, network_if);
    }

    /* Prepare Network to Access (Session) Packet */
    len = 0;
    if(!session->network_ipv4_tx_packet_template) {
        session->network_ipv4_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
    }
    buf = session->network_ipv4_tx_packet_template;

    eth.dst = network_if->gateway_mac;
    eth.src = network_if->mac;
    eth.qinq = false;
    eth.vlan_outer = network_if->vlan;
    eth.vlan_inner = 0;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &ip;
    ip.dst = session->ip_address;
    ip.src = network_if->ip;
    session->network_ipv4_tx_seq = 1;
    if(!session->network_ipv4_tx_flow_id) {
        ctx->stats.session_traffic_flows++;
        session->session_traffic_flows++;
    }
    session->network_ipv4_tx_flow_id = ctx->flow_id++;
    bbl.flow_id = session->network_ipv4_tx_flow_id;
    bbl.direction = BBL_DIRECTION_DOWN;

    if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
        return false;
    }
    session->network_ipv4_tx_packet_len = len;
    return true;
}

static bool
bbl_session_traffic_add_ipv6(bbl_ctx_s *ctx, bbl_session_s *session, bool ipv6_pd)
{
    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv6_t ip = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};
    uint8_t *buf;
    uint16_t len = 0;

    bbl_interface_s *network_if = session->network_interface;
    if(!(network_if && *(uint64_t*)network_if->ip6.address)) {
        return false;
    }

    /* Init BBL Session Key */
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;

    /* Prepare Access (Session) to Network Packet */
    if(ipv6_pd) {
        bbl.sub_type = BBL_SUB_TYPE_IPV6PD;
        if(!session->access_ipv6pd_tx_packet_template) {
            session->access_ipv6pd_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
        }
        buf = session->access_ipv6pd_tx_packet_template;
        ip.src = session->delegated_ipv6_address;
        session->access_ipv6pd_tx_seq = 1;
        if(!session->access_ipv6pd_tx_flow_id) {
            ctx->stats.session_traffic_flows++;
            session->session_traffic_flows++;
        }
        session->access_ipv6pd_tx_flow_id = ctx->flow_id++;
        bbl.flow_id = session->access_ipv6pd_tx_flow_id;
    } else {
        bbl.sub_type = BBL_SUB_TYPE_IPV6;
        if(!session->access_ipv6_tx_packet_template) {
            session->access_ipv6_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
        }
        buf = session->access_ipv6_tx_packet_template;
        ip.src = session->ipv6_address;
        session->access_ipv6_tx_seq = 1;
        if(!session->access_ipv6_tx_flow_id) {
            ctx->stats.session_traffic_flows++;
            session->session_traffic_flows++;
        }
        session->access_ipv6_tx_flow_id = ctx->flow_id++;
        bbl.flow_id = session->access_ipv6_tx_flow_id;
    }

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV6;
        pppoe.next = &ip;
    } else {
        /* IPoE */
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ip;
    }
    ip.dst = network_if->ip6.address;
    ip.ttl = 64;
    ip.protocol = IPV6_NEXT_HEADER_UDP;
    ip.next = &udp;
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.direction = BBL_DIRECTION_UP;

    if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
        return false;
    }
    if(ipv6_pd) {
        session->access_ipv6pd_tx_packet_len = len;
    } else {
        session->access_ipv6_tx_packet_len = len;
    }

    /* Prepare Network to Access (Session) Packet */
    len = 0;
    if(ipv6_pd) {
        if(!session->network_ipv6pd_tx_packet_template) {
            session->network_ipv6pd_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
        }
        buf = session->network_ipv6pd_tx_packet_template;
        ip.dst = session->delegated_ipv6_address;
        session->network_ipv6pd_tx_seq = 1;
        if(!session->network_ipv6pd_tx_flow_id) {
            ctx->stats.session_traffic_flows++;
            session->session_traffic_flows++;
        }
        session->network_ipv6pd_tx_flow_id = ctx->flow_id++;
        bbl.flow_id = session->network_ipv6pd_tx_flow_id;
    } else {
        if(!session->network_ipv6_tx_packet_template) {
            session->network_ipv6_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
        }
        buf = session->network_ipv6_tx_packet_template;
        ip.dst = session->ipv6_address;
        session->network_ipv6_tx_seq = 1;
        if(!session->network_ipv6_tx_flow_id) {
            ctx->stats.session_traffic_flows++;
            session->session_traffic_flows++;
        }
        session->network_ipv6_tx_flow_id = ctx->flow_id++;
        bbl.flow_id = session->network_ipv6_tx_flow_id;
    }

    eth.dst = network_if->gateway_mac;
    eth.src = network_if->mac;
    eth.qinq = false;
    eth.vlan_outer = network_if->vlan;
    eth.vlan_inner = 0;
    eth.type = ETH_TYPE_IPV6;
    eth.next = &ip;
    ip.src = network_if->ip6.address;
    bbl.direction = BBL_DIRECTION_DOWN;

    if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
        return false;
    }
    if(ipv6_pd) {
        session->network_ipv6pd_tx_packet_len = len;
    } else {
        session->network_ipv6_tx_packet_len = len;
    }
    return true;
}

bool
bbl_session_traffic_start_ipv4(bbl_ctx_s *ctx, bbl_session_s *session) {

    uint64_t tx_interval;

    if(ctx->config.session_traffic_ipv4_pps && session->ip_address &&
       (ctx->interfaces.network_if_count || session->a10nsp_session)) {
        /* Start IPv4 Session Traffic */
        if(bbl_session_traffic_add_ipv4(ctx, session)) {
            if(ctx->config.session_traffic_ipv4_pps > 1) {
                tx_interval = 1000000000 / ctx->config.session_traffic_ipv4_pps;
                if(tx_interval < ctx->config.tx_interval) {
                    /* It is not possible to send faster than TX interval. */
                    tx_interval = ctx->config.tx_interval;
                }
                timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv4, "Session Traffic IPv4",
                                   0, tx_interval, session, &bbl_session_traffic_ipv4);
            } else {
                timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv4, "Session Traffic IPv4",
                                   1, 0, session, &bbl_session_traffic_ipv4);
            }
            return true;
        } else {
            LOG(ERROR, "Traffic (ID: %u) failed to create IPv4 session traffic\n", session->session_id);
        }
    }
    return false;
}

bool
bbl_session_traffic_start_ipv6(bbl_ctx_s *ctx, bbl_session_s *session) {

    uint64_t tx_interval;

    if(ctx->config.session_traffic_ipv6_pps && *(uint64_t*)session->ipv6_address && ctx->interfaces.network_if_count) {
        /* Start IPv6 Session Traffic */
        if(bbl_session_traffic_add_ipv6(ctx, session, false)) {
            if(ctx->config.session_traffic_ipv6_pps > 1) {
                tx_interval = 1000000000 / ctx->config.session_traffic_ipv6_pps;
                if(tx_interval < ctx->config.tx_interval) {
                    /* It is not possible to send faster than TX interval. */
                    tx_interval = ctx->config.tx_interval;
                }
                timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv6, "Session Traffic IPv6",
                                   0, tx_interval, session, &bbl_session_traffic_ipv6);
            } else {
                timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv6, "Session Traffic IPv6",
                                   1, 0, session, &bbl_session_traffic_ipv6);
            }
            return true;
        } else {
            LOG(ERROR, "Traffic (ID: %u) failed to create IPv6 session traffic\n", session->session_id);
        }
    }
    return false;
}

bool
bbl_session_traffic_start_ipv6pd(bbl_ctx_s *ctx, bbl_session_s *session) {

    uint64_t tx_interval;

    if(ctx->config.session_traffic_ipv6pd_pps && *(uint64_t*)session->delegated_ipv6_address && ctx->interfaces.network_if_count) {
        /* Start IPv6 PD Session Traffic */
        if(bbl_session_traffic_add_ipv6(ctx, session, true)) {
            if(ctx->config.session_traffic_ipv6pd_pps > 1) {
                tx_interval = 1000000000 / ctx->config.session_traffic_ipv6pd_pps;
                if(tx_interval < ctx->config.tx_interval) {
                    /* It is not possible to send faster than TX interval. */
                    tx_interval = ctx->config.tx_interval;
                }
                timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv6pd, "Session Traffic IPv6 PD",
                                   0, tx_interval, session, &bbl_session_traffic_ipv6pd);
            } else {
                timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv6pd, "Session Traffic IPv6 PD",
                                   1, 0, session, &bbl_session_traffic_ipv6pd);
            }
            return true;
        } else {
            LOG(ERROR, "Traffic (ID: %u) failed to create IPv6 PD session traffic\n", session->session_id);
        }
    }
    return false;
}