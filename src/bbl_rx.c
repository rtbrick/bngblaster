/*
 * BNG Blaster (BBL) - RX Job
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_session.h"
#include "bbl_stream.h"
#include <openssl/md5.h>
#include <openssl/rand.h>

struct keyval_ igmp_msg_names[] = {
    { IGMP_TYPE_QUERY,      "general-query" },
    { IGMP_TYPE_REPORT_V1,  "v1-report" },
    { IGMP_TYPE_REPORT_V2,  "v2-report" },
    { IGMP_TYPE_LEAVE,      "v2-leave" },
    { IGMP_TYPE_REPORT_V3,  "v3-report" },
    { 0, NULL}
};

bool
bbl_add_session_packets_ipv4_l2tp (bbl_ctx_s *ctx, bbl_session_s *session)
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

    eth.dst = ctx->op.network_if->gateway_mac;
    eth.src = ctx->op.network_if->mac;
    eth.vlan_outer = ctx->config.network_vlan;
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

bool
bbl_add_session_packets_ipv4 (bbl_ctx_s *ctx, bbl_session_s *session)
{
    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv4_t ip = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};
    uint8_t *buf;
    uint16_t len = 0;

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
    ip.dst = ctx->op.network_if->ip;
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
    }
    session->access_ipv4_tx_flow_id = ctx->flow_id++;
    bbl.flow_id = session->access_ipv4_tx_flow_id;
    bbl.direction = BBL_DIRECTION_UP;

    if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
        return false;
    }
    session->access_ipv4_tx_packet_len = len;

    if(session->l2tp_session) {
        return bbl_add_session_packets_ipv4_l2tp(ctx, session);
    }

    /* Prepare Network to Access (Session) Packet */
    len = 0;
    if(!session->network_ipv4_tx_packet_template) {
        session->network_ipv4_tx_packet_template = malloc(DATA_TRAFFIC_MAX_LEN);
    }
    buf = session->network_ipv4_tx_packet_template;

    eth.dst = ctx->op.network_if->gateway_mac;
    eth.src = ctx->op.network_if->mac;
    eth.vlan_outer = ctx->config.network_vlan;
    eth.vlan_inner = 0;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &ip;
    ip.dst = session->ip_address;
    ip.src = ctx->op.network_if->ip;
    session->network_ipv4_tx_seq = 1;
    if(!session->network_ipv4_tx_flow_id) {
        ctx->stats.session_traffic_flows++;
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

bool
bbl_add_session_packets_ipv6 (bbl_ctx_s *ctx, bbl_session_s *session, bool ipv6_pd)
{
    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv6_t ip = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};
    uint8_t *buf;
    uint16_t len = 0;

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
        }
        session->access_ipv6_tx_flow_id = ctx->flow_id++;
        bbl.flow_id = session->access_ipv6_tx_flow_id;
    }

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
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
    ip.dst = ctx->op.network_if->ip6.address;
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
        }
        session->network_ipv6_tx_flow_id = ctx->flow_id++;
        bbl.flow_id = session->network_ipv6_tx_flow_id;
    }

    eth.dst = ctx->op.network_if->gateway_mac;
    eth.src = ctx->op.network_if->mac;
    eth.vlan_outer = ctx->config.network_vlan;
    eth.vlan_inner = 0;
    eth.type = ETH_TYPE_IPV6;
    eth.next = &ip;
    ip.src = ctx->op.network_if->ip6.address;
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

void
bbl_session_traffic_ipv4(timer_s *timer)
{
    bbl_session_s *session = timer->data;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ipcp_state != BBL_PPP_OPENED) {
            timer->periodic = false; /* Stop periodic timer */
            return;
        }
        if(session->l2tp && session->l2tp_session == NULL) {
            timer->periodic = false; /* Stop periodic timer */
            return;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            timer->periodic = false; /* Stop periodic timer */
            return;
        }
    }
    if(session->session_traffic) {
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
            timer->periodic = false; /* Stop periodic timer */
            return;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            timer->periodic = false; /* Stop periodic timer */
            return;
        }
    }
    if(session->session_traffic) {
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
            timer->periodic = false; /* Stop periodic timer */
            return;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            timer->periodic = false; /* Stop periodic timer */
            return;
        }
    }
    if(session->session_traffic) {
        if(session->delegated_ipv6_prefix.len) {
            session->send_requests |= BBL_SEND_SESSION_IPV6PD;
            session->network_send_requests |= BBL_SEND_SESSION_IPV6PD;
        }
        bbl_session_tx_qnode_insert(session);
        bbl_session_network_tx_qnode_insert(session);
    }
}

void
bbl_lcp_echo(timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    session = timer->data;
    interface = session->interface;
    ctx = interface->ctx;

    if(session->session_state == BBL_ESTABLISHED) {
        if(session->lcp_retries) {
            interface->stats.lcp_echo_timeout++;
        }
        if(session->lcp_retries > ctx->config.lcp_keepalive_retry) {
            LOG(PPPOE, "LCP ECHO TIMEOUT (ID: %u)\n", session->session_id);
            /* Force terminate session after timeout. */
            session->send_requests = BBL_SEND_DISCOVERY;
            bbl_session_update_state(ctx, session, BBL_TERMINATING);
            bbl_session_tx_qnode_insert(session);
        } else {
            session->lcp_request_code = PPP_CODE_ECHO_REQUEST;
            session->lcp_identifier++;
            session->lcp_options_len = 0;
            session->send_requests |= BBL_SEND_LCP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        }
    }
}


void
bbl_igmp_zapping(timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    uint32_t next_group;
    bbl_igmp_group_s *group;

    session = timer->data;
    interface = session->interface;
    ctx = interface->ctx;

    uint32_t join_delay = 0;
    uint32_t leave_delay = 0;
    struct timespec time_diff;
    struct timespec time_now;

    uint32_t ms;

    if(session->session_state != BBL_ESTABLISHED ||
       session->ipcp_state != BBL_PPP_OPENED) {
        return;
    }

    if(!session->zapping_joined_group || !session->zapping_leaved_group) {
        return;
    }

    if(session->zapping_view_start_time.tv_sec) {
        clock_gettime(CLOCK_MONOTONIC, &time_now);
        timespec_sub(&time_diff, &time_now, &session->zapping_view_start_time);
        if(time_diff.tv_sec >= ctx->config.igmp_zap_view_duration) {
            session->zapping_view_start_time.tv_sec = 0;
            session->zapping_count = 0;
        } else {
            return;
        }
    }

    /* Calculate last join delay... */
    group = session->zapping_joined_group;
    if(group->first_mc_rx_time.tv_sec) {
        timespec_sub(&time_diff, &group->first_mc_rx_time, &group->join_tx_time);
        ms = time_diff.tv_nsec / 1000000; // convert nanoseconds to milliseconds
        if(time_diff.tv_nsec % 1000000) ms++; // simple roundup function
        join_delay = (time_diff.tv_sec * 1000) + ms;
        if(!join_delay) join_delay = 1; // join delay must be at least one millisecond
        session->zapping_join_delay_sum += join_delay;
        session->zapping_join_delay_count++;
        if(join_delay > session->stats.max_join_delay) session->stats.max_join_delay = join_delay;
        if(session->stats.min_join_delay) {
            if(join_delay < session->stats.min_join_delay) session->stats.min_join_delay = join_delay;
        } else {
            session->stats.min_join_delay = join_delay;
        }
        session->stats.avg_join_delay = session->zapping_join_delay_sum / session->zapping_join_delay_count;

        LOG(IGMP, "IGMP (ID: %u) ZAPPING %u ms join delay for group %s\n",
            session->session_id, join_delay, format_ipv4_address(&group->group));
    } else {
        if(ctx->config.igmp_zap_wait) {
            /* Wait until MC traffic is received ... */
            return;
        } else {
            session->stats.mc_not_received++;
            LOG(IGMP, "IGMP (ID: %u) ZAPPING join failed for group %s\n",
                session->session_id, format_ipv4_address(&group->group));
        }
    }

    /* Select next group to be joined ... */
    next_group = be32toh(group->group) + be32toh(ctx->config.igmp_group_iter);
    if(next_group > session->zapping_group_max) {
        next_group = ctx->config.igmp_group;
    } else {
        next_group = htobe32(next_group);
    }

    /* Leave last joined group ... */
    group->state = IGMP_GROUP_LEAVING;
    group->robustness_count = session->igmp_robustness;
    group->send = true;
    group->leave_tx_time.tv_sec = 0;
    group->leave_tx_time.tv_nsec = 0;
    group->last_mc_rx_time.tv_sec = 0;
    group->last_mc_rx_time.tv_nsec = 0;

    /* Calculate last leave delay ... */
    group = session->zapping_leaved_group;
    if(group->group && group->last_mc_rx_time.tv_sec && group->leave_tx_time.tv_sec) {
        timespec_sub(&time_diff, &group->last_mc_rx_time, &group->leave_tx_time);
        ms = time_diff.tv_nsec / 1000000; // convert nanoseconds to milliseconds
        if(time_diff.tv_nsec % 1000000) ms++; // simple roundup function
        leave_delay = (time_diff.tv_sec * 1000) + ms;
        if(!leave_delay) leave_delay = 1; // leave delay must be at least one millisecond
        session->zapping_leave_delay_sum += leave_delay;
        session->zapping_leave_delay_count++;
        if(leave_delay > session->stats.max_leave_delay) session->stats.max_leave_delay = leave_delay;
        if(session->stats.min_leave_delay) {
            if(leave_delay < session->stats.min_leave_delay) session->stats.min_leave_delay = leave_delay;
        } else {
            session->stats.min_leave_delay = leave_delay;
        }
        session->stats.avg_leave_delay = session->zapping_leave_delay_sum / session->zapping_leave_delay_count;

        LOG(IGMP, "IGMP (ID: %u) ZAPPING %u ms leave delay for group %s\n",
            session->session_id, leave_delay, format_ipv4_address(&group->group));
    }

    /* Join next group ... */
    group->group = next_group;
    group->state = IGMP_GROUP_JOINING;
    group->robustness_count = session->igmp_robustness;
    group->send = true;
    group->packets = 0;
    group->loss = 0;
    group->join_tx_time.tv_sec = 0;
    group->join_tx_time.tv_nsec = 0;
    group->first_mc_rx_time.tv_sec = 0;
    group->first_mc_rx_time.tv_nsec = 0;
    group->leave_tx_time.tv_sec = 0;
    group->leave_tx_time.tv_nsec = 0;
    group->last_mc_rx_time.tv_sec = 0;
    group->last_mc_rx_time.tv_nsec = 0;

    session->send_requests |= BBL_SEND_IGMP;
    bbl_session_tx_qnode_insert(session);

    /* Swap join/leave */
    session->zapping_leaved_group = session->zapping_joined_group;
    session->zapping_joined_group = group;

    LOG(IGMP, "IGMP (ID: %u) ZAPPING leave %s join %s\n",
        session->session_id,
        format_ipv4_address(&session->zapping_leaved_group->group),
        format_ipv4_address(&session->zapping_joined_group->group));

    /* Handle viewing profile */
    session->zapping_count++;
    if(ctx->config.igmp_zap_count && ctx->config.igmp_zap_view_duration) {
        if(session->zapping_count >= ctx->config.igmp_zap_count) {
            clock_gettime(CLOCK_MONOTONIC, &session->zapping_view_start_time);
        }
    }
}

void
bbl_igmp_initial_join(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    bbl_interface_s *interface = session->interface;
    bbl_ctx_s *ctx = interface->ctx;
    uint32_t initial_group;
    bbl_igmp_group_s *group;

    int group_start_index = 0;

    if(session->session_state != BBL_ESTABLISHED ||
       (session->access_type == ACCESS_TYPE_PPPOE && session->ipcp_state != BBL_PPP_OPENED)) {
        return;
    }

    /* Get initial group */
    if(ctx->config.igmp_group_count > 1) {
        group_start_index = rand() % ctx->config.igmp_group_count;
    }
    initial_group = htobe32(be32toh(ctx->config.igmp_group) + (group_start_index * be32toh(ctx->config.igmp_group_iter)));

    group = &session->igmp_groups[0];
    memset(group, 0x0, sizeof(bbl_igmp_group_s));
    group->group = initial_group;
    group->source[0] = ctx->config.igmp_source;
    group->robustness_count = session->igmp_robustness;
    group->state = IGMP_GROUP_JOINING;
    group->send = true;
    session->zapping_count = 1;
    session->send_requests |= BBL_SEND_IGMP;
    bbl_session_tx_qnode_insert(session);

    LOG(IGMP, "IGMP (ID: %u) initial join for group %s\n",
        session->session_id, format_ipv4_address(&group->group));

    if(ctx->config.igmp_group_count > 1 && ctx->config.igmp_zap_interval > 0) {
        /* Start/Init Zapping Logic ... */
        group->zapping = true;
        session->zapping_joined_group = group;
        group = &session->igmp_groups[1];
        session->zapping_leaved_group = group;
        memset(group, 0x0, sizeof(bbl_igmp_group_s));
        group->zapping = true;
        group->source[0] = ctx->config.igmp_source;

        if(ctx->config.igmp_zap_count && ctx->config.igmp_zap_view_duration) {
            session->zapping_count = rand() % ctx->config.igmp_zap_count;
        }

        /* Adding 1 nanosecond to enforce a dedicated timer bucket for zapping. */
        timer_add_periodic(&ctx->timer_root, &session->timer_zapping, "IGMP Zapping", ctx->config.igmp_zap_interval, 1, session, bbl_igmp_zapping);
        LOG(IGMP, "IGMP (ID: %u) ZAPPING start zapping with interval %u\n",
            session->session_id, ctx->config.igmp_zap_interval);

        timer_smear_bucket(&ctx->timer_root, ctx->config.igmp_zap_interval, 1);
    }
}

void
bbl_rx_dhcpv6(bbl_ipv6_t *ipv6, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_udp_t *udp = (bbl_udp_t*)ipv6->next;
    bbl_dhcpv6_t *dhcpv6 = (bbl_dhcpv6_t*)udp->next;
    bbl_ctx_s *ctx = interface->ctx;
    uint64_t tx_interval;

    if(dhcpv6->server_duid_len && dhcpv6->server_duid_len < DHCPV6_BUFFER) {
        memcpy(session->server_duid, dhcpv6->server_duid, dhcpv6->server_duid_len);
        session->server_duid_len = dhcpv6->server_duid_len;
    }
    if(dhcpv6->type == DHCPV6_MESSAGE_REPLY) {
        if(dhcpv6->delegated_prefix) {
            if(!session->dhcpv6_received) {
                if(dhcpv6->delegated_prefix->len) {
                    memcpy(&session->delegated_ipv6_prefix, dhcpv6->delegated_prefix, sizeof(ipv6_prefix));
                    *(uint64_t*)&session->delegated_ipv6_address[0] = *(uint64_t*)session->delegated_ipv6_prefix.address;
                    *(uint64_t*)&session->delegated_ipv6_address[8] = session->ip6cp_ipv6_identifier;
                    LOG(IP, "IPv6 (ID: %u) DHCPv6 PD prefix %s/%d\n", session->session_id,
                        format_ipv6_address(&session->delegated_ipv6_prefix.address), session->delegated_ipv6_prefix.len);
                    if(dhcpv6->dns1) {
                        memcpy(&session->dhcpv6_dns1, dhcpv6->dns1, IPV6_ADDR_LEN);
                        if(dhcpv6->dns2) {
                            memcpy(&session->dhcpv6_dns2, dhcpv6->dns2, IPV6_ADDR_LEN);
                        }
                    }
                    if(session->l2tp == false && ctx->config.session_traffic_ipv6pd_pps && 
                       ctx->op.network_if && ctx->op.network_if->ip6.len) {
                        /* Start IPv6 PD Session Traffic */
                        if(bbl_add_session_packets_ipv6(ctx, session, true)) {
                            if(ctx->config.session_traffic_ipv6pd_pps > 1) {
                                tx_interval = 1000000000 / ctx->config.session_traffic_ipv6pd_pps;
                                if(tx_interval < ctx->config.tx_interval) {
                                    /* It is not possible to send faster than TX interval. */
                                    tx_interval = ctx->config.tx_interval;
                                }
                                timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv6pd, "Session Traffic IPv6PD",
                                                   0, tx_interval, session, bbl_session_traffic_ipv6pd);
                            } else {
                                timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv6pd, "Session Traffic IPv6PD",
                                                   1, 0, session, bbl_session_traffic_ipv6pd);
                            }
                        } else {
                            LOG(ERROR, "Traffic (ID: %u) failed to create IPv6 session traffic\n", session->session_id);
                        }
                    }
                }
            }
        }
        if(!session->dhcpv6_received) {
            ctx->dhcpv6_established++;
            if(ctx->dhcpv6_established > ctx->dhcpv6_established_max) {
                ctx->dhcpv6_established_max = ctx->dhcpv6_established;
            }
        }
        session->dhcpv6_received = true;
        session->send_requests &= ~BBL_SEND_DHCPV6_REQUEST;
    } else if(dhcpv6->type == DHCPV6_MESSAGE_ADVERTISE) {
        if(dhcpv6->ia_pd_option_len && dhcpv6->ia_pd_option_len < DHCPV6_BUFFER) {
            memcpy(session->dhcpv6_ia_pd_option, dhcpv6->ia_pd_option, dhcpv6->ia_pd_option_len);
            session->dhcpv6_ia_pd_option_len = dhcpv6->ia_pd_option_len;
            session->dhcpv6_type = DHCPV6_MESSAGE_REQUEST;
        }
        session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
        bbl_session_tx_qnode_insert(session);
    }
}

void
bbl_rx_stream(bbl_interface_s *interface, bbl_ethernet_header_t *eth, bbl_bbl_t *bbl, uint8_t tos) {

    bbl_stream *stream;
    void **search = NULL;

    struct timespec delay;
    uint64_t delay_nsec;

    search = dict_search(interface->ctx->stream_flow_dict, &bbl->flow_id);
    if(search) {
        stream = *search;
        stream->packets_rx++;
        stream->rx_len = eth->length;
        stream->rx_priority = tos;
        stream->rx_outer_vlan_pbit = eth->vlan_outer_priority;
        stream->rx_inner_vlan_pbit = eth->vlan_inner_priority;

        timespec_sub(&delay, &eth->timestamp, &bbl->timestamp);
        delay_nsec = delay.tv_sec * 1000000000 + delay.tv_nsec;
        if(delay_nsec > stream->max_delay_ns) {
            stream->max_delay_ns = delay_nsec;
        }
        if(stream->min_delay_ns) {
            if(delay_nsec < stream->min_delay_ns) {
                stream->min_delay_ns = delay_nsec;
            }
        } else {
            stream->min_delay_ns = delay_nsec;
        }
        if(!stream->rx_first_seq) {
            stream->rx_first_seq = bbl->flow_seq;
        } else {
            if(stream->rx_last_seq +1 != bbl->flow_seq) {
                stream->loss++;
            }
        }
        stream->rx_last_seq = bbl->flow_seq;
    }
}

void
bbl_rx_udp(bbl_ethernet_header_t *eth, bbl_ipv6_t *ipv6, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_udp_t *udp = (bbl_udp_t*)ipv6->next;
    bbl_bbl_t *bbl = NULL;

    switch(udp->dst) {
        case DHCPV6_UDP_CLIENT:
        case DHCPV6_UDP_SERVER:
            interface->stats.dhcpv6_rx++;
            return bbl_rx_dhcpv6(ipv6, interface, session);
        case BBL_UDP_PORT:
            bbl = (bbl_bbl_t*)udp->next;
            session->stats.accounting_packets_rx++;
            session->stats.accounting_bytes_rx += eth->length;
            break;
        default:
            break;
    }

    /* BBL receive handler */
    if(bbl && bbl->type == BBL_TYPE_UNICAST_SESSION) {
        switch (bbl->sub_type) {
            case BBL_SUB_TYPE_IPV6:
                if(bbl->outer_vlan_id != session->vlan_key.outer_vlan_id ||
                   bbl->inner_vlan_id != session->vlan_key.inner_vlan_id) {
                    interface->stats.session_ipv6_wrong_session++;
                    return;
                }
                if(bbl->flow_id == session->network_ipv6_tx_flow_id) {
                    /* Session traffic */
                    interface->stats.session_ipv6_rx++;
                    session->stats.access_ipv6_rx++;
                    if(!session->access_ipv6_rx_first_seq) {
                        session->access_ipv6_rx_first_seq = bbl->flow_seq;
                        interface->ctx->stats.session_traffic_flows_verified++;
                    } else {
                        if(session->access_ipv6_rx_last_seq +1 != bbl->flow_seq) {
                            interface->stats.session_ipv6_loss++;
                            session->stats.access_ipv6_loss++;
                            LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                session->session_id, bbl->flow_id, bbl->flow_seq, session->access_ipv6_rx_last_seq);
                        }
                    }
                    session->access_ipv6_rx_last_seq = bbl->flow_seq;
                } else {
                    bbl_rx_stream(interface, eth, bbl, ipv6->tos);
                }
                break;
            case BBL_SUB_TYPE_IPV6PD:
                if(bbl->outer_vlan_id != session->vlan_key.outer_vlan_id ||
                   bbl->inner_vlan_id != session->vlan_key.inner_vlan_id) {
                    interface->stats.session_ipv6pd_wrong_session++;
                    return;
                }
                if(bbl->flow_id == session->network_ipv6pd_tx_flow_id) {
                    /* Session traffic */
                    interface->stats.session_ipv6pd_rx++;
                    session->stats.access_ipv6pd_rx++;
                    if(!session->access_ipv6pd_rx_first_seq) {
                        session->access_ipv6pd_rx_first_seq = bbl->flow_seq;
                        interface->ctx->stats.session_traffic_flows_verified++;
                    } else {
                        if(session->access_ipv6pd_rx_last_seq +1 != bbl->flow_seq) {
                            interface->stats.session_ipv6pd_loss++;
                            session->stats.access_ipv6pd_loss++;
                            LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                session->session_id, bbl->flow_id, bbl->flow_seq, session->access_ipv6pd_rx_last_seq);
                        }
                    }
                    session->access_ipv6pd_rx_last_seq = bbl->flow_seq;
                } else {
                    bbl_rx_stream(interface, eth, bbl, ipv6->tos);
                }
                break;
            default:
                break;
        }
    }
}

void
bbl_rx_icmpv6(bbl_ipv6_t *ipv6, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_icmpv6_t *icmpv6 = (bbl_icmpv6_t*)ipv6->next;
    bbl_ctx_s *ctx = interface->ctx;
    uint64_t tx_interval;

    session->stats.icmpv6_rx++;
    if(icmpv6->type == IPV6_ICMPV6_ROUTER_ADVERTISEMENT) {
        if(!session->icmpv6_ra_received) {
            /* The first RA received ... */
            if(icmpv6->prefix.len) {
                memcpy(&session->ipv6_prefix, &icmpv6->prefix, sizeof(ipv6_prefix));
                *(uint64_t*)&session->ipv6_address[0] = *(uint64_t*)session->ipv6_prefix.address;
                *(uint64_t*)&session->ipv6_address[8] = session->ip6cp_ipv6_identifier;
                LOG(IP, "IPv6 (ID: %u) ICMPv6 RA prefix %s/%d\n",
                    session->session_id, format_ipv6_address(&session->ipv6_prefix.address), session->ipv6_prefix.len);
                if(icmpv6->dns1) {
                    memcpy(&session->ipv6_dns1, icmpv6->dns1, IPV6_ADDR_LEN);
                    if(icmpv6->dns2) {
                        memcpy(&session->ipv6_dns2, icmpv6->dns2, IPV6_ADDR_LEN);
                    }
                }
                if(session->l2tp == false && ctx->config.session_traffic_ipv6_pps && 
                   ctx->op.network_if && ctx->op.network_if->ip6.len) {
                    /* Start IPv6 Session Traffic */
                    if(bbl_add_session_packets_ipv6(ctx, session, false)) {
                        if(ctx->config.session_traffic_ipv6_pps > 1) {
                            tx_interval = 1000000000 / ctx->config.session_traffic_ipv6_pps;
                            if(tx_interval < ctx->config.tx_interval) {
                                /* It is not possible to send faster than TX interval. */
                                tx_interval = ctx->config.tx_interval;
                            }
                            timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv6, "Session Traffic IPv6",
                                               0, tx_interval, session, bbl_session_traffic_ipv6);
                        } else {
                            timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv6, "Session Traffic IPv6",
                                               1, 0, session, bbl_session_traffic_ipv6);
                        }
                    } else {
                        LOG(ERROR, "Traffic (ID: %u) failed to create IPv6 session traffic\n", session->session_id);
                    }
                }
            }
            if(icmpv6->other) {
                if(ctx->config.dhcpv6_enable) {
                    if(!session->dhcpv6_requested) {
                        ctx->dhcpv6_requested++;
                    }
                    session->dhcpv6_requested = true;
                    session->dhcpv6_type = DHCPV6_MESSAGE_SOLICIT;
                    session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
                    bbl_session_tx_qnode_insert(session);
                }
            }
        }
        session->icmpv6_ra_received = true;
    }
#if 0
    /* TODO: ICMPv6 neighbor discovery over PPPoE is currently not implemented! */
     else if(icmpv6->type == IPV6_ICMPV6_NEIGHBOR_SOLICITATION) {
        session->send_requests |= BBL_SEND_ICMPV6_NA;
    }
#endif
}

void
bbl_rx_icmp(bbl_ipv4_t *ipv4, bbl_session_s *session) {

    bbl_icmp_t *icmp = (bbl_icmp_t*)ipv4->next;

    if(icmp->type == ICMP_TYPE_ECHO_REQUEST) {
        session->icmp_reply_type = ICMP_TYPE_ECHO_REPLY;
        session->icmp_reply_destination = ipv4->src;
        if(icmp->data_len) {
            if(icmp->data_len > ICMP_DATA_BUFFER) {
                memcpy(session->icmp_reply_data, icmp->data, ICMP_DATA_BUFFER);
                session->icmp_reply_data_len = ICMP_DATA_BUFFER;
            } else {
                memcpy(session->icmp_reply_data, icmp->data, icmp->data_len);
                session->icmp_reply_data_len = icmp->data_len;
            }
        }
        session->send_requests |= BBL_SEND_ICMP_REPLY;
        bbl_session_tx_qnode_insert(session);
    }
}

void
bbl_rx_igmp(bbl_ipv4_t *ipv4, bbl_session_s *session) {

    bbl_igmp_t *igmp = (bbl_igmp_t*)ipv4->next;
    bbl_igmp_group_s *group = NULL;
    int i;
    bool send = false;

#if 0
    LOG(IGMP, "IGMPv%d (ID: %u) type %s received\n",
        igmp->version,
        session->session_id,
        val2key(igmp_msg_names, igmp->type));
#endif

    if(igmp->type == IGMP_TYPE_QUERY) {

        if(igmp->robustness) {
            session->igmp_robustness = igmp->robustness;
        }

        if(igmp->group) {
            /* Group Specfic Query */
            for(i=0; i < IGMP_MAX_GROUPS; i++) {
                group = &session->igmp_groups[i];
                if(group->group == igmp->group &&
                   group->state == IGMP_GROUP_ACTIVE) {
                    group->send = true;
                    send = true;
                }
            }
        } else {
            /* General Query */
            for(i=0; i < IGMP_MAX_GROUPS; i++) {
                group = &session->igmp_groups[i];
                if(group->state == IGMP_GROUP_ACTIVE) {
                    group->send = true;
                    send = true;
                }
            }
        }

        if(send) {
            session->send_requests |= BBL_SEND_IGMP;
            bbl_session_tx_qnode_insert(session);
        }
    }
}

void
bbl_rx_ipv4(bbl_ethernet_header_t *eth, bbl_ipv4_t *ipv4, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_udp_t *udp;
    bbl_bbl_t *bbl = NULL;
    bbl_igmp_group_s *group = NULL;
    int i;

    if(ipv4->offset & ~IPV4_DF) {
        /* Reassembling of fragmented IPv4 packets is currently not supported. */
        session->stats.ipv4_fragmented_rx++;
        interface->stats.ipv4_fragmented_rx++;
    }

    switch(ipv4->protocol) {
        case PROTOCOL_IPV4_IGMP:
            session->stats.igmp_rx++;
            interface->stats.igmp_rx++;
            return bbl_rx_igmp(ipv4, session);
        case PROTOCOL_IPV4_ICMP:
            session->stats.icmp_rx++;
            interface->stats.icmp_rx++;
            return bbl_rx_icmp(ipv4, session);
        case PROTOCOL_IPV4_UDP:
            udp = (bbl_udp_t*)ipv4->next;
            if(udp->protocol == UDP_PROTOCOL_BBL) {
                bbl = (bbl_bbl_t*)udp->next;
            }
            break;
        default:
            break;
    }

    session->stats.accounting_packets_rx++;
    session->stats.accounting_bytes_rx += eth->length;

    /* BBL receive handler */
    if(bbl) {
        if(bbl->type == BBL_TYPE_UNICAST_SESSION) {
            if(bbl->outer_vlan_id != session->vlan_key.outer_vlan_id ||
               bbl->inner_vlan_id != session->vlan_key.inner_vlan_id) {
                interface->stats.session_ipv4_wrong_session++;
                return;
            }
            if(bbl->flow_id == session->network_ipv4_tx_flow_id) {
                /* Session traffic */
                interface->stats.session_ipv4_rx++;
                session->stats.access_ipv4_rx++;
                if(!session->access_ipv4_rx_first_seq) {
                    session->access_ipv4_rx_first_seq = bbl->flow_seq;
                    interface->ctx->stats.session_traffic_flows_verified++;
                } else {
                    if(session->access_ipv4_rx_last_seq +1 != bbl->flow_seq) {
                        interface->stats.session_ipv4_loss++;
                        session->stats.access_ipv4_loss++;
                        LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                            session->session_id, bbl->flow_id, bbl->flow_seq, session->access_ipv4_rx_last_seq);
                    }
                }
                session->access_ipv4_rx_last_seq = bbl->flow_seq;
            } else {
                bbl_rx_stream(interface, eth, bbl, ipv4->tos);
            }
        } else if(bbl->type == BBL_TYPE_MULTICAST) {
            /* Multicast receive handler */
            for(i=0; i < IGMP_MAX_GROUPS; i++) {
                group = &session->igmp_groups[i];
                if(ipv4->dst == group->group) {
                    if(group->state >= IGMP_GROUP_ACTIVE) {
                        interface->stats.mc_rx++;
                        session->stats.mc_rx++;
                        group->packets++;
                        if(!group->first_mc_rx_time.tv_sec) {
                            group->first_mc_rx_time.tv_sec = eth->timestamp.tv_sec;
                            group->first_mc_rx_time.tv_nsec = eth->timestamp.tv_nsec;
                        } else if(bbl->flow_seq > session->mc_rx_last_seq + 1) {
                            interface->stats.mc_loss++;
                            session->stats.mc_loss++;
                            group->loss++;
                            LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                session->session_id, bbl->flow_id, bbl->flow_seq, session->mc_rx_last_seq);
                        }
                        session->mc_rx_last_seq = bbl->flow_seq;
                    } else {
                        interface->stats.mc_rx++;
                        session->stats.mc_rx++;
                        group->packets++;
                        group->last_mc_rx_time.tv_sec = eth->timestamp.tv_sec;
                        group->last_mc_rx_time.tv_nsec = eth->timestamp.tv_nsec;
                        if(session->zapping_joined_group &&
                            session->zapping_leaved_group == group) {
                            if(session->zapping_joined_group->first_mc_rx_time.tv_sec) {
                                session->stats.mc_old_rx_after_first_new++;
                            }
                        }
                    }
                    break;
                }
            }
        }
    } else {
        /* Multicast receive handler */
        for(i=0; i < IGMP_MAX_GROUPS; i++) {
            group = &session->igmp_groups[i];
            if(ipv4->dst == group->group) {
                if(group->state >= IGMP_GROUP_ACTIVE) {
                    interface->stats.mc_rx++;
                    session->stats.mc_rx++;
                    group->packets++;
                    if(!group->first_mc_rx_time.tv_sec) {
                        group->first_mc_rx_time.tv_sec = eth->timestamp.tv_sec;
                        group->first_mc_rx_time.tv_nsec = eth->timestamp.tv_nsec;
                    }
                } else {
                    interface->stats.mc_rx++;
                    session->stats.mc_rx++;
                    group->packets++;
                    group->last_mc_rx_time.tv_sec = eth->timestamp.tv_sec;
                    group->last_mc_rx_time.tv_nsec = eth->timestamp.tv_nsec;
                    if(session->zapping_joined_group &&
                       session->zapping_leaved_group == group) {
                        if(session->zapping_joined_group->first_mc_rx_time.tv_sec) {
                            session->stats.mc_old_rx_after_first_new++;
                        }
                    }
                }
            }
        }
    }
}

void
bbl_rx_ipv6(bbl_ethernet_header_t *eth, bbl_ipv6_t *ipv6, bbl_interface_s *interface, bbl_session_s *session) {
    switch(ipv6->protocol) {
        case IPV6_NEXT_HEADER_ICMPV6:
            interface->stats.icmpv6_rx++;
            return bbl_rx_icmpv6(ipv6, interface, session);
        case IPV6_NEXT_HEADER_UDP:
            bbl_rx_udp(eth, ipv6, interface, session);
            break;
        default:
            break;
    }
    session->stats.accounting_packets_rx++;
    session->stats.accounting_bytes_rx += eth->length;
}

void
bbl_rx_pap(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;
    bbl_pap_t *pap;
    bbl_ctx_s *ctx = interface->ctx;

    char substring[16];
    char *tok;
    
    l2tp_key_t key = {0};
    void **search = NULL;

    pppoes = (bbl_pppoe_session_t*)eth->next;
    pap = (bbl_pap_t*)pppoes->next;

    if(session->session_state == BBL_PPP_AUTH) {
        switch(pap->code) {
            case PAP_CODE_ACK:
                if(pap->reply_message_len > 23) {
                    if(strncmp(pap->reply_message, L2TP_REPLY_MESSAGE, 20) == 0) {
                        session->l2tp = true;
                        memset(substring, 0x0, sizeof(substring));
                        memcpy(substring, pap->reply_message+21, pap->reply_message_len-21);
                        tok = strtok(substring, ":");
                        if(tok) {
                            key.tunnel_id = atoi(tok);
                            tok = strtok(0, ":");
                            if(tok) {
                                key.session_id = atoi(tok);
                                search = dict_search(ctx->l2tp_session_dict, &key);
                                if(search) {
                                    session->l2tp_session = *search;
                                    session->l2tp_session->pppoe_session = session;
                                    LOG(L2TP, "L2TP (ID: %u) Tunnelled session with BNG Blaster LNS (%d:%d)\n", 
                                        session->session_id, session->l2tp_session->key.tunnel_id, session->l2tp_session->key.session_id);
                                }
                            }
                        }
                    }
                }
                bbl_session_update_state(ctx, session, BBL_PPP_NETWORK);
                if(ctx->config.ipcp_enable) {
                    session->ipcp_state = BBL_PPP_INIT;
                    session->ipcp_request_code = PPP_CODE_CONF_REQUEST;
                    session->send_requests |= BBL_SEND_IPCP_REQUEST;
                }
                if(ctx->config.ip6cp_enable) {
                    session->ip6cp_state = BBL_PPP_INIT;
                    session->ip6cp_request_code = PPP_CODE_CONF_REQUEST;
                    session->send_requests |= BBL_SEND_IP6CP_REQUEST;
                }
                bbl_session_tx_qnode_insert(session);
                break;
            default:
                bbl_session_update_state(ctx, session, BBL_PPP_TERMINATING);
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->lcp_options_len = 0;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
        }
    }
}


void
bbl_rx_chap(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;
    bbl_chap_t *chap;
    bbl_ctx_s *ctx = interface->ctx;

    MD5_CTX md5_ctx;

    char substring[16];
    char *tok;
    
    l2tp_key_t key = {0};
    void **search = NULL;

    pppoes = (bbl_pppoe_session_t*)eth->next;
    chap = (bbl_chap_t*)pppoes->next;

    if(session->session_state == BBL_PPP_AUTH) {
        switch(chap->code) {
            case CHAP_CODE_CHALLENGE:
                if(chap->challenge_len != CHALLENGE_LEN) {
                    bbl_session_update_state(ctx, session, BBL_PPP_TERMINATING);
                    session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                    session->lcp_options_len = 0;
                    session->send_requests |= BBL_SEND_LCP_REQUEST;
                    bbl_session_tx_qnode_insert(session);
                } else {
                    MD5_Init(&md5_ctx);
                    MD5_Update(&md5_ctx, &chap->identifier, 1);
                    MD5_Update(&md5_ctx, session->password, strlen(session->password));
                    MD5_Update(&md5_ctx, chap->challenge, chap->challenge_len);
                    MD5_Final(session->chap_response, &md5_ctx);
                    session->chap_identifier = chap->identifier;
                    session->send_requests |= BBL_SEND_CHAP_RESPONSE;
                    bbl_session_tx_qnode_insert(session);
                }
                break;
            case CHAP_CODE_SUCCESS:
                if(chap->reply_message_len > 23) {
                    if(strncmp(chap->reply_message, L2TP_REPLY_MESSAGE, 20) == 0) {
                        session->l2tp = true;
                        memset(substring, 0x0, sizeof(substring));
                        memcpy(substring, chap->reply_message+21, chap->reply_message_len-21);
                        tok = strtok(substring, ":");
                        if(tok) {
                            key.tunnel_id = atoi(tok);
                            tok = strtok(0, ":");
                            if(tok) {
                                key.session_id = atoi(tok);
                                search = dict_search(ctx->l2tp_session_dict, &key);
                                if(search) {
                                    session->l2tp_session = *search;
                                    session->l2tp_session->pppoe_session = session;
                                    LOG(L2TP, "L2TP (ID: %u) Tunnelled session with BNG Blaster LNS (%d:%d)\n", 
                                        session->session_id, session->l2tp_session->key.tunnel_id, session->l2tp_session->key.session_id);
                                }
                            }
                        }
                    }
                }
                bbl_session_update_state(ctx, session, BBL_PPP_NETWORK);
                if(ctx->config.ipcp_enable) {
                    session->ipcp_state = BBL_PPP_INIT;
                    session->ipcp_request_code = PPP_CODE_CONF_REQUEST;
                    session->send_requests |= BBL_SEND_IPCP_REQUEST;
                }
                if(ctx->config.ip6cp_enable) {
                    session->ip6cp_state = BBL_PPP_INIT;
                    session->ip6cp_request_code = PPP_CODE_CONF_REQUEST;
                    session->send_requests |= BBL_SEND_IP6CP_REQUEST;
                }
                bbl_session_tx_qnode_insert(session);
                break;
            default:
                bbl_session_update_state(ctx, session, BBL_PPP_TERMINATING);
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->lcp_options_len = 0;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
        }
    }
}

void
bbl_session_timeout(timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    session = timer->data;
    interface = session->interface;
    ctx = interface->ctx;

    if(session->session_state == BBL_ESTABLISHED) {
        bbl_session_clear(ctx, session);
    }
}

void
bbl_rx_established(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_ctx_s *ctx = interface->ctx;

    bool ipcp = false;
    bool ip6cp = false;
    uint64_t tx_interval;

    if(ctx->config.ipcp_enable == false || session->ipcp_state == BBL_PPP_OPENED) ipcp = true;
    if(ctx->config.ip6cp_enable == false || session->ip6cp_state == BBL_PPP_OPENED) ip6cp = true;

    if(ipcp && ip6cp) {
        if(session->session_state != BBL_ESTABLISHED) {
            if(ctx->sessions_established_max < ctx->sessions) {
                ctx->stats.last_session_established.tv_sec = eth->timestamp.tv_sec;
                ctx->stats.last_session_established.tv_nsec = eth->timestamp.tv_nsec;
                bbl_session_update_state(ctx, session, BBL_ESTABLISHED);
                if(ctx->sessions_established == ctx->sessions) {
                    LOG(NORMAL, "ALL SESSIONS ESTABLISHED\n");
                }
            } else {
                bbl_session_update_state(ctx, session, BBL_ESTABLISHED);
            }
            if(ctx->config.lcp_keepalive_interval) {
                /* Start LCP echo request / keep alive */
                timer_add_periodic(&ctx->timer_root, &session->timer_lcp_echo, "LCP ECHO", ctx->config.lcp_keepalive_interval, 0, session, bbl_lcp_echo);
            }
            if(session->l2tp == false && ctx->config.igmp_group && ctx->config.igmp_autostart && ctx->config.igmp_start_delay) {
                /* Start IGMP */
                timer_add(&ctx->timer_root, &session->timer_igmp, "IGMP", ctx->config.igmp_start_delay, 0, session, bbl_igmp_initial_join);
            }
            if(ctx->config.pppoe_session_time) {
                /* Start Session Timer */
                timer_add(&ctx->timer_root, &session->timer_session, "Session", ctx->config.pppoe_session_time, 0, session, bbl_session_timeout);
            }
            if(ctx->config.session_traffic_ipv4_pps && session->ip_address &&
               ctx->op.network_if && ctx->op.network_if->ip) {
                /* Start IPv4 Session Traffic */
                if(bbl_add_session_packets_ipv4(ctx, session)) {
                    if(ctx->config.session_traffic_ipv4_pps > 1) {
                        tx_interval = 1000000000 / ctx->config.session_traffic_ipv4_pps;
                        if(tx_interval < ctx->config.tx_interval) {
                            /* It is not possible to send faster than TX interval. */
                            tx_interval = ctx->config.tx_interval;
                        }
                        timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv4, "Session Traffic IPv4",
                                           0, tx_interval, session, bbl_session_traffic_ipv4);
                    } else {
                        timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv4, "Session Traffic IPv4",
                                           1, 0, session, bbl_session_traffic_ipv4);
                    }
                } else {
                    LOG(ERROR, "Traffic (ID: %u) failed to create IPv4 session traffic\n", session->session_id);
                }
            }
        }
    }
}

void
bbl_rx_established_ipoe(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_ctx_s *ctx = interface->ctx;
    uint64_t tx_interval;

    if(session->session_state != BBL_ESTABLISHED) {
        if(ctx->sessions_established_max < ctx->sessions) {
            ctx->stats.last_session_established.tv_sec = eth->timestamp.tv_sec;
            ctx->stats.last_session_established.tv_nsec = eth->timestamp.tv_nsec;
            bbl_session_update_state(ctx, session, BBL_ESTABLISHED);
            if(ctx->sessions_established == ctx->sessions) {
                LOG(NORMAL, "ALL SESSIONS ESTABLISHED\n");
            }
        } else {
            bbl_session_update_state(ctx, session, BBL_ESTABLISHED);
        }
        if(ctx->config.igmp_group && ctx->config.igmp_autostart && ctx->config.igmp_start_delay) {
            /* Start IGMP */
            timer_add(&ctx->timer_root, &session->timer_igmp, "IGMP", ctx->config.igmp_start_delay, 0, session, bbl_igmp_initial_join);
        }
        if(ctx->config.session_traffic_ipv4_pps && session->ip_address &&
            ctx->op.network_if && ctx->op.network_if->ip) {
            /* Start IPv4 Session Traffic */
            if(bbl_add_session_packets_ipv4(ctx, session)) {
                if(ctx->config.session_traffic_ipv4_pps > 1) {
                    tx_interval = 1000000000 / ctx->config.session_traffic_ipv4_pps;
                    if(tx_interval < ctx->config.tx_interval) {
                        /* It is not possible to send faster than TX interval. */
                        tx_interval = ctx->config.tx_interval;
                    }
                    timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv4, "Session Traffic IPv4",
                                       0, tx_interval, session, bbl_session_traffic_ipv4);
                } else {
                    timer_add_periodic(&ctx->timer_root, &session->timer_session_traffic_ipv4, "Session Traffic IPv4",
                                       1, 0, session, bbl_session_traffic_ipv4);
                }
            } else {
                LOG(ERROR, "Traffic (ID: %u) failed to create IPv4 session traffic\n", session->session_id);
            }
        }
    }
}

void
bbl_rx_ip6cp(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;
    bbl_ip6cp_t *ip6cp;
    bbl_ctx_s *ctx;
    ctx = interface->ctx;

    if(session->lcp_state != BBL_PPP_OPENED) {
        return;
    }

    if(!ctx->config.ip6cp_enable) {
        /* Protocol Reject */
        *(uint16_t*)session->lcp_options = htobe16(PROTOCOL_IP6CP);
        session->lcp_options_len = 2;
        session->lcp_peer_identifier = ++session->lcp_identifier;
        session->lcp_response_code = PPP_CODE_PROT_REJECT;
        session->send_requests |= BBL_SEND_LCP_RESPONSE;
        bbl_session_tx_qnode_insert(session);
        return;
    }

    pppoes = (bbl_pppoe_session_t*)eth->next;
    ip6cp = (bbl_ip6cp_t*)pppoes->next;

    switch(ip6cp->code) {
        case PPP_CODE_CONF_REQUEST:
            if(ip6cp->ipv6_identifier) {
                session->ip6cp_ipv6_peer_identifier = ip6cp->ipv6_identifier;
            }
            if(ip6cp->options_len <= PPP_OPTIONS_BUFFER) {
                memcpy(session->ip6cp_options, ip6cp->options, ip6cp->options_len);
                session->ip6cp_options_len = ip6cp->options_len;
            } else {
                ip6cp->options_len = 0;
            }
            switch(session->ip6cp_state) {
                case BBL_PPP_INIT:
                    session->ip6cp_state = BBL_PPP_PEER_ACK;
                    break;
                case BBL_PPP_LOCAL_ACK:
                    session->ip6cp_state = BBL_PPP_OPENED;
                    bbl_rx_established(eth, interface, session);
                    session->link_local_ipv6_address[0] = 0xfe;
                    session->link_local_ipv6_address[0] = 0x80;
                    *(uint64_t*)&session->link_local_ipv6_address[8] = session->ip6cp_ipv6_identifier;
                    session->send_requests |= BBL_SEND_ICMPV6_RS;
                    bbl_session_tx_qnode_insert(session);
                    break;
                default:
                    break;
            }
            session->ip6cp_peer_identifier = ip6cp->identifier;
            session->ip6cp_response_code = PPP_CODE_CONF_ACK;
            session->send_requests |= BBL_SEND_IP6CP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_CONF_NAK:
            session->ip6cp_retries = 0;
            if(ip6cp->ipv6_identifier) {
                session->ip6cp_ipv6_identifier = ip6cp->ipv6_identifier;
            }
            session->send_requests |= BBL_SEND_IP6CP_REQUEST;
            session->ipcp_request_code = PPP_CODE_CONF_REQUEST;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_CONF_ACK:
            session->ip6cp_retries = 0;
            switch(session->ip6cp_state) {
                case BBL_PPP_INIT:
                    session->ip6cp_state = BBL_PPP_LOCAL_ACK;
                    break;
                case BBL_PPP_PEER_ACK:
                    session->ip6cp_state = BBL_PPP_OPENED;
                    bbl_rx_established(eth, interface, session);
                    session->link_local_ipv6_address[0] = 0xfe;
                    session->link_local_ipv6_address[1] = 0x80;
                    *(uint64_t*)&session->link_local_ipv6_address[8] = session->ip6cp_ipv6_identifier;
                    session->send_requests |= BBL_SEND_ICMPV6_RS;
                    bbl_session_tx_qnode_insert(session);
                    break;
                default:
                    break;
            }
            break;
        case PPP_CODE_TERM_REQUEST:
            session->ip6cp_peer_identifier = ip6cp->identifier;
            session->ip6cp_response_code = PPP_CODE_TERM_ACK;
            session->send_requests |= BBL_SEND_IP6CP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_TERM_ACK:
            session->ip6cp_retries = 0;
            session->ip6cp_state = BBL_PPP_CLOSED;
            break;
        default:
            break;
    }
}

void
bbl_rx_ipcp(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;
    bbl_ipcp_t *ipcp;
    bbl_ctx_s *ctx;
    ctx = interface->ctx;

    if(session->lcp_state != BBL_PPP_OPENED) {
        return;
    }

    if(!ctx->config.ipcp_enable) {
        /* Protocol Reject */
        *(uint16_t*)session->lcp_options = htobe16(PROTOCOL_IPCP);
        session->lcp_options_len = 2;
        session->lcp_peer_identifier = ++session->lcp_identifier;
        session->lcp_response_code = PPP_CODE_PROT_REJECT;
        session->send_requests |= BBL_SEND_LCP_RESPONSE;
        bbl_session_tx_qnode_insert(session);
        return;
    }

    pppoes = (bbl_pppoe_session_t*)eth->next;
    ipcp = (bbl_ipcp_t*)pppoes->next;

    switch(ipcp->code) {
        case PPP_CODE_CONF_REQUEST:
            if(ipcp->address) {
                session->peer_ip_address = ipcp->address;
            }
            if(ipcp->options_len <= PPP_OPTIONS_BUFFER) {
                memcpy(session->ipcp_options, ipcp->options, ipcp->options_len);
                session->ipcp_options_len = ipcp->options_len;
            } else {
                ipcp->options_len = 0;
            }
            switch(session->ipcp_state) {
                case BBL_PPP_INIT:
                    session->ipcp_state = BBL_PPP_PEER_ACK;
                    break;
                case BBL_PPP_LOCAL_ACK:
                    session->ipcp_state = BBL_PPP_OPENED;
                    bbl_rx_established(eth, interface, session);
                    LOG(IP, "IPv4 (ID: %u) address %s\n",
                        session->session_id, format_ipv4_address(&session->ip_address));
                    break;
                default:
                    break;
            }
            session->ipcp_peer_identifier = ipcp->identifier;
            session->ipcp_response_code = PPP_CODE_CONF_ACK;
            session->send_requests |= BBL_SEND_IPCP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_CONF_NAK:
            session->ipcp_retries = 0;
            if(ipcp->address) {
                session->ip_address = ipcp->address;
            }
            if(ipcp->dns1) {
                session->dns1 = ipcp->dns1;
            }
            if(ipcp->dns2) {
                session->dns2 = ipcp->dns2;
            }
            session->send_requests |= BBL_SEND_IPCP_REQUEST;
            session->ipcp_request_code = PPP_CODE_CONF_REQUEST;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_CONF_ACK:
            session->ipcp_retries = 0;
            switch(session->ipcp_state) {
                case BBL_PPP_INIT:
                    session->ipcp_state = BBL_PPP_LOCAL_ACK;
                    break;
                case BBL_PPP_PEER_ACK:
                    session->ipcp_state = BBL_PPP_OPENED;
                    bbl_rx_established(eth, interface, session);
                    LOG(IP, "IPv4 (ID: %u) address %s\n",
                        session->session_id, format_ipv4_address(&session->ip_address));
                    break;
                default:
                    break;
            }
            break;
        case PPP_CODE_TERM_REQUEST:
            session->ipcp_peer_identifier = ipcp->identifier;
            session->ipcp_response_code = PPP_CODE_TERM_ACK;
            session->send_requests |= BBL_SEND_IPCP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_TERM_ACK:
            session->ipcp_retries = 0;
            session->ipcp_state = BBL_PPP_CLOSED;
            break;
        default:
            break;
    }
}

void
bbl_rx_lcp(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;
    bbl_lcp_t *lcp;
    bbl_ctx_s *ctx = interface->ctx;

    pppoes = (bbl_pppoe_session_t*)eth->next;
    lcp = (bbl_lcp_t*)pppoes->next;

    switch(lcp->code) {
        case PPP_CODE_CONF_REQUEST:
            session->auth_protocol = lcp->auth;
            if(session->access_config->authentication_protocol) {
                if(session->access_config->authentication_protocol != lcp->auth) {
                    lcp->auth = session->access_config->authentication_protocol;
                    session->auth_protocol = 0;
                }
            } else {
                lcp->auth = PROTOCOL_PAP;
            }
            if(!(session->auth_protocol == PROTOCOL_CHAP || session->auth_protocol == PROTOCOL_PAP)) {
                /* Reject authentication protocol */
                if(lcp->auth == PROTOCOL_CHAP) {
                    session->lcp_options[0] = 3;
                    session->lcp_options[1] = 5;
                    *(uint16_t*)&session->lcp_options[2] = htobe16(PROTOCOL_CHAP);
                    session->lcp_options[4] = 5;
                    session->lcp_options_len = 5;
                } else {
                    session->lcp_options[0] = 3;
                    session->lcp_options[1] = 4;
                    *(uint16_t*)&session->lcp_options[2] = htobe16(PROTOCOL_PAP);
                    session->lcp_options_len = 4;
                }
                session->lcp_peer_identifier = lcp->identifier;
                session->lcp_response_code = PPP_CODE_CONF_NAK;
                session->send_requests |= BBL_SEND_LCP_RESPONSE;
                bbl_session_tx_qnode_insert(session);
                return;
            }
            if(lcp->mru) {
                session->mru = lcp->mru;
            }
            if(lcp->magic) {
                session->peer_magic_number = lcp->magic;
            }
            if(lcp->options_len <= PPP_OPTIONS_BUFFER) {
                memcpy(session->lcp_options, lcp->options, lcp->options_len);
                session->lcp_options_len = lcp->options_len;
            } else {
                lcp->options_len = 0;
            }
            switch(session->lcp_state) {
                case BBL_PPP_INIT:
                    session->lcp_state = BBL_PPP_PEER_ACK;
                    break;
                case BBL_PPP_LOCAL_ACK:
                    session->lcp_state = BBL_PPP_OPENED;
                    bbl_session_update_state(ctx, session, BBL_PPP_AUTH);
                    if(session->auth_protocol == PROTOCOL_PAP) {
                        session->send_requests |= BBL_SEND_PAP_REQUEST;
                        bbl_session_tx_qnode_insert(session);
                    }
                    break;
                default:
                    break;
            }
            session->lcp_peer_identifier = lcp->identifier;
            session->lcp_response_code = PPP_CODE_CONF_ACK;
            session->send_requests |= BBL_SEND_LCP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_CONF_ACK:
            session->lcp_retries = 0;
            switch(session->lcp_state) {
                case BBL_PPP_INIT:
                    session->lcp_state = BBL_PPP_LOCAL_ACK;
                    break;
                case BBL_PPP_PEER_ACK:
                    session->lcp_state = BBL_PPP_OPENED;
                    bbl_session_update_state(ctx, session, BBL_PPP_AUTH);
                    if(session->auth_protocol == PROTOCOL_PAP) {
                        session->send_requests |= BBL_SEND_PAP_REQUEST;
                        bbl_session_tx_qnode_insert(session);
                    }
                    break;
                default:
                    break;
            }
            break;
        case PPP_CODE_CONF_NAK:
            session->lcp_retries = 0;
            if(lcp->mru) {
                session->mru = lcp->mru;
            }
            if(lcp->magic) {
                session->magic_number = lcp->magic;
            }
            session->send_requests |= BBL_SEND_LCP_REQUEST;
            session->lcp_request_code = PPP_CODE_CONF_REQUEST;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_ECHO_REQUEST:
            session->lcp_peer_identifier = lcp->identifier;
            session->lcp_response_code = PPP_CODE_ECHO_REPLY;
            session->lcp_options_len = 0;
            session->send_requests |= BBL_SEND_LCP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_ECHO_REPLY:
            session->lcp_retries = 0;
            break;
        case PPP_CODE_TERM_REQUEST:
            if(session->session_state != BBL_PPP_TERMINATING) {
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
            }
            bbl_session_update_state(ctx, session, BBL_PPP_TERMINATING);
            session->lcp_peer_identifier = lcp->identifier;
            session->lcp_response_code = PPP_CODE_TERM_ACK;
            session->lcp_options_len = 0;
            session->send_requests = BBL_SEND_LCP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_TERM_ACK:
            bbl_session_update_state(ctx, session, BBL_TERMINATING);
            session->lcp_retries = 0;
            session->send_requests = BBL_SEND_DISCOVERY;
            bbl_session_tx_qnode_insert(session);
            break;
        default:
            break;
    }
}

void
bbl_rx_session(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;

    pppoes = (bbl_pppoe_session_t*)eth->next;
    switch(pppoes->protocol) {
        case PROTOCOL_LCP:
            bbl_rx_lcp(eth, interface, session);
            interface->stats.lcp_rx++;
            break;
        case PROTOCOL_IPCP:
            bbl_rx_ipcp(eth, interface, session);
            interface->stats.ipcp_rx++;
            break;
        case PROTOCOL_IP6CP:
            bbl_rx_ip6cp(eth, interface, session);
            interface->stats.ip6cp_rx++;
            break;
        case PROTOCOL_PAP:
            bbl_rx_pap(eth, interface, session);
            interface->stats.pap_rx++;
            break;
        case PROTOCOL_CHAP:
            bbl_rx_chap(eth, interface, session);
            interface->stats.chap_rx++;
            break;
        case PROTOCOL_IPV4:
            bbl_rx_ipv4(eth, (bbl_ipv4_t*)pppoes->next, interface, session);
            break;
        case PROTOCOL_IPV6:
            bbl_rx_ipv6(eth, (bbl_ipv6_t*)pppoes->next, interface, session);
            break;
        default:
            interface->stats.packets_rx_drop_unknown++;
            break;
    }
}

void
bbl_rx_discovery(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_discovery_t *pppoed;
    bbl_ctx_s *ctx = interface->ctx;

    pppoed = (bbl_pppoe_discovery_t*)eth->next;
    switch(pppoed->code) {
        case PPPOE_PADO:
            interface->stats.pado_rx++;
            if(session->session_state == BBL_PPPOE_INIT) {
                /* Store server MAC address */
                memcpy(session->server_mac, eth->src, ETH_ADDR_LEN);
                if(pppoed->ac_cookie_len) {
                    /* Store AC cookie */
                    if(session->pppoe_ac_cookie) free(session->pppoe_ac_cookie);
                    session->pppoe_ac_cookie = malloc(pppoed->ac_cookie_len);
                    session->pppoe_ac_cookie_len = pppoed->ac_cookie_len;
                    memcpy(session->pppoe_ac_cookie, pppoed->ac_cookie, pppoed->ac_cookie_len);
                }
                if(pppoed->service_name_len) {
                    if(session->pppoe_service_name_len) {
                        /* Compare service name */
                        if(pppoed->service_name_len != session->pppoe_service_name_len || 
                           memcmp(pppoed->service_name, session->pppoe_service_name, session->pppoe_service_name_len) != 0) {
                            LOG(PPPOE, "PPPoE Error (ID: %u) Wrong service name in PADO\n", session->session_id);
                            return;
                        }
                    } else {
                        /* Store service name */
                        session->pppoe_service_name = malloc(pppoed->service_name_len);
                        session->pppoe_service_name_len = pppoed->service_name_len;
                        memcpy(session->pppoe_service_name, pppoed->service_name, pppoed->service_name_len);
                    }
                } else {
                    LOG(PPPOE, "PPPoE Error (ID: %u) Missing service name in PADO\n", session->session_id);
                    return;
                }
                if(session->pppoe_host_uniq) {
                    if(pppoed->host_uniq_len != sizeof(uint64_t) || 
                       *(uint64_t*)pppoed->host_uniq != session->pppoe_host_uniq) {
                        LOG(PPPOE, "PPPoE Error (ID: %u) Wrong host-uniq in PADO\n", session->session_id);
                        return;
                    }
                }
                bbl_session_update_state(ctx, session, BBL_PPPOE_REQUEST);
                session->send_requests = BBL_SEND_DISCOVERY;
                bbl_session_tx_qnode_insert(session);
            }
            break;
        case PPPOE_PADS:
            interface->stats.pads_rx++;
            if(session->session_state == BBL_PPPOE_REQUEST) {
                if(pppoed->session_id) {
                    if(session->pppoe_host_uniq) {
                        if(pppoed->host_uniq_len != sizeof(uint64_t) || 
                           *(uint64_t*)pppoed->host_uniq != session->pppoe_host_uniq) {
                            LOG(PPPOE, "PPPoE Error (ID: %u) Wrong host-uniq in PADS\n", session->session_id);
                            return;
                        }
                    }
                    if(pppoed->service_name_len != session->pppoe_service_name_len || 
                        memcmp(pppoed->service_name, session->pppoe_service_name, session->pppoe_service_name_len) != 0) {
                        LOG(PPPOE, "PPPoE Error (ID: %u) Wrong service name in PADS\n", session->session_id);
                        return;
                    }
                    session->pppoe_session_id = pppoed->session_id;
                    bbl_session_update_state(ctx, session, BBL_PPP_LINK);
                    session->send_requests = BBL_SEND_LCP_REQUEST;
                    session->lcp_request_code = PPP_CODE_CONF_REQUEST;
                    session->lcp_state = BBL_PPP_INIT;
                    bbl_session_tx_qnode_insert(session);
                } else {
                    LOG(PPPOE, "PPPoE Error (ID: %u) Invalid PADS\n", session->session_id);
                    return;
                }
            }
            break;
        case PPPOE_PADT:
            interface->stats.padt_rx++;
            bbl_session_update_state(ctx, session, BBL_TERMINATED);
            session->send_requests = 0;
            break;
        default:
            interface->stats.packets_rx_drop_unknown++;
            break;
    }
}

void
bbl_rx_arp(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_arp_t *arp = (bbl_arp_t*)eth->next;
    if(arp->sender_ip == session->peer_ip_address) {
        if(!session->arp_resolved) {
            memcpy(session->server_mac, arp->sender, ETH_ADDR_LEN);
        }
        if(arp->code == ARP_REQUEST) {
            session->send_requests |= BBL_SEND_ARP_REPLY;
            bbl_session_tx_qnode_insert(session);
        } else {
            if(!session->arp_resolved) {
                bbl_rx_established_ipoe(eth, interface, session);
                session->arp_resolved = true;
            }
        }
    }
}

/** 
 * bbl_rx_handler_access 
 *
 * This function handles all packets received on access interfaces.
 * 
 * @param eth pointer to ethernet header structure of received packet
 * @param interface pointer to interface on which packet was received
 */
void
bbl_rx_handler_access(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_ctx_s *ctx;
    bbl_session_s *session;
    uint32_t session_id = 0;

    ctx = interface->ctx;

    /* The session-id is mapped into the last 3 bytes of 
     * the client MAC address. The original approach using
     * VLAN identifiers was not working as some NIC drivers
     * strip outer VLAN and it is also possible to have 
     * multiple session per VLAN (N:1). */
    session_id |= eth->dst[5];
    session_id |= eth->dst[4] << 8;
    session_id |= eth->dst[3] << 16;

    session = bbl_session_get(ctx, session_id);
    if(session) {
        if(session->session_state != BBL_TERMINATED &&
           session->session_state != BBL_IDLE) {
            session->stats.packets_rx++;
            session->stats.bytes_rx += eth->length;
            switch (session->access_type) {
                case ACCESS_TYPE_PPPOE:
                    switch(eth->type) {
                        case ETH_TYPE_PPPOE_DISCOVERY:
                            bbl_rx_discovery(eth, interface, session);
                            break;
                        case ETH_TYPE_PPPOE_SESSION:
                            bbl_rx_session(eth, interface, session);
                            break;
                        default:
                            interface->stats.packets_rx_drop_unknown++;
                            break;
                    }
                    break;
                case ACCESS_TYPE_IPOE:
                    switch(eth->type) {
                        case ETH_TYPE_ARP:
                            interface->stats.arp_rx++;
                            bbl_rx_arp(eth, interface, session);
                            break;
                        case ETH_TYPE_IPV4:
                            bbl_rx_ipv4(eth, (bbl_ipv4_t*)eth->next, interface, session);
                            break;
                        case ETH_TYPE_IPV6:
                            bbl_rx_ipv6(eth, (bbl_ipv6_t*)eth->next, interface, session);
                            break;
                        default:
                            interface->stats.packets_rx_drop_unknown++;
                            break;
                    }
                    break;
                default:
                    interface->stats.packets_rx_drop_unknown++;
                    break;
            }
        }
    }
}

void
bbl_rx_network_arp(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_secondary_ip_s *secondary_ip;

    bbl_arp_t *arp = (bbl_arp_t*)eth->next;
    if(arp->sender_ip == interface->gateway) {
        interface->arp_resolved = true;
        if(*(uint32_t*)interface->gateway_mac == 0) {
            memcpy(interface->gateway_mac, arp->sender, ETH_ADDR_LEN);
        }
        if(arp->code == ARP_REQUEST) {
            if(arp->target_ip == interface->ip) {
                interface->arp_reply_ip = interface->ip;
                interface->send_requests |= BBL_IF_SEND_ARP_REPLY;
            } else {
                secondary_ip = interface->ctx->config.secondary_ip_addresses;
                while(secondary_ip) {
                    if(arp->target_ip == secondary_ip->ip) {
                        secondary_ip->arp_reply = true;
                        interface->send_requests |= BBL_IF_SEND_SEC_ARP_REPLY;
                        return;
                    }
                    secondary_ip = secondary_ip->next;
                }
            }
        }
    }
}

void
bbl_rx_network_icmpv6(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_ipv6_t *ipv6;
    bbl_icmpv6_t *icmpv6;
    bbl_secondary_ip6_s *secondary_ip6;

    ipv6 = (bbl_ipv6_t*)eth->next;
    icmpv6 = (bbl_icmpv6_t*)ipv6->next;

    if(memcmp(ipv6->src, interface->gateway6.address, IPV6_ADDR_LEN) == 0) {
        interface->icmpv6_nd_resolved = true;
        if(*(uint32_t*)interface->gateway_mac == 0) {
            memcpy(interface->gateway_mac, eth->src, ETH_ADDR_LEN);
        }
    }
    if(icmpv6->type == IPV6_ICMPV6_NEIGHBOR_SOLICITATION) {
        if(memcmp(icmpv6->prefix.address, interface->ip6.address, IPV6_ADDR_LEN) == 0) {
            memcpy(interface->icmpv6_src, ipv6->src, IPV6_ADDR_LEN);
            interface->send_requests |= BBL_IF_SEND_ICMPV6_NA;
        } else {
            secondary_ip6 = interface->ctx->config.secondary_ip6_addresses;
            while(secondary_ip6) {
                if(memcmp(icmpv6->prefix.address, secondary_ip6->ip, IPV6_ADDR_LEN) == 0) {
                    secondary_ip6->icmpv6_na = true;
                    memcpy(secondary_ip6->icmpv6_src, ipv6->src, IPV6_ADDR_LEN);
                    interface->send_requests |= BBL_IF_SEND_SEC_ICMPV6_NA;
                    return;
                }
                secondary_ip6 = secondary_ip6->next;
            }
        }
    }
}

/** 
 * bbl_rx_handler_network 
 *
 * This function handles all packets received on network interfaces.
 * 
 * @param eth pointer to ethernet header structure of received packet
 * @param interface pointer to interface on which packet was received
 */
void
bbl_rx_handler_network(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {

    bbl_ctx_s *ctx;

    bbl_ipv4_t *ipv4 = NULL;
    bbl_ipv6_t *ipv6 = NULL;
    bbl_udp_t *udp = NULL;
    bbl_bbl_t *bbl = NULL;
    bbl_session_s *session;

    ctx = interface->ctx;

    switch(eth->type) {
        case ETH_TYPE_ARP:
            return bbl_rx_network_arp(eth, interface);
        case ETH_TYPE_IPV4:
            if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
                /* Drop wrong MAC */
                return;   
            }
            ipv4 = (bbl_ipv4_t*)eth->next;
            if(ipv4->protocol == PROTOCOL_IPV4_UDP) {
                udp = (bbl_udp_t*)ipv4->next;
                if(udp->protocol == UDP_PROTOCOL_BBL) {
                    bbl = (bbl_bbl_t*)udp->next;
                } else if(udp->protocol == UDP_PROTOCOL_QMX_LI) {
                    return bbl_qmx_li_handler_rx(eth, (bbl_qmx_li_t*)udp->next, interface);
                } else if(udp->protocol == UDP_PROTOCOL_L2TP) {
                    return bbl_l2tp_handler_rx(eth, (bbl_l2tp_t*)udp->next, interface);
                }
            }
            break;
        case ETH_TYPE_IPV6:
            ipv6 = (bbl_ipv6_t*)eth->next;
            if(ipv6->protocol == IPV6_NEXT_HEADER_UDP) {
                if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
                    /* Drop wrong MAC */
                    return;
                }
                udp = (bbl_udp_t*)ipv6->next;
                if(udp->protocol == UDP_PROTOCOL_BBL) {
                    bbl = (bbl_bbl_t*)udp->next;
                }
            } else if(ipv6->protocol == IPV6_NEXT_HEADER_ICMPV6) {
                return bbl_rx_network_icmpv6(eth, interface);
            }
            break;
        default:
            break;
    }

    if(bbl) {
        if(bbl->type == BBL_TYPE_UNICAST_SESSION) {
            session = bbl_session_get(ctx, bbl->session_id);
            if(session) {
                switch (bbl->sub_type) {
                    case BBL_SUB_TYPE_IPV4:
                        if(session->access_ipv4_tx_flow_id == bbl->flow_id) {
                            interface->stats.session_ipv4_rx++;
                            session->stats.network_ipv4_rx++;
                            if(!session->network_ipv4_rx_first_seq) {
                                session->network_ipv4_rx_first_seq = bbl->flow_seq;
                                interface->ctx->stats.session_traffic_flows_verified++;
                            } else {
                                if(session->network_ipv4_rx_last_seq +1 != bbl->flow_seq) {
                                    interface->stats.session_ipv4_loss++;
                                    session->stats.network_ipv4_loss++;
                                    LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                        session->session_id, bbl->flow_id, bbl->flow_seq, session->network_ipv4_rx_last_seq);
                                }
                            }
                            session->network_ipv4_rx_last_seq = bbl->flow_seq;
                        } else {
                            if(ipv4) bbl_rx_stream(interface, eth, bbl, ipv4->tos);
                        }
                        break;
                    case BBL_SUB_TYPE_IPV6:
                        if(session->access_ipv6_tx_flow_id == bbl->flow_id) {
                            interface->stats.session_ipv6_rx++;
                            session->stats.network_ipv6_rx++;
                            if(!session->network_ipv6_rx_first_seq) {
                                session->network_ipv6_rx_first_seq = bbl->flow_seq;
                                interface->ctx->stats.session_traffic_flows_verified++;
                            } else {
                                if(session->network_ipv6_rx_last_seq +1 != bbl->flow_seq) {
                                    interface->stats.session_ipv6_loss++;
                                    session->stats.network_ipv6_loss++;
                                    LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                        session->session_id, bbl->flow_id, bbl->flow_seq, session->network_ipv6_rx_last_seq);
                                }
                            }
                            session->network_ipv6_rx_last_seq = bbl->flow_seq;
                        } else {
                            if(ipv6) bbl_rx_stream(interface, eth, bbl, ipv6->tos);
                        }
                        break;
                    case BBL_SUB_TYPE_IPV6PD:
                        if(session->access_ipv6pd_tx_flow_id == bbl->flow_id) {
                            interface->stats.session_ipv6pd_rx++;
                            session->stats.network_ipv6pd_rx++;
                            if(!session->network_ipv6pd_rx_first_seq) {
                                session->network_ipv6pd_rx_first_seq = bbl->flow_seq;
                                interface->ctx->stats.session_traffic_flows_verified++;
                            } else {
                                if(session->network_ipv6pd_rx_last_seq +1 != bbl->flow_seq) {
                                    interface->stats.session_ipv6pd_loss++;
                                    session->stats.network_ipv6pd_loss++;
                                    LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                        session->session_id, bbl->flow_id, bbl->flow_seq, session->network_ipv6pd_rx_last_seq);
                                }
                            }
                            session->network_ipv6pd_rx_last_seq = bbl->flow_seq;
                        } else {
                            if(ipv6) bbl_rx_stream(interface, eth, bbl, ipv6->tos);
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    } else {
        interface->stats.packets_rx_drop_unknown++;
    }
}
