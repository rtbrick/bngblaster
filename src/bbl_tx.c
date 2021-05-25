/*
 * BNG Blaster (BBL) - TX Job
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_session.h"

protocol_error_t
bbl_encode_packet_session_ipv4 (bbl_session_s *session)
{
    bbl_interface_s *interface;
    interface = session->interface;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ipcp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return WRONG_PROTOCOL_STATE;
        }
    }

    session->stats.access_ipv4_tx++;
    interface->stats.session_ipv4_tx++;

    memcpy(session->write_buf, session->access_ipv4_tx_packet_template, session->access_ipv4_tx_packet_len);
    session->write_idx = session->access_ipv4_tx_packet_len;

    *(uint64_t*)(session->write_buf + (session->access_ipv4_tx_packet_len - 16)) = session->access_ipv4_tx_seq++;
    *(uint32_t*)(session->write_buf + (session->access_ipv4_tx_packet_len - 8)) = interface->tx_timestamp.tv_sec;
    *(uint32_t*)(session->write_buf + (session->access_ipv4_tx_packet_len - 4)) = interface->tx_timestamp.tv_nsec;
    return PROTOCOL_SUCCESS;
}

protocol_error_t
bbl_encode_packet_session_ipv6 (bbl_session_s *session)
{
    bbl_interface_s *interface;
    interface = session->interface;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ip6cp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return WRONG_PROTOCOL_STATE;
        }
    }
     
    session->stats.access_ipv6_tx++;
    interface->stats.session_ipv6_tx++;

    memcpy(session->write_buf, session->access_ipv6_tx_packet_template, session->access_ipv6_tx_packet_len);
    session->write_idx = session->access_ipv6_tx_packet_len;

    *(uint64_t*)(session->write_buf + (session->access_ipv6_tx_packet_len - 16)) = session->access_ipv6_tx_seq++;
    *(uint32_t*)(session->write_buf + (session->access_ipv6_tx_packet_len - 8)) = interface->tx_timestamp.tv_sec;
    *(uint32_t*)(session->write_buf + (session->access_ipv6_tx_packet_len - 4)) = interface->tx_timestamp.tv_nsec;
    return PROTOCOL_SUCCESS;
}

protocol_error_t
bbl_encode_packet_session_ipv6pd (bbl_session_s *session)
{
    bbl_interface_s *interface;
    interface = session->interface;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ip6cp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return WRONG_PROTOCOL_STATE;
        }
    }

    session->stats.access_ipv6pd_tx++;
    interface->stats.session_ipv6pd_tx++;

    memcpy(session->write_buf, session->access_ipv6pd_tx_packet_template, session->access_ipv6pd_tx_packet_len);
    session->write_idx = session->access_ipv6pd_tx_packet_len;

    *(uint64_t*)(session->write_buf + (session->access_ipv6pd_tx_packet_len - 16)) = session->access_ipv6pd_tx_seq++;
    *(uint32_t*)(session->write_buf + (session->access_ipv6pd_tx_packet_len - 8)) = interface->tx_timestamp.tv_sec;
    *(uint32_t*)(session->write_buf + (session->access_ipv6pd_tx_packet_len - 4)) = interface->tx_timestamp.tv_nsec;
    return PROTOCOL_SUCCESS;
}

protocol_error_t
bbl_encode_packet_network_session_ipv4 (bbl_interface_s *interface, bbl_session_s *session)
{
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ipcp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return WRONG_PROTOCOL_STATE;
        }
    }

    session->stats.network_ipv4_tx++;
    interface->stats.session_ipv4_tx++;
    if(session->l2tp_session) {
        interface->stats.l2tp_data_tx++;
        session->l2tp_session->tunnel->stats.data_tx++;
        session->l2tp_session->stats.data_tx++;
        session->l2tp_session->stats.data_ipv4_tx++;
    }

    memcpy(session->write_buf, session->network_ipv4_tx_packet_template, session->network_ipv4_tx_packet_len);
    session->write_idx = session->network_ipv4_tx_packet_len;

    *(uint64_t*)(session->write_buf + (session->network_ipv4_tx_packet_len - 16)) = session->network_ipv4_tx_seq++;
    *(uint32_t*)(session->write_buf + (session->network_ipv4_tx_packet_len - 8)) = interface->tx_timestamp.tv_sec;
    *(uint32_t*)(session->write_buf + (session->network_ipv4_tx_packet_len - 4)) = interface->tx_timestamp.tv_nsec;
    return PROTOCOL_SUCCESS;
}

protocol_error_t
bbl_encode_packet_network_session_ipv6 (bbl_interface_s *interface, bbl_session_s *session)
{
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ip6cp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return WRONG_PROTOCOL_STATE;
        }
    }

    session->stats.network_ipv6_tx++;
    interface->stats.session_ipv6_tx++;

    memcpy(session->write_buf, session->network_ipv6_tx_packet_template, session->network_ipv6_tx_packet_len);
    session->write_idx = session->network_ipv6_tx_packet_len;

    *(uint64_t*)(session->write_buf + (session->network_ipv6_tx_packet_len - 16)) = session->network_ipv6_tx_seq++;
    *(uint32_t*)(session->write_buf + (session->network_ipv6_tx_packet_len - 8)) = interface->tx_timestamp.tv_sec;
    *(uint32_t*)(session->write_buf + (session->network_ipv6_tx_packet_len - 4)) = interface->tx_timestamp.tv_nsec;
    return PROTOCOL_SUCCESS;
}

protocol_error_t
bbl_encode_packet_network_session_ipv6pd (bbl_interface_s *interface, bbl_session_s *session)
{
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
            session->ip6cp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
            return WRONG_PROTOCOL_STATE;
        }
    }
    
    session->stats.network_ipv6pd_tx++;
    interface->stats.session_ipv6pd_tx++;

    memcpy(session->write_buf, session->network_ipv6pd_tx_packet_template, session->network_ipv6pd_tx_packet_len);
    session->write_idx = session->network_ipv6pd_tx_packet_len;

    *(uint64_t*)(session->write_buf + (session->network_ipv6pd_tx_packet_len - 16)) = session->network_ipv6pd_tx_seq++;
    *(uint32_t*)(session->write_buf + (session->network_ipv6pd_tx_packet_len - 8)) = interface->tx_timestamp.tv_sec;
    *(uint32_t*)(session->write_buf + (session->network_ipv6pd_tx_packet_len - 4)) = interface->tx_timestamp.tv_nsec;
    return PROTOCOL_SUCCESS;
}

void
bbl_igmp_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    bbl_igmp_group_s *group = NULL;
    int i;
    bool send = false;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->session_state != BBL_ESTABLISHED ||
        session->ipcp_state != BBL_PPP_OPENED) {
            return;
        }
    }

    for(i=0; i < IGMP_MAX_GROUPS; i++) {
        group = &session->igmp_groups[i];
        if(group->state == IGMP_GROUP_JOINING) {
            if(group->robustness_count) {
                session->send_requests |= BBL_SEND_IGMP;
                group->send = true;
                send = true;
            } else {
                group->state = IGMP_GROUP_ACTIVE;
            }
        } else if(group->state == IGMP_GROUP_LEAVING) {
            if(group->robustness_count) {
                session->send_requests |= BBL_SEND_IGMP;
                group->send = true;
                send = true;
            } else {
                group->state = IGMP_GROUP_IDLE;
            }
        }
    }
    if(send) {
        session->send_requests |= BBL_SEND_IGMP;
        bbl_session_tx_qnode_insert(session);
    }
    return;
}

protocol_error_t
bbl_encode_packet_igmp (bbl_session_s *session)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_igmp_t igmp = {0};

    bbl_igmp_group_record_t *gr;
    int i, i2;

    bool is_join = false;
    bool is_leave = false;

    bbl_igmp_group_s *group = NULL;

    interface = session->interface;
    ctx = interface->ctx;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        /* Check session and IPCP (PPP IPv4) state to prevent sending IGMP request
        * after session or IPCP has closed. */
        if(session->session_state != BBL_ESTABLISHED || session->ipcp_state != BBL_PPP_OPENED) {
            session->send_requests &= ~BBL_SEND_IGMP;
            return WRONG_PROTOCOL_STATE;
        }
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV4;
        pppoe.next = &ipv4;
    } else {
        /* IPoE */
        eth.type = ETH_TYPE_IPV4;
        eth.next = &ipv4;
    }
    ipv4.dst = IPV4_MC_IGMP;
    ipv4.src = session->ip_address;
    ipv4.ttl = 1;
    ipv4.protocol = PROTOCOL_IPV4_IGMP;
    ipv4.router_alert_option = true;
    ipv4.next = &igmp;
    for(i=0; i < IGMP_MAX_GROUPS; i++) {
        if(session->igmp_groups[i].send && session->igmp_groups[i].state) {
            group = &session->igmp_groups[i];
            if(group->state == IGMP_GROUP_LEAVING) {
                if(is_join) {
                    if(!ctx->config.igmp_combined_leave_join) {
                        continue;
                    }
                } else {
                    is_leave = true;
                }
            } else {
                /* Joining ... */
                if(is_leave) {
                    if(!ctx->config.igmp_combined_leave_join) {
                        continue;
                    }
                } else {
                    is_join = true;
                }
            }
            group->send = false;
            if(group->robustness_count) {
                group->robustness_count--;
            }
            if(session->igmp_version == IGMP_VERSION_3) {
                igmp.version = IGMP_VERSION_3;
                igmp.type = IGMP_TYPE_REPORT_V3;
                gr = &igmp.group_record[igmp.group_records++];
                gr->group = group->group;
                /* Copy sources ... */
                for(i2=0; i2 < IGMP_MAX_SOURCES; i2++) {
                    if(group->source[i2]) {
                        gr->source[gr->sources++] = group->source[i2];
                    }
                }
                if(gr->sources) {
                    /* SSM */
                    if(group->state == IGMP_GROUP_LEAVING) {
                        gr->type = IGMP_BLOCK_OLD_SOURCES;
                        if(!group->leave_tx_time.tv_sec) {
                            group->leave_tx_time.tv_sec = interface->tx_timestamp.tv_sec;
                            group->leave_tx_time.tv_nsec = interface->tx_timestamp.tv_nsec;
                        }
                    } else {
                        if(group->state == IGMP_GROUP_ACTIVE) {
                            gr->type = IGMP_INCLUDE;
                        } else {
                            gr->type = IGMP_ALLOW_NEW_SOURCES;
                        }
                        if(!group->join_tx_time.tv_sec) {
                            group->join_tx_time.tv_sec = interface->tx_timestamp.tv_sec;
                            group->join_tx_time.tv_nsec = interface->tx_timestamp.tv_nsec;
                        }
                    }
                } else {
                    /* ASM */
                    if(group->state == IGMP_GROUP_LEAVING) {
                        gr->type = IGMP_CHANGE_TO_INCLUDE;
                        if(!group->leave_tx_time.tv_sec) {
                            group->leave_tx_time.tv_sec = interface->tx_timestamp.tv_sec;
                            group->leave_tx_time.tv_nsec = interface->tx_timestamp.tv_nsec;
                        }
                    } else {
                        gr->type = IGMP_EXCLUDE;
                        if(!group->join_tx_time.tv_sec) {
                            group->join_tx_time.tv_sec = interface->tx_timestamp.tv_sec;
                            group->join_tx_time.tv_nsec = interface->tx_timestamp.tv_nsec;
                        }
                    }
                }
            } else {
                ipv4.dst = group->group;
                igmp.group = group->group;
                if(session->igmp_version == IGMP_VERSION_2) {
                    igmp.version = IGMP_VERSION_2;
                    if(group->state == IGMP_GROUP_LEAVING) {
                        igmp.type = IGMP_TYPE_LEAVE;
                        if(!group->leave_tx_time.tv_sec) {
                            group->leave_tx_time.tv_sec = interface->tx_timestamp.tv_sec;
                            group->leave_tx_time.tv_nsec = interface->tx_timestamp.tv_nsec;
                        }
                    } else {
                        igmp.type = IGMP_TYPE_REPORT_V2;
                        if(!group->join_tx_time.tv_sec) {
                            group->join_tx_time.tv_sec = interface->tx_timestamp.tv_sec;
                            group->join_tx_time.tv_nsec = interface->tx_timestamp.tv_nsec;
                        }
                    }
                } else {
                    igmp.version = IGMP_VERSION_1;
                    if(group->state == IGMP_GROUP_LEAVING) {
                        group->state = IGMP_GROUP_IDLE;
                        return WRONG_PROTOCOL_STATE;
                    } else {
                        igmp.type = IGMP_TYPE_REPORT_V1;
                        if(!group->join_tx_time.tv_sec) {
                            group->join_tx_time.tv_sec = interface->tx_timestamp.tv_sec;
                            group->join_tx_time.tv_nsec = interface->tx_timestamp.tv_nsec;
                        }
                    }
                }
                break;
            }
            if(group->state == IGMP_GROUP_JOINING) {
                if(!group->robustness_count) {
                    group->state = IGMP_GROUP_ACTIVE;
                }
            } else if(group->state == IGMP_GROUP_LEAVING) {
                if(!group->robustness_count) {
                    group->state = IGMP_GROUP_IDLE;
                }
            }
        }
    }
    if(!group) {
        /* Nothing to do... */
        session->send_requests &= ~BBL_SEND_IGMP;
        return IGNORED;
    }
    timer_add(&ctx->timer_root, &session->timer_igmp, "IGMP", 1, 0, session, &bbl_igmp_timeout);
    session->stats.igmp_tx++;
    interface->stats.igmp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_packet_icmp_reply (bbl_session_s *session)
{
    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_icmp_t icmp = {0};

    if(session->icmp_reply_destination) {
        session->stats.icmp_tx++;
        session->interface->stats.icmp_tx++;
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
            pppoe.next = &ipv4;
        } else {
            /* IPoE */
            eth.type = ETH_TYPE_IPV4;
            eth.next = &ipv4;
        }
        ipv4.dst = session->icmp_reply_destination;
        ipv4.src = session->ip_address;
        ipv4.ttl = 64;
        ipv4.protocol = PROTOCOL_IPV4_ICMP;
        ipv4.next = &icmp;
        icmp.type = session->icmp_reply_type;
        icmp.data = session->icmp_reply_data;
        icmp.data_len = session->icmp_reply_data_len;
        session->icmp_reply_destination = 0;
        session->icmp_reply_type = 0;
        session->icmp_reply_data_len = 0;
        return encode_ethernet(session->write_buf, &session->write_idx, &eth);
    } else {
        return PROTOCOL_SUCCESS;
    }
}

void
bbl_pap_timeout (timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    session = timer->data;
    interface = session->interface;
    if(session->session_state == BBL_PPP_AUTH) {
        interface->stats.pap_timeout++;
        session->send_requests |= BBL_SEND_PAP_REQUEST;
        bbl_session_tx_qnode_insert(session);
    }
}

protocol_error_t
bbl_encode_packet_pap_request (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_pap_t pap = {0};

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.pap_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_PAP;
    pppoe.next = &pap;

    pap.code = PAP_CODE_REQUEST;
    pap.identifier = 1;
    pap.username = session->username;
    pap.username_len = strlen(session->username);
    pap.password = session->password;
    pap.password_len = strlen(session->password);
    timer_add(&ctx->timer_root, &session->timer_auth, "Authentication Timeout", 5, 0, session, &bbl_pap_timeout);
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_chap_timeout (timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    session = timer->data;
    interface = session->interface;
    if(session->session_state == BBL_PPP_AUTH) {
        interface->stats.chap_timeout++;
        session->send_requests |= BBL_SEND_CHAP_RESPONSE;
        bbl_session_tx_qnode_insert(session);
    }
}

protocol_error_t
bbl_encode_packet_chap_response (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_chap_t chap = {0};

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.chap_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_CHAP;
    pppoe.next = &chap;
    chap.code = CHAP_CODE_RESPONSE;
    chap.identifier = session->chap_identifier;
    chap.challenge = session->chap_response;
    chap.challenge_len = CHALLENGE_LEN;
    chap.name = session->username;
    chap.name_len = strlen(session->username);
    timer_add(&ctx->timer_root, &session->timer_auth, "Authentication Timeout", 5, 0, session, &bbl_chap_timeout);
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_icmpv6_timeout (timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    session = timer->data;
    interface = session->interface;
    if(!session->icmpv6_ra_received) {
        interface->stats.icmpv6_rs_timeout++;
        session->send_requests |= BBL_SEND_ICMPV6_RS;
        bbl_session_tx_qnode_insert(session);
    }
}

protocol_error_t
bbl_encode_packet_icmpv6_rs (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_icmpv6_t icmpv6 = {0};

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.icmpv6_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->ip6cp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV6;
        pppoe.next = &ipv6;
    } else {
        /* IPoE */
        eth.type = PROTOCOL_IPV6;
        eth.next = &ipv6;
    }
    ipv6.dst = (void*)ipv6_multicast_all_routers;
    ipv6.src = (void*)session->link_local_ipv6_address;
    ipv6.ttl = 255;
    ipv6.protocol = IPV6_NEXT_HEADER_ICMPV6;
    ipv6.next = &icmpv6;
    icmpv6.type = IPV6_ICMPV6_ROUTER_SOLICITATION;
    timer_add(&ctx->timer_root, &session->timer_icmpv6, "ICMPv6", 5, 0, session, &bbl_icmpv6_timeout);
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_dhcpv6_timeout (timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    session = timer->data;
    interface = session->interface;
    if(!session->dhcpv6_received) {
        interface->stats.dhcpv6_timeout++;
        session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
        bbl_session_tx_qnode_insert(session);
    }
}

protocol_error_t
bbl_encode_packet_dhcpv6_request (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_udp_t udp = {0};
    bbl_dhcpv6_t dhcpv6 = {0};

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.dhcpv6_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->ip6cp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV6;
        pppoe.next = &ipv6;
    } else {
        /* IPoE */
        eth.type = PROTOCOL_IPV6;
        eth.next = &ipv6;
    }
    ipv6.dst = (void*)ipv6_multicast_all_routers;
    ipv6.src = (void*)session->link_local_ipv6_address;
    ipv6.ttl = 255;
    ipv6.protocol = IPV6_NEXT_HEADER_UDP;
    ipv6.next = &udp;
    udp.dst = DHCPV6_UDP_SERVER;
    udp.src = DHCPV6_UDP_CLIENT;
    udp.protocol = UDP_PROTOCOL_DHCPV6;
    udp.next = &dhcpv6;
    dhcpv6.type = session->dhcpv6_type;
    dhcpv6.transaction_id = rand();
    dhcpv6.client_duid = session->duid;
    dhcpv6.client_duid_len = DUID_LEN;
    dhcpv6.delegated_prefix_iaid = rand();
    dhcpv6.delegated_prefix = &session->delegated_ipv6_prefix;
    if(dhcpv6.type == DHCPV6_MESSAGE_REQUEST) {
        if(session->server_duid_len) {
            dhcpv6.server_duid = session->server_duid;
            dhcpv6.server_duid_len = session->server_duid_len;
        }
        if(session->dhcpv6_ia_pd_option_len) {
            dhcpv6.ia_pd_option = session->dhcpv6_ia_pd_option;
            dhcpv6.ia_pd_option_len = session->dhcpv6_ia_pd_option_len;
        }
    } else {
        dhcpv6.rapid = ctx->config.dhcpv6_rapid_commit;
        dhcpv6.oro = true;
    }
    timer_add(&ctx->timer_root, &session->timer_dhcpv6, "DHCPv6", 5, 0, session, &bbl_dhcpv6_timeout);
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_ip6cp_timeout (timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    session = timer->data;
    interface = session->interface;
    ctx = interface->ctx;
    if(session->session_state == BBL_PPP_NETWORK && session->ip6cp_state != BBL_PPP_OPENED) {
        if(session->ip6cp_retries) {
            interface->stats.ip6cp_timeout++;
        }
        if(session->ip6cp_retries > ctx->config.ip6cp_conf_request_retry) {
            session->ip6cp_state = BBL_PPP_CLOSED;
            LOG(PPPOE, "IP6CP TIMEOUT (ID: %u)\n", session->session_id);
            if(session->ipcp_state == BBL_PPP_CLOSED && session->ip6cp_state == BBL_PPP_CLOSED) {
                bbl_session_clear(ctx, session);
            }
        } else {
            session->send_requests |= BBL_SEND_IP6CP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        }
    }
}

protocol_error_t
bbl_encode_packet_ip6cp_request (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ip6cp_t ip6cp = {0};

    if(session->ip6cp_state == BBL_PPP_CLOSED || session->ip6cp_state == BBL_PPP_OPENED) {
        return WRONG_PROTOCOL_STATE;
    }

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.ip6cp_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_IP6CP;
    pppoe.next = &ip6cp;

    ip6cp.code = session->ip6cp_request_code;
    ip6cp.identifier = ++session->ip6cp_identifier;
    if(ip6cp.code == PPP_CODE_CONF_REQUEST) {
        ip6cp.ipv6_identifier = session->ip6cp_ipv6_identifier;
    }
    timer_add(&ctx->timer_root, &session->timer_ip6cp, "IP6CP timeout", ctx->config.ip6cp_conf_request_timeout, 0, session, &bbl_ip6cp_timeout);
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_packet_ip6cp_response (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    
    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ip6cp_t ip6cp = {0};

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.ip6cp_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_IP6CP;
    pppoe.next = &ip6cp;

    ip6cp.code = session->ip6cp_response_code;
    ip6cp.identifier = session->ip6cp_peer_identifier;
    if(session->ip6cp_options_len) {
        ip6cp.options = session->ip6cp_options;
        ip6cp.options_len = session->ip6cp_options_len;
    } else {
        ip6cp.ipv6_identifier = session->ip6cp_ipv6_identifier;
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_ipcp_timeout (timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    session = timer->data;
    interface = session->interface;
    ctx = interface->ctx;
    if(session->session_state == BBL_PPP_NETWORK && session->ipcp_state != BBL_PPP_OPENED) {
        if(session->ipcp_retries) {
            interface->stats.ipcp_timeout++;
        }
        if(session->ipcp_retries > ctx->config.ipcp_conf_request_retry) {
            session->ipcp_state = BBL_PPP_CLOSED;
            LOG(PPPOE, "IPCP TIMEOUT (ID: %u)\n", session->session_id);
            if(session->ipcp_state == BBL_PPP_CLOSED && session->ip6cp_state == BBL_PPP_CLOSED) {
                bbl_session_clear(ctx, session);
            }
        } else {
            session->send_requests |= BBL_SEND_IPCP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        }
    }
}

protocol_error_t
bbl_encode_packet_ipcp_request (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipcp_t ipcp = {0};

    if(session->ipcp_state == BBL_PPP_CLOSED || session->ipcp_state == BBL_PPP_OPENED) {
        return WRONG_PROTOCOL_STATE;
    }

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.ipcp_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_IPCP;
    pppoe.next = &ipcp;

    ipcp.code = session->ipcp_request_code;
    ipcp.identifier = ++session->ipcp_identifier;
    if(ipcp.code == PPP_CODE_CONF_REQUEST) {
        if(session->ip_address || ctx->config.ipcp_request_ip) {
            ipcp.address = session->ip_address;
            ipcp.option_address = true;
        }
        if(ctx->config.ipcp_request_dns1) {
            ipcp.dns1 = session->dns1;
            ipcp.option_dns1 = true;
        }
        if(ctx->config.ipcp_request_dns2) {
            ipcp.dns2 = session->dns2;
            ipcp.option_dns2 = true;
        }
    }
    timer_add(&ctx->timer_root, &session->timer_ipcp, "IPCP timeout", ctx->config.ipcp_conf_request_timeout, 0, session, &bbl_ipcp_timeout);
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_packet_ipcp_response (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipcp_t ipcp = {0};

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.ipcp_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_IPCP;
    pppoe.next = &ipcp;

    ipcp.code = session->ipcp_response_code;
    ipcp.identifier = session->ipcp_peer_identifier;
    if(session->ipcp_options_len) {
        ipcp.options = session->ipcp_options;
        ipcp.options_len = session->ipcp_options_len;
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_lcp_timeout (timer_s *timer)
{
    bbl_session_s *session;
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    session = timer->data;
    interface = session->interface;
    ctx = interface->ctx;

    if(session->session_state == BBL_PPP_LINK && session->lcp_state != BBL_PPP_OPENED) {
        if(session->lcp_retries) {
            interface->stats.lcp_timeout++;
        }
        if(session->lcp_retries > ctx->config.lcp_conf_request_retry) {
            bbl_session_clear(ctx, session);
        } else {
            session->send_requests |= BBL_SEND_LCP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        }
    } else if (session->session_state == BBL_PPP_TERMINATING) {
        if(session->lcp_retries > 3) {
            /* Send max 3 terminate requests. */
            bbl_session_update_state(ctx, session, BBL_TERMINATING);
            session->send_requests = BBL_SEND_DISCOVERY;
            bbl_session_tx_qnode_insert(session);
        } else {
            bbl_session_clear(ctx, session);
        }
    }
}

protocol_error_t
bbl_encode_packet_lcp_request (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_lcp_t lcp = {0};
    uint16_t timeout = 1; /* default timeout 1 second */

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.lcp_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_LCP;
    pppoe.next = &lcp;

    lcp.code = session->lcp_request_code;
    lcp.identifier = ++session->lcp_identifier;
    if(lcp.code == PPP_CODE_ECHO_REQUEST) {
        lcp.magic = session->magic_number;
        timeout = 0;
    } else if(lcp.code == PPP_CODE_CONF_REQUEST) {
        lcp.mru = session->mru;
        lcp.magic = session->magic_number;
        timeout = ctx->config.lcp_conf_request_timeout;
    }
    if(timeout) {
        timer_add(&ctx->timer_root, &session->timer_lcp, "LCP timeout", timeout, 0, session, &bbl_lcp_timeout);
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_packet_lcp_response (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_lcp_t lcp = {0};

    interface = session->interface;
    ctx = interface->ctx;
    interface->stats.lcp_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_LCP;
    pppoe.next = &lcp;

    lcp.code = session->lcp_response_code;
    lcp.identifier = session->lcp_peer_identifier;

    if(lcp.code == PPP_CODE_ECHO_REPLY) {
        lcp.magic = session->magic_number;
    } else {
        if(session->lcp_options_len) {
            lcp.options = session->lcp_options;
            lcp.options_len = session->lcp_options_len;
        } else {
            lcp.mru = session->peer_mru;
            lcp.auth = session->auth_protocol;
            lcp.magic = session->peer_magic_number;
        }
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_padi_timeout (timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPPOE_INIT) {
        session->send_requests = BBL_SEND_DISCOVERY;
        bbl_session_tx_qnode_insert(session);
    }
}

void
bbl_padr_timeout (timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPPOE_REQUEST) {
        session->send_requests = BBL_SEND_DISCOVERY;
        bbl_session_tx_qnode_insert(session);
    }
}

protocol_error_t
bbl_encode_padi (bbl_session_s *session)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_discovery_t pppoe = {0};
    access_line_t access_line = {0};

    interface = session->interface;
    ctx = interface->ctx;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;

    eth.type = ETH_TYPE_PPPOE_DISCOVERY;
    eth.next = &pppoe;
    pppoe.code = PPPOE_PADI;
    if(session->pppoe_service_name) {
        pppoe.service_name = (uint8_t*)session->pppoe_service_name;
        pppoe.service_name_len = session->pppoe_service_name_len;
    }
    if(session->pppoe_host_uniq) {
        pppoe.host_uniq = (uint8_t*)&session->pppoe_host_uniq;
        pppoe.host_uniq_len = sizeof(uint64_t);
    }
    if(session->agent_circuit_id || session->agent_remote_id) {
        access_line.aci = session->agent_circuit_id;
        access_line.ari = session->agent_remote_id;
        access_line.up = session->rate_up;
        access_line.down = session->rate_down;
        access_line.dsl_type = session->dsl_type;
        pppoe.access_line = &access_line;
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_padr (bbl_session_s *session)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_discovery_t pppoe = {0};
    access_line_t access_line = {0};

    interface = session->interface;
    ctx = interface->ctx;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_DISCOVERY;
    eth.next = &pppoe;
    pppoe.code = PPPOE_PADR;
    pppoe.ac_cookie = session->pppoe_ac_cookie;
    pppoe.ac_cookie_len = session->pppoe_ac_cookie_len;
    if(session->pppoe_service_name) {
        pppoe.service_name = (uint8_t*)session->pppoe_service_name;
        pppoe.service_name_len = session->pppoe_service_name_len;
    }
    if(session->pppoe_host_uniq) {
        pppoe.host_uniq = (uint8_t*)&session->pppoe_host_uniq;
        pppoe.host_uniq_len = sizeof(uint64_t);
    }
    if(session->agent_circuit_id || session->agent_remote_id) {
        access_line.aci = session->agent_circuit_id;
        access_line.ari = session->agent_remote_id;
        access_line.up = session->rate_up;
        access_line.down = session->rate_down;
        access_line.dsl_type = session->dsl_type;
        pppoe.access_line = &access_line;
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_padt (bbl_session_s *session)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_discovery_t pppoe = {0};

    interface = session->interface;
    ctx = interface->ctx;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_DISCOVERY;
    eth.next = &pppoe;
    pppoe.code = PPPOE_PADT;
    pppoe.session_id = session->pppoe_session_id;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_packet_discovery (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    protocol_error_t result = UNKNOWN_PROTOCOL;

    interface = session->interface;
    ctx = interface->ctx;

     switch(session->session_state) {
        case BBL_PPPOE_INIT:
            result = bbl_encode_padi(session);
            timer_add(&ctx->timer_root, &session->timer_padi, "PADI timeout", 5, 0, session, &bbl_padi_timeout);
            interface->stats.padi_tx++;
            if(!ctx->stats.first_session_tx.tv_sec) {
                ctx->stats.first_session_tx.tv_sec = interface->tx_timestamp.tv_sec;
                ctx->stats.first_session_tx.tv_nsec = interface->tx_timestamp.tv_nsec;
            }
            break;
        case BBL_PPPOE_REQUEST:
            result = bbl_encode_padr(session);
            timer_add(&ctx->timer_root, &session->timer_padr, "PADR timeout", 5, 0, session, &bbl_padr_timeout);
            interface->stats.padr_tx++;
            break;
        case BBL_TERMINATING:
            bbl_session_update_state(ctx, session, BBL_TERMINATED);
            result = bbl_encode_padt(session);
            interface->stats.padt_tx++;
            break;
        default:
            break;
    }

    return result;
}

void
bbl_dhcp_timeout (timer_s *timer)
{
    bbl_session_s *session = timer->data;

    if(session->dhcp_state == BBL_DHCP_INIT || 
       session->dhcp_state == BBL_DHCP_BOUND) {
        /* Wrong state */
        return;
    } 

    session->send_requests = BBL_SEND_DHCP_REQUEST;
    bbl_session_tx_qnode_insert(session);
}

protocol_error_t
bbl_encode_packet_dhcp (bbl_session_s *session) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_udp_t udp = {0};
    struct dhcp_header header = {0};
    bbl_dhcp_t dhcp = {0};
    access_line_t access_line = {0};
    struct timespec now;

    if(session->dhcp_state == BBL_DHCP_INIT ||
       session->dhcp_state == BBL_DHCP_BOUND) {
        return IGNORED;
    }

    interface = session->interface;
    ctx = interface->ctx;

    dhcp.header = &header;

    eth.dst = session->dhcp_server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = ctx->config.dhcp_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;

    eth.type = ETH_TYPE_IPV4;
    eth.next = &ipv4;
    ipv4.src = session->ip_address;
    ipv4.dst = session->dhcp_server;
    ipv4.ttl = 255;
    ipv4.tos = ctx->config.dhcp_tos;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = DHCP_UDP_CLIENT;
    udp.dst = DHCP_UDP_SERVER;
    udp.protocol = UDP_PROTOCOL_DHCP;
    udp.next = &dhcp;

    /* Init DHCP header */
    header.op = BOOTREQUEST;
    header.htype = 1; /* fixed set to ethernet */
    header.hlen = 6;
    header.xid = session->dhcp_xid;
    if(ctx->config.dhcp_broadcast && session->dhcp_state != BBL_DHCP_RELEASE) {
        header.flags = htobe16(1 << 15);
        eth.dst = (uint8_t*)broadcast_mac;
        ipv4.dst = IPV4_BROADCAST;
    }
    header.ciaddr = session->ip_address;
    memcpy(header.chaddr, session->client_mac, ETH_ADDR_LEN);
    /* The 'secs' field of a BOOTREQUEST message SHOULD represent the
     * elapsed time, in seconds, since the client sent its first 
     * BOOTREQUEST message. */
    clock_gettime(CLOCK_MONOTONIC, &now);
    if(session->dhcp_request_timestamp.tv_sec) {
        header.secs = htobe16(now.tv_sec - session->dhcp_request_timestamp.tv_sec);
    } else {
        header.secs = 0;
        session->dhcp_request_timestamp.tv_sec = now.tv_sec;
    }

    /* Option 82 ... */
    if((session->agent_circuit_id || session->agent_remote_id) && session->dhcp_state != BBL_DHCP_RELEASE) {
        access_line.aci = session->agent_circuit_id;
        access_line.ari = session->agent_remote_id;
        dhcp.access_line = &access_line;
    }

    switch(session->dhcp_state) {
        case BBL_DHCP_SELECTING:
            dhcp.type = DHCP_MESSAGE_DISCOVER;
            session->stats.dhcp_tx_discover++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-Discover send\n", session->session_id);
            eth.dst = (uint8_t*)broadcast_mac;
            ipv4.dst = IPV4_BROADCAST;
            dhcp.parameter_request_list = true;
            dhcp.option_netmask = true;
            dhcp.option_dns1 = true;
            dhcp.option_dns2 = true;
            dhcp.option_router = true;
            dhcp.option_host_name = true;
            dhcp.option_domain_name = true;
            if(!ctx->stats.first_session_tx.tv_sec) {
                ctx->stats.first_session_tx.tv_sec = interface->tx_timestamp.tv_sec;
                ctx->stats.first_session_tx.tv_nsec = interface->tx_timestamp.tv_nsec;
            }
            break;
        case BBL_DHCP_REQUESTING:
            dhcp.type = DHCP_MESSAGE_REQUEST;
            session->stats.dhcp_tx_request++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-Request send\n", session->session_id);
            dhcp.option_address = true;
            dhcp.address = session->dhcp_address;
            dhcp.option_server_identifier = true;
            dhcp.server_identifier = session->dhcp_server_identifier;
            dhcp.parameter_request_list = true;
            dhcp.option_netmask = true;
            dhcp.option_dns1 = true;
            dhcp.option_dns2 = true;
            dhcp.option_router = true;
            dhcp.option_host_name = true;
            dhcp.option_domain_name = true;
            break;
        case BBL_DHCP_RENEWING:
            dhcp.type = DHCP_MESSAGE_REQUEST;
            session->stats.dhcp_tx_request++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-Request send\n", session->session_id);
            break;
        case BBL_DHCP_RELEASE:
            dhcp.type = DHCP_MESSAGE_RELEASE;
            session->stats.dhcp_tx_release++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-Release send\n", session->session_id);
            dhcp.option_server_identifier = true;
            dhcp.server_identifier = session->dhcp_server_identifier;
            if(session->session_state == BBL_TERMINATING) {
                bbl_session_update_state(ctx, session, BBL_TERMINATED);
            }
            break;
        default:
            return IGNORED;
    }

    timer_add(&ctx->timer_root, &session->timer_dhcp_retry, "DHCP timeout", ctx->config.dhcp_timeout, 0, session, &bbl_dhcp_timeout);
    interface->stats.dhcp_tx++;

    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_arp_timeout (timer_s *timer)
{
    bbl_session_s *session = timer->data;
    session->send_requests |= BBL_SEND_ARP_REQUEST;
    bbl_session_tx_qnode_insert(session);
}

protocol_error_t
bbl_encode_packet_arp_request (bbl_session_s *session)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    bbl_ethernet_header_t eth = {0};
    bbl_arp_t arp = {0};
    
    interface = session->interface;
    ctx = interface->ctx;

    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.type = ETH_TYPE_ARP;
    eth.next = &arp;
    arp.code = ARP_REQUEST;
    arp.sender = session->client_mac;
    arp.sender_ip = session->ip_address;
    arp.target_ip = session->peer_ip_address;

    if(session->arp_resolved) {
        if(ctx->config.arp_interval) {
            timer_add(&ctx->timer_root, &session->timer_arp, "ARP timeout", ctx->config.arp_interval, 0, session, &bbl_arp_timeout);
        }
    } else {
        timer_add(&ctx->timer_root, &session->timer_arp, "ARP timeout", ctx->config.arp_timeout, 0, session, &bbl_arp_timeout);
    }
    interface->stats.arp_tx++;
    if(!ctx->stats.first_session_tx.tv_sec) {
        ctx->stats.first_session_tx.tv_sec = interface->tx_timestamp.tv_sec;
        ctx->stats.first_session_tx.tv_nsec = interface->tx_timestamp.tv_nsec;
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_packet_arp_reply (bbl_session_s *session)
{
    bbl_ethernet_header_t eth = {0};
    bbl_arp_t arp = {0};
    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.type = ETH_TYPE_ARP;
    eth.next = &arp;
    arp.code = ARP_REPLY;
    arp.sender = session->client_mac;
    arp.sender_ip = session->ip_address;
    arp.target = session->server_mac;
    arp.target_ip = session->peer_ip_address;
    session->interface->stats.arp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_encode_packet (bbl_session_s *session, uint8_t *buf, uint16_t *len, bool *accounting)
{
    protocol_error_t result = UNKNOWN_PROTOCOL;

    /* Reset write buffer. */
    session->write_buf = buf;
    session->write_idx = 0;

    if(session->send_requests & BBL_SEND_DISCOVERY) {
        result = bbl_encode_packet_discovery(session);
        session->send_requests &= ~BBL_SEND_DISCOVERY;
    } else if (session->send_requests & BBL_SEND_LCP_REQUEST) {
        result = bbl_encode_packet_lcp_request(session);
        session->send_requests &= ~BBL_SEND_LCP_REQUEST;
        session->lcp_retries++;
    } else if (session->send_requests & BBL_SEND_LCP_RESPONSE) {
        result = bbl_encode_packet_lcp_response(session);
        session->send_requests &= ~BBL_SEND_LCP_RESPONSE;
    } else if (session->send_requests & BBL_SEND_PAP_REQUEST) {
        result = bbl_encode_packet_pap_request(session);
        session->send_requests &= ~BBL_SEND_PAP_REQUEST;
        session->auth_retries++;
    } else if (session->send_requests & BBL_SEND_CHAP_RESPONSE) {
        result = bbl_encode_packet_chap_response(session);
        session->send_requests &= ~BBL_SEND_CHAP_RESPONSE;
        session->auth_retries++;
    } else if (session->send_requests & BBL_SEND_IPCP_REQUEST) {
        result = bbl_encode_packet_ipcp_request(session);
        session->send_requests &= ~BBL_SEND_IPCP_REQUEST;
        session->ipcp_retries++;
    } else if (session->send_requests & BBL_SEND_IPCP_RESPONSE) {
        result = bbl_encode_packet_ipcp_response(session);
        session->send_requests &= ~BBL_SEND_IPCP_RESPONSE;
    } else if (session->send_requests & BBL_SEND_IP6CP_REQUEST) {
        result = bbl_encode_packet_ip6cp_request(session);
        session->send_requests &= ~BBL_SEND_IP6CP_REQUEST;
        session->ip6cp_retries++;
    } else if (session->send_requests & BBL_SEND_IP6CP_RESPONSE) {
        result = bbl_encode_packet_ip6cp_response(session);
        session->send_requests &= ~BBL_SEND_IP6CP_RESPONSE;
    } else if (session->send_requests & BBL_SEND_ICMPV6_RS) {
        result = bbl_encode_packet_icmpv6_rs(session);
        session->send_requests &= ~BBL_SEND_ICMPV6_RS;
    } else if (session->send_requests & BBL_SEND_DHCPV6_REQUEST) {
        result = bbl_encode_packet_dhcpv6_request(session);
        session->send_requests &= ~BBL_SEND_DHCPV6_REQUEST;
    } else if (session->send_requests & BBL_SEND_IGMP) {
        result = bbl_encode_packet_igmp(session);
    } else if (session->send_requests & BBL_SEND_ICMP_REPLY) {
        result = bbl_encode_packet_icmp_reply(session);
        session->send_requests &= ~BBL_SEND_ICMP_REPLY;
    } else if (session->send_requests & BBL_SEND_SESSION_IPV4) {
        result = bbl_encode_packet_session_ipv4(session);
        session->send_requests &= ~BBL_SEND_SESSION_IPV4;
        *accounting = true;
    } else if (session->send_requests & BBL_SEND_SESSION_IPV6) {
        result = bbl_encode_packet_session_ipv6(session);
        session->send_requests &= ~BBL_SEND_SESSION_IPV6;
        *accounting = true;
    } else if (session->send_requests & BBL_SEND_SESSION_IPV6PD) {
        result = bbl_encode_packet_session_ipv6pd(session);
        session->send_requests &= ~BBL_SEND_SESSION_IPV6PD;
        *accounting = true;
    } else if (session->send_requests & BBL_SEND_ARP_REQUEST) {
        result = bbl_encode_packet_arp_request(session);
        session->send_requests &= ~BBL_SEND_ARP_REQUEST;
    } else if (session->send_requests & BBL_SEND_ARP_REPLY) {
        result = bbl_encode_packet_arp_reply(session);
        session->send_requests &= ~BBL_SEND_ARP_REPLY;
    } else if (session->send_requests & BBL_SEND_DHCP_REQUEST) {
        result = bbl_encode_packet_dhcp(session);
        session->send_requests &= ~BBL_SEND_DHCP_REQUEST;
    } else {
        session->send_requests = 0;
    }

    *len = session->write_idx;
    return result;
}

protocol_error_t
bbl_encode_network_packet (bbl_interface_s *interface, bbl_session_s *session, uint8_t *buf, uint16_t *len)
{
    protocol_error_t result = UNKNOWN_PROTOCOL;

    /* Reset write buffer. */
    session->write_buf = buf;
    session->write_idx = 0;

    if (session->network_send_requests & BBL_SEND_SESSION_IPV4) {
        result = bbl_encode_packet_network_session_ipv4(interface, session);
        session->network_send_requests &= ~BBL_SEND_SESSION_IPV4;
    } else if (session->network_send_requests & BBL_SEND_SESSION_IPV6) {
        result = bbl_encode_packet_network_session_ipv6(interface, session);
        session->network_send_requests &= ~BBL_SEND_SESSION_IPV6;
    } else if (session->network_send_requests & BBL_SEND_SESSION_IPV6PD) {
        result = bbl_encode_packet_network_session_ipv6pd(interface, session);
        session->network_send_requests &= ~BBL_SEND_SESSION_IPV6PD;
    } else {
        session->network_send_requests = 0;
    }

    *len = session->write_idx;
    return result;
}

void
bbl_network_arp_timeout (timer_s *timer)
{
    bbl_interface_s *interface = timer->data;
    interface->send_requests |= BBL_SEND_ARP_REQUEST;
}

void
bbl_network_nd_timeout (timer_s *timer)
{
    bbl_interface_s *interface = timer->data;
    interface->send_requests |= BBL_IF_SEND_ICMPV6_NS;
}

protocol_error_t
bbl_encode_interface_packet (bbl_interface_s *interface, uint8_t *buf, uint16_t *len)
{
    protocol_error_t result = UNKNOWN_PROTOCOL;
    bbl_ethernet_header_t eth = {0};
    bbl_arp_t arp = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_icmpv6_t icmpv6 = {0};

    bbl_secondary_ip_s *secondary_ip;
    bbl_secondary_ip6_s *secondary_ip6;

    *len = 0;

    eth.src = interface->mac;
    eth.vlan_outer = interface->ctx->config.network_vlan;
    if(interface->send_requests & BBL_IF_SEND_ARP_REQUEST) {
        interface->send_requests &= ~BBL_IF_SEND_ARP_REQUEST;
        eth.type = ETH_TYPE_ARP;
        eth.next = &arp;
        arp.code = ARP_REQUEST;
        arp.sender = interface->mac;
        arp.sender_ip = interface->ip;
        arp.target_ip = interface->gateway;
        if(interface->arp_resolved) {
            timer_add(&interface->ctx->timer_root, &interface->timer_arp, "ARP timeout", 300, 0, interface, &bbl_network_arp_timeout);
        } else {
            timer_add(&interface->ctx->timer_root, &interface->timer_arp, "ARP timeout", 1, 0, interface, &bbl_network_arp_timeout);
        }
        result = encode_ethernet(buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_ARP_REPLY) {
        interface->send_requests &= ~BBL_IF_SEND_ARP_REPLY;
        eth.dst = interface->gateway_mac;
        eth.type = ETH_TYPE_ARP;
        eth.next = &arp;
        arp.code = ARP_REPLY;
        arp.sender = interface->mac;
        arp.sender_ip = interface->arp_reply_ip;
        arp.target = interface->gateway_mac;
        arp.target_ip = interface->gateway;
        result = encode_ethernet(buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_SEC_ARP_REPLY) {
        secondary_ip = interface->ctx->config.secondary_ip_addresses;
        while(secondary_ip) {
            if(secondary_ip->arp_reply) {
                secondary_ip->arp_reply = false;
                eth.dst = interface->gateway_mac;
                eth.type = ETH_TYPE_ARP;
                eth.next = &arp;
                arp.code = ARP_REPLY;
                arp.sender = interface->mac;
                arp.sender_ip = secondary_ip->ip;
                arp.target = interface->gateway_mac;
                arp.target_ip = interface->gateway;
                result = encode_ethernet(buf, len, &eth);
                break;
            }
            secondary_ip = secondary_ip->next;
        }
        if(!secondary_ip) {
            /* Stop if we reach end of secondary IP address list */
            interface->send_requests &= ~BBL_IF_SEND_SEC_ARP_REPLY;
        }
    } else if(interface->send_requests & BBL_IF_SEND_ICMPV6_NS) {
        interface->send_requests &= ~BBL_IF_SEND_ICMPV6_NS;
        if(*(uint32_t*)interface->gateway_mac == 0) {
            eth.dst = (uint8_t*)ipv6_multicast_mac;
        } else {
            eth.dst = interface->gateway_mac;
        }
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
        ipv6.src = interface->ip6.address;
        ipv6.dst = interface->gateway6.address;
        ipv6.protocol = IPV6_NEXT_HEADER_ICMPV6;
        ipv6.next = &icmpv6;
        ipv6.ttl = 255;
        icmpv6.type = IPV6_ICMPV6_NEIGHBOR_SOLICITATION;
        memcpy(icmpv6.prefix.address, interface->gateway6.address, IPV6_ADDR_LEN);
        icmpv6.mac = interface->mac;
        if(interface->icmpv6_nd_resolved) {
            timer_add(&interface->ctx->timer_root, &interface->timer_nd, "ND timeout", 300, 0, interface, &bbl_network_nd_timeout);
        } else {
            timer_add(&interface->ctx->timer_root, &interface->timer_nd, "ND timeout", 1, 0, interface, &bbl_network_nd_timeout);
        }
        result = encode_ethernet(buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_ICMPV6_NA) {
        interface->send_requests &= ~BBL_IF_SEND_ICMPV6_NA;
        eth.dst = interface->gateway_mac;
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
        ipv6.src = interface->ip6.address;
        ipv6.dst = interface->icmpv6_src;
        ipv6.protocol = IPV6_NEXT_HEADER_ICMPV6;
        ipv6.next = &icmpv6;
        ipv6.ttl = 255;
        icmpv6.type = IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT;
        memcpy(icmpv6.prefix.address, interface->ip6.address, IPV6_ADDR_LEN);
        icmpv6.mac = interface->mac;
        result = encode_ethernet(buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_SEC_ICMPV6_NA) {
        secondary_ip6 = interface->ctx->config.secondary_ip6_addresses;
        while(secondary_ip6) {
            if(secondary_ip6->icmpv6_na) {
                secondary_ip6->icmpv6_na = false;
                eth.dst = interface->gateway_mac;
                eth.type = ETH_TYPE_IPV6;
                eth.next = &ipv6;
                ipv6.src = secondary_ip6->ip;
                ipv6.dst = secondary_ip6->icmpv6_src;
                ipv6.protocol = IPV6_NEXT_HEADER_ICMPV6;
                ipv6.next = &icmpv6;
                ipv6.ttl = 255;
                icmpv6.type = IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT;
                memcpy(icmpv6.prefix.address, secondary_ip6->ip, IPV6_ADDR_LEN);
                icmpv6.mac = interface->mac;
                result = encode_ethernet(buf, len, &eth);
                break;
            }
            secondary_ip6 = secondary_ip6->next;
        }
        if(!secondary_ip6) {
            /* Stop if we reach end of secondary IP address list */
            interface->send_requests &= ~BBL_IF_SEND_SEC_ICMPV6_NA;
        }
    } else {
        interface->send_requests = 0;
    }

    return result;
}

/** 
 * bbl_tx 
 *
 * This function should be called as long a send buffer is available or 
 * return code is not EMPTY. 
 * 
 * @param ctx pointer to ethernet header structure of received packet
 * @param interface pointer to interface on which packet was received
 * @param buf send buffer where packet can be crafted
 * @param len length of the crafted packet
 */
protocol_error_t
bbl_tx (bbl_ctx_s *ctx, bbl_interface_s *interface, uint8_t *buf, uint16_t *len)
{
    protocol_error_t result = EMPTY; /* EMPTY means that everthing was send */
    bbl_session_s *session;
    bbl_l2tp_queue_t *q;

    bool accounting;

    /* Write per interface frames like ARP, ICMPv6 NS or LLDP. */
    if(interface->send_requests) {
        return bbl_encode_interface_packet(interface, buf, len);
    }

    if(interface->access) { /* Access interfaces ... */
        /* Write per session frames. */
        if (!CIRCLEQ_EMPTY(&interface->session_tx_qhead)) {
            session = CIRCLEQ_FIRST(&interface->session_tx_qhead);

            if(session->send_requests != 0) {
                accounting = false;
                result = bbl_encode_packet(session, buf, len, &accounting);
                if(result == PROTOCOL_SUCCESS) {
                    session->stats.packets_tx++;
                    session->stats.bytes_tx += *len;
                    if(accounting) {
                        session->stats.accounting_packets_tx++;
                        session->stats.accounting_bytes_tx += *len;
                    }
                }
                /* Remove only from TX queue if all requests are processed! */
                if(session->send_requests == 0) {
                    bbl_session_tx_qnode_remove(session);
                } else {
                    /* Move to the end. */
                    bbl_session_tx_qnode_remove(session);
                    bbl_session_tx_qnode_insert(session);
                }
            } else {
                bbl_session_tx_qnode_remove(session);
            }
            return result;
        }
    } else { /* Network interfaces ... */
        /* Write per session frames. */
        if (!CIRCLEQ_EMPTY(&interface->session_tx_qhead)) {
            session = CIRCLEQ_FIRST(&interface->session_tx_qhead);
            if(session->network_send_requests != 0) {
                result = bbl_encode_network_packet(interface, session, buf, len);
                /* Remove only from TX queue if all requests are processed! */
                if(session->network_send_requests == 0) {
                    bbl_session_network_tx_qnode_remove(session);
                } else {
                    /* Move to the end. */
                    bbl_session_network_tx_qnode_remove(session);
                    bbl_session_network_tx_qnode_insert(session);
                }
            } else {
                bbl_session_network_tx_qnode_remove(session);
            }
            return result;
        }
        /* Write L2TP frames. */
        if (!CIRCLEQ_EMPTY(&interface->l2tp_tx_qhead)) {
            /* Pop element from queue. */
            q = CIRCLEQ_FIRST(&interface->l2tp_tx_qhead);
            CIRCLEQ_REMOVE(&interface->l2tp_tx_qhead, q, tx_qnode);
            CIRCLEQ_NEXT(q, tx_qnode) = NULL;
            CIRCLEQ_PREV(q, tx_qnode) = NULL;
            /* Copy packet from queue to ring buffer. */
            memcpy(buf, q->packet, q->packet_len);
            *len = q->packet_len;
            if(q->data) {
                free(q);
            }
            return PROTOCOL_SUCCESS;
        }
        /* Write Multicast frames. */
        if(ctx->config.send_multicast_traffic && ctx->config.igmp_group_count && ctx->multicast_traffic ) {
            if(interface->mc_packet_cursor < ctx->config.igmp_group_count) {
                memcpy(buf, interface->mc_packets + (interface->mc_packet_cursor*interface->mc_packet_len), interface->mc_packet_len);
                *(uint64_t*)(buf + (interface->mc_packet_len - 16)) = interface->mc_packet_seq;
                *(uint32_t*)(buf + (interface->mc_packet_len - 8)) = interface->tx_timestamp.tv_sec;
                *(uint32_t*)(buf + (interface->mc_packet_len - 4)) = interface->tx_timestamp.tv_nsec;
                *len = interface->mc_packet_len;
                interface->mc_packet_cursor++;
                return PROTOCOL_SUCCESS;
            } else {
                /* This must be the last send operation in this function to fill up remaining slots
                * with multicast traffic but all other types of traffic have priority. */
                interface->mc_packet_cursor = 0;
                interface->mc_packet_seq++;
            }
        }
    }
    return result;
}