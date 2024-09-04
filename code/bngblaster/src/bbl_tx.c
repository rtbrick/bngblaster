/*
 * BNG Blaster (BBL) - TX Job
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_session.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"

void
bbl_tx_igmp_timeout(timer_s *timer)
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
    } else {
        if(session->session_state != BBL_ESTABLISHED) {
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

static protocol_error_t
bbl_tx_encode_packet_igmp(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_igmp_s igmp = {0};
    uint8_t mac[ETH_ADDR_LEN];

    bbl_igmp_group_record_s *gr;
    int i, i2;

    bool is_join = false;
    bool is_leave = false;

    bbl_igmp_group_s *group = NULL;

    struct timespec timestamp;
    clock_gettime(CLOCK_MONOTONIC, &timestamp);

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
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
        if(session->session_state != BBL_ESTABLISHED) {
            session->send_requests &= ~BBL_SEND_IGMP;
            return WRONG_PROTOCOL_STATE;
        }
        ipv4_multicast_mac(IPV4_MC_IGMP, mac);
        eth.dst = mac;
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
                    if(!g_ctx->config.igmp_combined_leave_join) {
                        continue;
                    }
                } else {
                    is_leave = true;
                }
            } else {
                /* Joining ... */
                if(is_leave) {
                    if(!g_ctx->config.igmp_combined_leave_join) {
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
                            group->leave_tx_time.tv_sec = timestamp.tv_sec;
                            group->leave_tx_time.tv_nsec = timestamp.tv_nsec;
                        }
                    } else {
                        if(group->state == IGMP_GROUP_ACTIVE) {
                            gr->type = IGMP_INCLUDE;
                        } else {
                            gr->type = IGMP_ALLOW_NEW_SOURCES;
                        }
                        if(!group->join_tx_time.tv_sec) {
                            group->join_tx_time.tv_sec = timestamp.tv_sec;
                            group->join_tx_time.tv_nsec = timestamp.tv_nsec;
                        }
                    }
                } else {
                    /* ASM */
                    if(group->state == IGMP_GROUP_LEAVING) {
                        gr->type = IGMP_CHANGE_TO_INCLUDE;
                        if(!group->leave_tx_time.tv_sec) {
                            group->leave_tx_time.tv_sec = timestamp.tv_sec;
                            group->leave_tx_time.tv_nsec = timestamp.tv_nsec;
                        }
                    } else {
                        gr->type = IGMP_EXCLUDE;
                        if(!group->join_tx_time.tv_sec) {
                            group->join_tx_time.tv_sec = timestamp.tv_sec;
                            group->join_tx_time.tv_nsec = timestamp.tv_nsec;
                        }
                    }
                }
            } else {
                ipv4.dst = group->group;
                igmp.group = group->group;
                if(session->access_type != ACCESS_TYPE_PPPOE) {
                    /* IPoE */
                    ipv4_multicast_mac(group->group, mac);
                    eth.dst = mac;
                }
                if(session->igmp_version == IGMP_VERSION_2) {
                    igmp.version = IGMP_VERSION_2;
                    if(group->state == IGMP_GROUP_LEAVING) {
                        igmp.type = IGMP_TYPE_LEAVE;
                        if(!group->leave_tx_time.tv_sec) {
                            group->leave_tx_time.tv_sec = timestamp.tv_sec;
                            group->leave_tx_time.tv_nsec = timestamp.tv_nsec;
                        }
                    } else {
                        igmp.type = IGMP_TYPE_REPORT_V2;
                        if(!group->join_tx_time.tv_sec) {
                            group->join_tx_time.tv_sec = timestamp.tv_sec;
                            group->join_tx_time.tv_nsec = timestamp.tv_nsec;
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
                            group->join_tx_time.tv_sec = timestamp.tv_sec;
                            group->join_tx_time.tv_nsec = timestamp.tv_nsec;
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

    timer_add(&g_ctx->timer_root, &session->timer_igmp, "IGMP", 
              (g_ctx->config.igmp_robustness_interval / 1000), 
              (g_ctx->config.igmp_robustness_interval % 1000) * MSEC, 
              session, &bbl_tx_igmp_timeout);

    session->stats.igmp_tx++;
    access_interface->stats.igmp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_tx_pap_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPP_AUTH) {
        session->access_interface->stats.pap_timeout++;
        if(session->auth_retries > g_ctx->config.authentication_retry) {
            bbl_session_clear(session);
        } else {
            session->send_requests |= BBL_SEND_PAP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        }
    }
}

static protocol_error_t
bbl_tx_encode_packet_pap_request(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_pap_s pap = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
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

    timer_add(&g_ctx->timer_root, &session->timer_auth, "Authentication Timeout",
              g_ctx->config.authentication_timeout, 0, session, &bbl_tx_pap_timeout);

    access_interface->stats.pap_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_tx_chap_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPP_AUTH) {
        session->access_interface->stats.chap_timeout++;
        if(session->auth_retries > g_ctx->config.authentication_retry) {
            bbl_session_clear(session);
        } else {
            session->send_requests |= BBL_SEND_CHAP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
        }
    }
}

static protocol_error_t
bbl_tx_encode_packet_chap_response(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_chap_s chap = {0};

    access_interface->stats.chap_tx++;

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
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

    timer_add(&g_ctx->timer_root, &session->timer_auth, "Authentication Timeout", 
              g_ctx->config.authentication_timeout, 0, session, &bbl_tx_chap_timeout);

    access_interface->stats.chap_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_icmpv6_timeout(timer_s *timer)
{
    bbl_session_s *session  = timer->data;
    if(!session->icmpv6_ra_received) {
        session->access_interface->stats.icmpv6_rs_timeout++;
        session->send_requests |= BBL_SEND_ICMPV6_RS;
        bbl_session_tx_qnode_insert(session);
    }
}

static protocol_error_t
bbl_tx_encode_packet_icmpv6_rs(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_icmpv6_s icmpv6 = {0};
    uint8_t mac[ETH_ADDR_LEN];

    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->ip6cp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
        eth.dst = session->server_mac;
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;

        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV6;
        pppoe.next = &ipv6;
    } else {
        /* IPoE */
        ipv6_multicast_mac(ipv6_multicast_all_routers, mac);
        eth.dst = mac;
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
    }
    ipv6.dst = (void*)ipv6_multicast_all_routers;
    ipv6.src = (void*)session->link_local_ipv6_address;
    ipv6.ttl = 255;
    ipv6.protocol = IPV6_NEXT_HEADER_ICMPV6;
    ipv6.next = &icmpv6;
    icmpv6.type = IPV6_ICMPV6_ROUTER_SOLICITATION;

    timer_add(&g_ctx->timer_root, &session->timer_icmpv6, "ICMPv6", 
              5, 0, session, &bbl_icmpv6_timeout);

    session->stats.icmpv6_tx++;
    access_interface->stats.icmpv6_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_tx_dhcpv6_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(!(session->dhcpv6_state == BBL_DHCP_BOUND ||
         session->dhcpv6_state == BBL_DHCP_INIT)) {
        session->access_interface->stats.dhcpv6_timeout++;
        if(session->dhcpv6_retry < g_ctx->config.dhcpv6_retry) {
            session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
            bbl_session_tx_qnode_insert(session);
        } else {
            if(session->dhcpv6_state == BBL_DHCP_RELEASE) {
                session->dhcpv6_state = BBL_DHCP_INIT;
                if(session->session_state == BBL_TERMINATING) {
                    bbl_session_clear(session);
                }
            } else {
                bbl_dhcpv6_restart(session);
            }
        }
    }
}

static protocol_error_t
bbl_tx_encode_packet_dhcpv6_request(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_udp_s udp = {0};
    bbl_dhcpv6_s dhcpv6 = {0};
    bbl_dhcpv6_s dhcpv6_relay = {0};
    access_line_s access_line = {0};
    struct timespec now;
    struct timespec time_diff;
    time_t elapsed = 0;

    uint8_t mac[ETH_ADDR_LEN];

    if(session->dhcpv6_state == BBL_DHCP_INIT ||
       session->dhcpv6_state == BBL_DHCP_BOUND) {
        return IGNORED;
    }

    if(g_ctx->config.dhcpv6_ldra) {
        dhcpv6_relay.type = DHCPV6_MESSAGE_RELAY_FORW;
        dhcpv6_relay.peer_address = (void*)session->link_local_ipv6_address;
        dhcpv6_relay.relay_message = &dhcpv6;
        if(g_ctx->config.dhcpv6_access_line && 
           (session->agent_circuit_id || session->agent_remote_id)) {
            access_line.aci = session->agent_circuit_id;
            access_line.ari = session->agent_remote_id;
            access_line.aaci = session->access_aggregation_circuit_id;
            access_line.up = session->rate_up;
            access_line.down = session->rate_down;
            access_line.dsl_type = session->dsl_type;
            
        }
        if(!access_line.aci) {
            /* The ACI is mapped to the Interface-Id option, 
            * which is mandatory for relay forward messages. */
            access_line.aci = format_mac_address(session->client_mac);
        }
        dhcpv6_relay.access_line = &access_line;
        udp.next = &dhcpv6_relay;
    } else {
        udp.next = &dhcpv6;
    }

    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        if(session->ip6cp_state != BBL_PPP_OPENED) {
            return WRONG_PROTOCOL_STATE;
        }
        eth.dst = session->server_mac;
        eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV6;
        pppoe.next = &ipv6;
    } else {
        /* IPoE */
        ipv6_multicast_mac(ipv6_multicast_all_dhcp, mac);
        eth.dst = mac;
        eth.vlan_outer_priority = g_ctx->config.dhcpv6_vlan_priority;
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
    }
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    ipv6.dst = (void*)ipv6_multicast_all_dhcp;
    ipv6.src = (void*)session->link_local_ipv6_address;
    ipv6.ttl = 64;
    ipv6.tos = g_ctx->config.dhcpv6_tc;
    ipv6.protocol = IPV6_NEXT_HEADER_UDP;
    ipv6.next = &udp;
    udp.dst = DHCPV6_UDP_SERVER;
    udp.src = DHCPV6_UDP_CLIENT;
    udp.protocol = UDP_PROTOCOL_DHCPV6;

    /* The 'elapsed' option message SHOULD represent the
     * amount of time since the client began its current 
     * DHCP transaction. This time is expressed in hundredths 
     * of a second. */
    clock_gettime(CLOCK_MONOTONIC, &now);
    if(session->dhcpv6_request_timestamp.tv_sec) {
        timespec_sub(&time_diff, &now, &session->dhcpv6_request_timestamp);
        elapsed = (time_diff.tv_sec * 100) + (time_diff.tv_nsec / 10000000);
        if(elapsed > UINT16_MAX) elapsed = UINT16_MAX;
    } else {
        session->dhcpv6_request_timestamp.tv_sec = now.tv_sec;
    }
    dhcpv6.elapsed = elapsed;
    dhcpv6.xid = session->dhcpv6_xid;
    dhcpv6.client_duid = session->dhcpv6_duid;
    dhcpv6.client_duid_len = DUID_LEN;
    dhcpv6.server_duid = session->dhcpv6_server_duid;
    dhcpv6.server_duid_len = session->dhcpv6_server_duid_len;
    dhcpv6.ia_na_iaid = session->dhcpv6_ia_na_iaid;
    dhcpv6.ia_na_option = session->dhcpv6_ia_na_option;
    dhcpv6.ia_na_option_len = session->dhcpv6_ia_na_option_len;
    dhcpv6.ia_pd_iaid = session->dhcpv6_ia_pd_iaid;
    dhcpv6.ia_pd_option = session->dhcpv6_ia_pd_option;
    dhcpv6.ia_pd_option_len = session->dhcpv6_ia_pd_option_len;
    dhcpv6.oro = true;
    switch (session->dhcpv6_state) {
        case BBL_DHCP_SELECTING:
            dhcpv6.type = DHCPV6_MESSAGE_SOLICIT;
            session->stats.dhcpv6_tx_solicit++;
            dhcpv6.rapid = g_ctx->config.dhcpv6_rapid_commit;
            dhcpv6.server_duid_len = 0;
            dhcpv6.ia_na_option_len = 0;
            dhcpv6.ia_pd_option_len = 0;
            LOG(DHCP, "DHCPv6 (ID: %u) DHCPv6-Solicit send\n", session->session_id);
            if(!g_ctx->stats.first_session_tx.tv_sec) {
                g_ctx->stats.first_session_tx.tv_sec = now.tv_sec;
                g_ctx->stats.first_session_tx.tv_nsec = now.tv_nsec;
            }
            break;
        case BBL_DHCP_REQUESTING:
            dhcpv6.type = DHCPV6_MESSAGE_REQUEST;
            session->stats.dhcpv6_tx_request++;
            LOG(DHCP, "DHCPv6 (ID: %u) DHCPv6-Request send\n", session->session_id);
            break;
        case BBL_DHCP_RENEWING:
            dhcpv6.type = DHCPV6_MESSAGE_RENEW;
            session->stats.dhcpv6_tx_renew++;
            LOG(DHCP, "DHCPv6 (ID: %u) DHCPv6-Renew send\n", session->session_id);
            break;
        case BBL_DHCP_RELEASE:
            dhcpv6.type = DHCPV6_MESSAGE_RELEASE;
            session->stats.dhcpv6_tx_release++;
            dhcpv6.oro = false;
            LOG(DHCP, "DHCPv6 (ID: %u) DHCPv6-Release send\n", session->session_id);
            break;
        default:
            return IGNORED;
    }

    timer_add(&g_ctx->timer_root, &session->timer_dhcpv6, "DHCPv6",
              g_ctx->config.dhcpv6_timeout, 0, session, &bbl_tx_dhcpv6_timeout);

    session->dhcpv6_retry++;
    session->stats.dhcpv6_tx++;
    access_interface->stats.dhcpv6_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_tx_ip6cp_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPP_NETWORK && session->ip6cp_state != BBL_PPP_OPENED) {
        if(session->ip6cp_retries) {
            session->access_interface->stats.ip6cp_timeout++;
        }
        if(session->ip6cp_retries > g_ctx->config.ip6cp_conf_request_retry) {
            session->ip6cp_state = BBL_PPP_CLOSED;
            LOG(PPPOE, "IP6CP TIMEOUT (ID: %u)\n", session->session_id);
            if(session->ipcp_state == BBL_PPP_CLOSED && session->ip6cp_state == BBL_PPP_CLOSED) {
                bbl_session_clear(session);
            }
        } else {
            session->send_requests |= BBL_SEND_IP6CP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        }
    }
}

static protocol_error_t
bbl_tx_encode_packet_ip6cp_request(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_ip6cp_s ip6cp = {0};

    if(session->ip6cp_state == BBL_PPP_CLOSED || session->ip6cp_state == BBL_PPP_OPENED) {
        return WRONG_PROTOCOL_STATE;
    }

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
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
    timer_add(&g_ctx->timer_root, &session->timer_ip6cp, "IP6CP timeout",
              g_ctx->config.ip6cp_conf_request_timeout, 0, session, &bbl_tx_ip6cp_timeout);

    access_interface->stats.ip6cp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

static protocol_error_t
bbl_tx_encode_packet_ip6cp_response(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_ip6cp_s ip6cp = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
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

    access_interface->stats.ip6cp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_ipcp_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPP_NETWORK && session->ipcp_state != BBL_PPP_OPENED) {
        if(session->ipcp_retries) {
            session->access_interface->stats.ipcp_timeout++;
        }
        if(session->ipcp_retries > g_ctx->config.ipcp_conf_request_retry) {
            session->ipcp_state = BBL_PPP_CLOSED;
            LOG(PPPOE, "IPCP TIMEOUT (ID: %u)\n", session->session_id);
            if(session->ipcp_state == BBL_PPP_CLOSED && session->ip6cp_state == BBL_PPP_CLOSED) {
                bbl_session_clear(session);
            }
        } else {
            session->send_requests |= BBL_SEND_IPCP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        }
    }
}

static protocol_error_t
bbl_tx_encode_packet_ipcp_request(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_ipcp_s ipcp = {0};

    if(session->ipcp_state == BBL_PPP_CLOSED || session->ipcp_state == BBL_PPP_OPENED) {
        return WRONG_PROTOCOL_STATE;
    }

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    pppoe.protocol = PROTOCOL_IPCP;
    pppoe.next = &ipcp;

    ipcp.code = session->ipcp_request_code;
    ipcp.identifier = ++session->ipcp_identifier;
    if(ipcp.code == PPP_CODE_CONF_REQUEST) {
        if(session->ip_address || g_ctx->config.ipcp_request_ip) {
            ipcp.address = session->ip_address;
            ipcp.option_address = true;
        }
        if(session->ipcp_request_dns1) {
            ipcp.dns1 = session->dns1;
            ipcp.option_dns1 = true;
        }
        if(session->ipcp_request_dns2) {
            ipcp.dns2 = session->dns2;
            ipcp.option_dns2 = true;
        }
    }

    timer_add(&g_ctx->timer_root, &session->timer_ipcp, "IPCP timeout",
              g_ctx->config.ipcp_conf_request_timeout, 0, session, &bbl_ipcp_timeout);

    access_interface->stats.ipcp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

static protocol_error_t
bbl_tx_encode_packet_ipcp_response(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_ipcp_s ipcp = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
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

    access_interface->stats.ipcp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_lcp_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPP_LINK && session->lcp_state != BBL_PPP_OPENED) {
        if(session->lcp_retries) {
            session->access_interface->stats.lcp_timeout++;
        }
        if(session->lcp_retries > g_ctx->config.lcp_conf_request_retry) {
            bbl_session_clear(session);
        } else {
            session->send_requests |= BBL_SEND_LCP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        }
    } else if(session->session_state == BBL_PPP_TERMINATING) {
        if(session->lcp_retries > 3) {
            /* Send max 3 terminate requests. */
            bbl_session_update_state(session, BBL_TERMINATING);
            session->lcp_state = BBL_PPP_CLOSED;
            if(session->ipcp_state > BBL_PPP_DISABLED) {
                session->ipcp_state = BBL_PPP_CLOSED;
            }
            if(session->ip6cp_state > BBL_PPP_DISABLED) {
                session->ip6cp_state = BBL_PPP_CLOSED;
            }
            session->send_requests = BBL_SEND_DISCOVERY;
            bbl_session_tx_qnode_insert(session);
        } else {
            bbl_session_clear(session);
        }
    }
}

static protocol_error_t
bbl_tx_encode_packet_lcp_request(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_lcp_s lcp = {0};
    uint16_t timeout = 1; /* default timeout 1 second */

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
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
        timeout = g_ctx->config.lcp_conf_request_timeout;
    }

    if(timeout) {
        timer_add(&g_ctx->timer_root, &session->timer_lcp, "LCP timeout", 
                  timeout, 0, session, &bbl_lcp_timeout);
    }

    access_interface->stats.lcp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

static protocol_error_t
bbl_tx_encode_packet_lcp_response(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_lcp_s lcp = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
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

    access_interface->stats.lcp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_padi_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPPOE_INIT) {
        session->send_requests = BBL_SEND_DISCOVERY;
        bbl_session_tx_qnode_insert(session);
    }
}

void
bbl_padr_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_PPPOE_REQUEST) {
        if(session->pppoe_retries > g_ctx->config.pppoe_discovery_retry) {
            bbl_session_update_state(session, BBL_PPPOE_INIT);
        }
        session->send_requests = BBL_SEND_DISCOVERY;
        bbl_session_tx_qnode_insert(session);
    }
}

static protocol_error_t
bbl_encode_padi(bbl_session_s *session)
{
    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_discovery_s pppoe = {0};
    access_line_s access_line = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;

    eth.type = ETH_TYPE_PPPOE_DISCOVERY;
    eth.next = &pppoe;
    pppoe.code = PPPOE_PADI;
    if(session->pppoe_service_name) {
        pppoe.service_name = session->pppoe_service_name;
        pppoe.service_name_len = session->pppoe_service_name_len;
    }
    if(session->pppoe_host_uniq) {
        pppoe.host_uniq = (uint8_t*)&session->pppoe_host_uniq;
        pppoe.host_uniq_len = sizeof(uint64_t);
    }
    if(g_ctx->config.pppoe_max_payload) {
        pppoe.max_payload = g_ctx->config.pppoe_max_payload;
    }
    if(session->agent_circuit_id || session->agent_remote_id) {
        access_line.aci = session->agent_circuit_id;
        access_line.ari = session->agent_remote_id;
        access_line.aaci = session->access_aggregation_circuit_id;
        access_line.up = session->rate_up;
        access_line.down = session->rate_down;
        access_line.dsl_type = session->dsl_type;
        access_line.profile = session->access_line_profile;
        pppoe.access_line = &access_line;
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

static protocol_error_t
bbl_encode_padr(bbl_session_s *session)
{
    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_discovery_s pppoe = {0};
    access_line_s access_line = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_DISCOVERY;
    eth.next = &pppoe;
    pppoe.code = PPPOE_PADR;
    pppoe.ac_cookie = session->pppoe_ac_cookie;
    pppoe.ac_cookie_len = session->pppoe_ac_cookie_len;
    if(session->pppoe_service_name) {
        pppoe.service_name = session->pppoe_service_name;
        pppoe.service_name_len = session->pppoe_service_name_len;
    }
    if(session->pppoe_host_uniq) {
        pppoe.host_uniq = (uint8_t*)&session->pppoe_host_uniq;
        pppoe.host_uniq_len = sizeof(uint64_t);
    }
    if(g_ctx->config.pppoe_max_payload) {
        pppoe.max_payload = g_ctx->config.pppoe_max_payload;
    }
    if(session->agent_circuit_id || session->agent_remote_id) {
        access_line.aci = session->agent_circuit_id;
        access_line.ari = session->agent_remote_id;
        access_line.aaci = session->access_aggregation_circuit_id;
        access_line.up = session->rate_up;
        access_line.down = session->rate_down;
        access_line.dsl_type = session->dsl_type;
        access_line.profile = session->access_line_profile;
        pppoe.access_line = &access_line;
    }
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

static protocol_error_t
bbl_encode_padt(bbl_session_s *session)
{
    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_discovery_s pppoe = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    eth.type = ETH_TYPE_PPPOE_DISCOVERY;
    eth.next = &pppoe;
    pppoe.code = PPPOE_PADT;
    pppoe.session_id = session->pppoe_session_id;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

protocol_error_t
bbl_tx_encode_packet_discovery(bbl_session_s *session) {
    bbl_access_interface_s *access_interface = session->access_interface;

    protocol_error_t result = UNKNOWN_PROTOCOL;

    switch(session->session_state) {
        case BBL_PPPOE_INIT:
            result = bbl_encode_padi(session);
            timer_add(&g_ctx->timer_root, &session->timer_padi, "PADI timeout", 
                      g_ctx->config.pppoe_discovery_timeout, 0, session, &bbl_padi_timeout);
            access_interface->stats.padi_tx++;
            if(!g_ctx->stats.first_session_tx.tv_sec) {
                clock_gettime(CLOCK_MONOTONIC, &g_ctx->stats.first_session_tx);
            }
            break;
        case BBL_PPPOE_REQUEST:
            result = bbl_encode_padr(session);
            timer_add(&g_ctx->timer_root, &session->timer_padr, "PADR timeout", 
                      g_ctx->config.pppoe_discovery_timeout, 0, session, &bbl_padr_timeout);
            access_interface->stats.padr_tx++;
            break;
        case BBL_TERMINATING:
            result = bbl_encode_padt(session);
            access_interface->stats.padt_tx++;
            bbl_session_update_state(session, BBL_TERMINATED);
            break;
        default:
            break;
    }

    return result;
}

void
bbl_dhcp_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(!(session->dhcp_state == BBL_DHCP_INIT ||
         session->dhcp_state == BBL_DHCP_BOUND)) {
        session->access_interface->stats.dhcp_timeout++;
        if(session->dhcp_retry < g_ctx->config.dhcp_retry) {
            session->send_requests |= BBL_SEND_DHCP_REQUEST;
            bbl_session_tx_qnode_insert(session);
        } else {
            if(session->dhcp_state == BBL_DHCP_RELEASE) {
                session->dhcp_state = BBL_DHCP_INIT;
                if(session->session_state == BBL_TERMINATING) {
                    bbl_session_clear(session);
                }
            } else {
                bbl_dhcp_restart(session);
            }
        }
    }
}

static protocol_error_t
bbl_tx_encode_packet_dhcp(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_udp_s udp = {0};
    struct dhcp_header header = {0};
    bbl_dhcp_s dhcp = {0};
    access_line_s access_line = {0};
    struct timespec now;
    time_t secs = 0;

    if(session->dhcp_state == BBL_DHCP_INIT ||
       session->dhcp_state == BBL_DHCP_BOUND) {
        return IGNORED;
    }

    dhcp.header = &header;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.dhcp_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;

    eth.type = ETH_TYPE_IPV4;
    eth.next = &ipv4;
    ipv4.src = session->ip_address;
    ipv4.ttl = 255;
    ipv4.tos = g_ctx->config.dhcp_tos;
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
    if(g_ctx->config.dhcp_broadcast && session->dhcp_state < BBL_DHCP_BOUND) {
        header.flags = htobe16(1 << 15);
    }
    memcpy(header.chaddr, session->client_mac, ETH_ADDR_LEN);

    /* The 'secs' field of a BOOTREQUEST message SHOULD represent the
     * elapsed time, in seconds, since the client sent its first
     * BOOTREQUEST message. */
    clock_gettime(CLOCK_MONOTONIC, &now);
    if(session->dhcp_request_timestamp.tv_sec) {
        secs = now.tv_sec - session->dhcp_request_timestamp.tv_sec;
        if(secs > UINT16_MAX) secs = UINT16_MAX;
        header.secs = htobe16(secs);
    } else {
        header.secs = 0;
        session->dhcp_request_timestamp.tv_sec = now.tv_sec;
    }

    /* Option 82 ... */
    if(g_ctx->config.dhcp_access_line && 
       (session->agent_circuit_id || session->agent_remote_id) && 
       session->dhcp_state != BBL_DHCP_RELEASE) {
        access_line.aci = session->agent_circuit_id;
        access_line.ari = session->agent_remote_id;
        access_line.aaci = session->access_aggregation_circuit_id;
        access_line.up = session->rate_up;
        access_line.down = session->rate_down;
        access_line.dsl_type = session->dsl_type;
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
            if(!g_ctx->stats.first_session_tx.tv_sec) {
                g_ctx->stats.first_session_tx.tv_sec = now.tv_sec;
                g_ctx->stats.first_session_tx.tv_nsec = now.tv_nsec;
            }
            break;
        case BBL_DHCP_REQUESTING:
            dhcp.type = DHCP_MESSAGE_REQUEST;
            session->stats.dhcp_tx_request++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-Request send\n", session->session_id);
            eth.dst = (uint8_t*)broadcast_mac;
            ipv4.dst = IPV4_BROADCAST;
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
            eth.dst = session->dhcp_server_mac;
            ipv4.dst = session->dhcp_server_identifier;
            header.ciaddr = session->ip_address;
            break;
        case BBL_DHCP_RELEASE:
            dhcp.type = DHCP_MESSAGE_RELEASE;
            session->stats.dhcp_tx_release++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-Release send\n", session->session_id);
            eth.dst = session->dhcp_server_mac;
            ipv4.dst = session->dhcp_server_identifier;
            header.ciaddr = session->ip_address;
            dhcp.option_server_identifier = true;
            dhcp.server_identifier = session->dhcp_server_identifier;
            break;
        default:
            return IGNORED;
    }

    session->dhcp_retry++;
    if(dhcp.type == DHCP_MESSAGE_RELEASE) {
        if(session->dhcp_retry < g_ctx->config.dhcp_release_retry) {
            timer_add(&g_ctx->timer_root, &session->timer_dhcp_retry, "DHCP timeout", 
                      g_ctx->config.dhcp_release_interval, 0, session, &bbl_dhcp_timeout);
        } else {
            session->dhcp_state = BBL_DHCP_INIT;
            if(session->session_state == BBL_TERMINATING) {
                bbl_session_clear(session);
            }
        }
    } else {
        timer_add(&g_ctx->timer_root, &session->timer_dhcp_retry, "DHCP timeout", 
                  g_ctx->config.dhcp_timeout, 0, session, &bbl_dhcp_timeout);
    }

    session->stats.dhcp_tx++;
    access_interface->stats.dhcp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

void
bbl_arp_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    session->send_requests |= BBL_SEND_ARP_REQUEST;
    bbl_session_tx_qnode_insert(session);
}

static protocol_error_t
bbl_tx_encode_packet_arp_request(bbl_session_s *session)
{
    bbl_access_interface_s *access_interface = session->access_interface;

    bbl_ethernet_header_s eth = {0};
    bbl_arp_s arp = {0};

    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
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
        if(g_ctx->config.arp_interval) {
            timer_add(&g_ctx->timer_root, &session->timer_arp, "ARP timeout", 
                      g_ctx->config.arp_interval, 0, session, &bbl_arp_timeout);
        }
    } else {
        timer_add(&g_ctx->timer_root, &session->timer_arp, "ARP timeout", 
                  g_ctx->config.arp_timeout, 0, session, &bbl_arp_timeout);
    }
    if(!g_ctx->stats.first_session_tx.tv_sec) {
        clock_gettime(CLOCK_MONOTONIC, &g_ctx->stats.first_session_tx);
    }

    access_interface->stats.arp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

static protocol_error_t
bbl_tx_encode_packet_arp_reply(bbl_session_s *session)
{
    bbl_ethernet_header_s eth = {0};
    bbl_arp_s arp = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
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

    session->access_interface->stats.arp_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

static protocol_error_t
bbl_tx_encode_packet_cfm_cc(bbl_session_s *session)
{
    bbl_ethernet_header_s eth = {0};
    bbl_cfm_s cfm = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.type = ETH_TYPE_CFM;
    eth.next = &cfm;
    cfm.type = CFM_TYPE_CCM;
    cfm.seq = session->cfm_seq++;
    cfm.rdi = session->cfm_rdi;
    cfm.md_level = session->cfm_level;
    cfm.md_name_format = CMF_MD_NAME_FORMAT_NONE;
    cfm.ma_id = session->cfm_ma_id;
    cfm.ma_name_format = CMF_MA_NAME_FORMAT_STRING;
    if(session->cfm_ma_name) {
        cfm.ma_name_len = strlen(session->cfm_ma_name);
        cfm.ma_name = (uint8_t*)session->cfm_ma_name;
    }

    session->access_interface->stats.cfm_cc_tx++;
    return encode_ethernet(session->write_buf, &session->write_idx, &eth);
}

static protocol_error_t
bbl_tx_encode_packet(bbl_session_s *session, uint8_t *buf, uint16_t *len)
{
    protocol_error_t result = UNKNOWN_PROTOCOL;

    /* Reset write buffer. */
    session->write_buf = buf;
    session->write_idx = 0;

    if(session->send_requests & BBL_SEND_DISCOVERY) {
        result = bbl_tx_encode_packet_discovery(session);
        session->send_requests &= ~BBL_SEND_DISCOVERY;
        session->pppoe_retries++;
    } else if(session->send_requests & BBL_SEND_LCP_REQUEST) {
        result = bbl_tx_encode_packet_lcp_request(session);
        session->send_requests &= ~BBL_SEND_LCP_REQUEST;
        session->lcp_retries++;
    } else if(session->send_requests & BBL_SEND_LCP_RESPONSE) {
        result = bbl_tx_encode_packet_lcp_response(session);
        session->send_requests &= ~BBL_SEND_LCP_RESPONSE;
    } else if(session->send_requests & BBL_SEND_PAP_REQUEST) {
        result = bbl_tx_encode_packet_pap_request(session);
        session->send_requests &= ~BBL_SEND_PAP_REQUEST;
        session->auth_retries++;
    } else if(session->send_requests & BBL_SEND_CHAP_RESPONSE) {
        result = bbl_tx_encode_packet_chap_response(session);
        session->send_requests &= ~BBL_SEND_CHAP_RESPONSE;
        session->auth_retries++;
    } else if(session->send_requests & BBL_SEND_IPCP_REQUEST) {
        result = bbl_tx_encode_packet_ipcp_request(session);
        session->send_requests &= ~BBL_SEND_IPCP_REQUEST;
        session->ipcp_retries++;
    } else if(session->send_requests & BBL_SEND_IPCP_RESPONSE) {
        result = bbl_tx_encode_packet_ipcp_response(session);
        session->send_requests &= ~BBL_SEND_IPCP_RESPONSE;
    } else if(session->send_requests & BBL_SEND_IP6CP_REQUEST) {
        result = bbl_tx_encode_packet_ip6cp_request(session);
        session->send_requests &= ~BBL_SEND_IP6CP_REQUEST;
        session->ip6cp_retries++;
    } else if(session->send_requests & BBL_SEND_IP6CP_RESPONSE) {
        result = bbl_tx_encode_packet_ip6cp_response(session);
        session->send_requests &= ~BBL_SEND_IP6CP_RESPONSE;
    } else if(session->send_requests & BBL_SEND_ICMPV6_RS) {
        result = bbl_tx_encode_packet_icmpv6_rs(session);
        session->send_requests &= ~BBL_SEND_ICMPV6_RS;
    } else if(session->send_requests & BBL_SEND_DHCPV6_REQUEST) {
        result = bbl_tx_encode_packet_dhcpv6_request(session);
        session->send_requests &= ~BBL_SEND_DHCPV6_REQUEST;
    } else if(session->send_requests & BBL_SEND_IGMP) {
        result = bbl_tx_encode_packet_igmp(session);
    } else if(session->send_requests & BBL_SEND_ARP_REQUEST) {
        result = bbl_tx_encode_packet_arp_request(session);
        session->send_requests &= ~BBL_SEND_ARP_REQUEST;
    } else if(session->send_requests & BBL_SEND_ARP_REPLY) {
        result = bbl_tx_encode_packet_arp_reply(session);
        session->send_requests &= ~BBL_SEND_ARP_REPLY;
    } else if(session->send_requests & BBL_SEND_DHCP_REQUEST) {
        result = bbl_tx_encode_packet_dhcp(session);
        session->send_requests &= ~BBL_SEND_DHCP_REQUEST;
    } else if(session->send_requests & BBL_SEND_CFM_CC) {
        result = bbl_tx_encode_packet_cfm_cc(session);
        session->send_requests &= ~BBL_SEND_CFM_CC;
    } else {
        session->send_requests = 0;
    }
    *len = session->write_idx;
    return result;
}

void
bbl_tx_network_arp_timeout(timer_s *timer)
{
    bbl_network_interface_s *interface = timer->data;
    interface->send_requests |= BBL_IF_SEND_ARP_REQUEST;
}

void
bbl_tx_network_nd_timeout(timer_s *timer)
{
    bbl_network_interface_s *interface = timer->data;
    interface->send_requests |= BBL_IF_SEND_ICMPV6_NS;
}

void
bbl_tx_network_ra_timeout(timer_s *timer)
{
    bbl_network_interface_s *interface = timer->data;
    interface->send_requests |= BBL_IF_SEND_ICMPV6_RA;
}

static protocol_error_t
bbl_tx_encode_network_packet(bbl_network_interface_s *interface, uint8_t *buf, uint16_t *len)
{
    protocol_error_t result = UNKNOWN_PROTOCOL;

    bbl_ethernet_header_s eth = {0};
    bbl_arp_s arp = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_icmpv6_s icmpv6 = {0};
    uint8_t mac[ETH_ADDR_LEN];
    ipv6addr_t ipv6_dst;

    *len = 0;

    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    if(interface->send_requests & BBL_IF_SEND_ARP_REQUEST) {
        interface->send_requests &= ~BBL_IF_SEND_ARP_REQUEST;
        eth.type = ETH_TYPE_ARP;
        eth.next = &arp;
        arp.code = ARP_REQUEST;
        arp.sender = interface->mac;
        arp.sender_ip = interface->ip.address;
        arp.target_ip = interface->gateway;
        if(interface->arp_resolved) {
            timer_add(&g_ctx->timer_root, &interface->timer_arp, "ARP timeout", 
                      300, 0, interface, &bbl_tx_network_arp_timeout);
        } else {
            timer_add(&g_ctx->timer_root, &interface->timer_arp, "ARP timeout", 
                      1, 0, interface, &bbl_tx_network_arp_timeout);
        }
        result = encode_ethernet(buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_ICMPV6_NS) {
        interface->send_requests &= ~BBL_IF_SEND_ICMPV6_NS;
        memcpy(ipv6_dst, interface->gateway6_solicited_node_multicast, IPV6_ADDR_LEN);
        ((uint8_t*)ipv6_dst)[13] = ((uint8_t*)interface->gateway6)[13];
        ((uint8_t*)ipv6_dst)[14] = ((uint8_t*)interface->gateway6)[14];
        ((uint8_t*)ipv6_dst)[15] = ((uint8_t*)interface->gateway6)[15];
        ipv6_multicast_mac(ipv6_dst, mac);
        eth.dst = mac;
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
        ipv6.src = interface->ip6.address;
        ipv6.dst = ipv6_dst;
        ipv6.protocol = IPV6_NEXT_HEADER_ICMPV6;
        ipv6.next = &icmpv6;
        ipv6.ttl = 255;
        icmpv6.type = IPV6_ICMPV6_NEIGHBOR_SOLICITATION;
        memcpy(icmpv6.prefix.address, interface->gateway6, IPV6_ADDR_LEN);
        icmpv6.mac = interface->mac;
        if(interface->icmpv6_nd_resolved) {
            timer_add(&g_ctx->timer_root, &interface->timer_nd, "ND timeout", 
                      300, 0, interface, &bbl_tx_network_nd_timeout);
        } else {
            timer_add(&g_ctx->timer_root, &interface->timer_nd, "ND timeout", 
                      1, 0, interface, &bbl_tx_network_nd_timeout);
        }
        result = encode_ethernet(buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_ICMPV6_RA) {
        interface->send_requests &= ~BBL_IF_SEND_ICMPV6_RA;
        ipv6_multicast_mac(ipv6_multicast_all_nodes, mac);
        eth.dst = mac;
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
        ipv6.src = interface->ip6_ll;
        ipv6.dst = (void*)ipv6_multicast_all_nodes;
        ipv6.protocol = IPV6_NEXT_HEADER_ICMPV6;
        ipv6.next = &icmpv6;
        ipv6.ttl = 255;
        icmpv6.type = IPV6_ICMPV6_ROUTER_ADVERTISEMENT;
        icmpv6.mac = interface->mac;
        timer_add(&g_ctx->timer_root, &interface->timer_ra, "RA timer", 
                  10, 0, interface, &bbl_tx_network_ra_timeout);
        result = encode_ethernet(buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_ISIS_P2P_HELLO) {
        interface->send_requests &= ~BBL_IF_SEND_ISIS_P2P_HELLO;
        result = isis_p2p_hello_encode(interface, buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_ISIS_L1_HELLO) {
        interface->send_requests &= ~BBL_IF_SEND_ISIS_L1_HELLO;
        result = isis_hello_encode(interface, buf, len, &eth, ISIS_LEVEL_1);
    } else if(interface->send_requests & BBL_IF_SEND_ISIS_L2_HELLO) {
        interface->send_requests &= ~BBL_IF_SEND_ISIS_L2_HELLO;
        result = isis_hello_encode(interface, buf, len, &eth, ISIS_LEVEL_2);
    } else if(interface->send_requests & BBL_IF_SEND_LDP_HELLO_IPV6) {
        interface->send_requests &= ~BBL_IF_SEND_LDP_HELLO_IPV6;
        result = ldp_hello_ipv6_encode(interface, buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_LDP_HELLO_IPV4) {
        interface->send_requests &= ~BBL_IF_SEND_LDP_HELLO_IPV4;
        result = ldp_hello_ipv4_encode(interface, buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_OSPFV2_HELLO) {
        interface->send_requests &= ~BBL_IF_SEND_OSPFV2_HELLO;
        result = ospf_hello_v2_encode(interface, buf, len, &eth);
    } else if(interface->send_requests & BBL_IF_SEND_OSPFV3_HELLO) {
        interface->send_requests &= ~BBL_IF_SEND_OSPFV3_HELLO;
        result = ospf_hello_v3_encode(interface, buf, len, &eth);
    } else {
        interface->send_requests = 0;
    }
    if(result == PROTOCOL_SUCCESS) {
        interface->stats.packets_tx++;
        interface->stats.bytes_tx += *len;
    }
    return result;
}

static protocol_error_t
bbl_tx_encode_interface_packet(bbl_interface_s *interface, 
                               uint8_t *buf, uint16_t *len)
{
    protocol_error_t result = UNKNOWN_PROTOCOL;

    bbl_ethernet_header_s eth = {0};
    bbl_lacp_s lacp = {0};
    bbl_lag_member_s *member;

    if(interface->send_requests & BBL_SEND_LACP) {
        interface->send_requests &= ~BBL_SEND_LACP;
        member = interface->lag_member;
        member->stats.lacp_tx++;
        eth.src = interface->mac;
        eth.dst = (uint8_t*)slow_mac;
        eth.type = ETH_TYPE_LACP;
        eth.next = &lacp;
        lacp.actor_system_id = member->actor_system_id;
        lacp.actor_system_priority = member->actor_system_priority;
        lacp.actor_key = member->actor_key;
        lacp.actor_port_priority = member->actor_port_priority;
        lacp.actor_port_id = member->actor_port_id;
        lacp.actor_state = member->actor_state;
        lacp.partner_system_id = member->partner_system_id;
        lacp.partner_system_priority = member->partner_system_priority;
        lacp.partner_key = member->partner_key;
        lacp.partner_port_priority = member->partner_port_priority;
        lacp.partner_port_id = member->partner_port_id;
        lacp.partner_state = member->partner_state;
        result = encode_ethernet(buf, len, &eth);
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
 * @param interface pointer to interface on which packet was received
 * @param buf send buffer where packet can be crafted
 * @param len length of the crafted packet
 */
protocol_error_t
bbl_tx(bbl_interface_s *interface, uint8_t *buf, uint16_t *len)
{
    protocol_error_t result = EMPTY; /* EMPTY means that everything was send */

    bbl_network_interface_s *network_interface;
    bbl_access_interface_s *access_interface;
    bbl_a10nsp_interface_s *a10nsp_interface;
    bbl_session_s *session;
    bbl_l2tp_queue_s *l2tpq;

    if(interface->state == INTERFACE_DISABLED) {
        return EMPTY;
    }

    /* Interface packets like LACP or LLDP. */
    if(interface->send_requests) {
        return bbl_tx_encode_interface_packet(interface, buf, len);
    }

    if(interface->state != INTERFACE_UP) {
        return EMPTY;
    }

    if(interface->type == LAG_MEMBER_INTERFACE) {
        if(interface->lag_member->primary) {
            return bbl_tx(interface->lag->interface, buf, len);
        } else {
            return EMPTY;
        }
    }

    if(interface->access) {
        access_interface = interface->access;
        if(!bbl_txq_is_empty(access_interface->txq)) {
            *len = bbl_txq_from_buffer(access_interface->txq, buf);
            if(*len) {
                access_interface->stats.packets_tx++;
                access_interface->stats.bytes_tx += *len;
                return PROTOCOL_SUCCESS;
            } else {
                return SEND_ERROR;
            }
        }
        /* Session packets. */
        if(!CIRCLEQ_EMPTY(&access_interface->session_tx_qhead)) {
            session = CIRCLEQ_FIRST(&access_interface->session_tx_qhead);
            if(session->send_requests != 0) {
                result = bbl_tx_encode_packet(session, buf, len);
                if(result == PROTOCOL_SUCCESS) {
                    access_interface->stats.packets_tx++;
                    access_interface->stats.bytes_tx += *len;
                    session->stats.packets_tx++;
                    session->stats.bytes_tx += *len;
                }
                /* Remove only from TX queue if all requests are processed! */
                bbl_session_tx_qnode_remove(session);
                if(session->send_requests) {
                    /* Move to the end. */
                    bbl_session_tx_qnode_insert(session);
                }
            } else {
                bbl_session_tx_qnode_remove(session);
            }
            return result;
        }
    } else if(interface->a10nsp) {
        a10nsp_interface = interface->a10nsp;
        if(!bbl_txq_is_empty(a10nsp_interface->txq)) {
            *len = bbl_txq_from_buffer(a10nsp_interface->txq, buf);
            if(*len) {
                a10nsp_interface->stats.packets_tx++;
                a10nsp_interface->stats.bytes_tx += *len;
                return PROTOCOL_SUCCESS;
            } else {
                return SEND_ERROR;
            }
        }
    }

    network_interface = interface->network;
    while(network_interface) {
        /* Network interface packets like ARP. */
        if(network_interface->send_requests) {
            return bbl_tx_encode_network_packet(network_interface, buf, len);
        }
        if(!bbl_txq_is_empty(network_interface->txq)) {
            *len = bbl_txq_from_buffer(network_interface->txq, buf);
            if(*len) {
                network_interface->stats.packets_tx++;
                network_interface->stats.bytes_tx += *len;
                return PROTOCOL_SUCCESS;
            } else {
                return SEND_ERROR;
            }
        }
        /* L2TP packets. */
        if(!CIRCLEQ_EMPTY(&network_interface->l2tp_tx_qhead)) {
            /* Pop element from queue. */
            l2tpq = CIRCLEQ_FIRST(&network_interface->l2tp_tx_qhead);
            CIRCLEQ_REMOVE(&network_interface->l2tp_tx_qhead, l2tpq, tx_qnode);
            CIRCLEQ_NEXT(l2tpq, tx_qnode) = NULL;
            CIRCLEQ_PREV(l2tpq, tx_qnode) = NULL;
            /* Copy packet from queue to ring buffer. */
            memcpy(buf, l2tpq->packet, l2tpq->packet_len);
            *len = l2tpq->packet_len;
            if(l2tpq->data) {
                free(l2tpq);
            }
            network_interface->stats.packets_tx++;
            network_interface->stats.bytes_tx += *len;
            return PROTOCOL_SUCCESS;
        }
        network_interface = network_interface->next;
    }
    return result;
}