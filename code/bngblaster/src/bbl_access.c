/*
 * BNG Blaster (BBL) - Access Functions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_session.h"
#include "bbl_stream.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"
#include "bbl_tx.h"
#include <openssl/md5.h>
#include <openssl/rand.h>

void
bbl_access_interface_rate_job(timer_s *timer)
{
    bbl_access_interface_s *interface = timer->data;
    bbl_compute_avg_rate(&interface->stats.rate_packets_tx, interface->stats.packets_tx);
    bbl_compute_avg_rate(&interface->stats.rate_packets_rx, interface->stats.packets_rx);
    bbl_compute_avg_rate(&interface->stats.rate_bytes_tx, interface->stats.bytes_tx);
    bbl_compute_avg_rate(&interface->stats.rate_bytes_rx, interface->stats.bytes_rx);
    bbl_compute_avg_rate(&interface->stats.rate_mc_rx, interface->stats.mc_rx);
    bbl_compute_avg_rate(&interface->stats.rate_stream_tx, interface->stats.stream_tx);
    bbl_compute_avg_rate(&interface->stats.rate_stream_rx, interface->stats.stream_rx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv4_tx, interface->stats.session_ipv4_tx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv4_rx, interface->stats.session_ipv4_rx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv6_tx, interface->stats.session_ipv6_tx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv6_rx, interface->stats.session_ipv6_rx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv6pd_tx, interface->stats.session_ipv6pd_tx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv6pd_rx, interface->stats.session_ipv6pd_rx);
}

/**
 * bbl_access_interfaces_add
 */
bool
bbl_access_interfaces_add()
{
    bbl_access_config_s *access_config = g_ctx->config.access_config;
    bbl_access_interface_s *access_interface;
    bbl_interface_s *interface;

    char ifname[SUB_STR_LEN];

    while(access_config) {
        interface = bbl_interface_get(access_config->interface);
        if(!interface) {
            LOG(ERROR, "Failed to add access interface %s (interface not found)\n", access_config->interface);
            return false;
        }
        if(!interface->access) {
            snprintf(ifname, sizeof(ifname), "%s", access_config->interface);

            access_interface = calloc(1, sizeof(bbl_access_interface_s));
            interface->access = access_interface;

            CIRCLEQ_INSERT_TAIL(&g_ctx->access_interface_qhead, access_interface, access_interface_qnode);

            /* Init interface */
            access_interface->name = access_config->interface;
            access_interface->interface = interface;
            
            /* Init TXQ */
            access_interface->txq = calloc(1, sizeof(bbl_txq_s));
            bbl_txq_init(access_interface->txq, BBL_TXQ_DEFAULT_SIZE);

            /* Init ethernet */
            memcpy(access_interface->mac, interface->mac, ETH_ADDR_LEN);

            /* TX list init */
            CIRCLEQ_INIT(&access_interface->session_tx_qhead);
            
            /* Timer to compute periodic rates */
            timer_add_periodic(&g_ctx->timer_root, &access_interface->rate_job, "Rate Computation", 1, 0, access_interface,
                               &bbl_access_interface_rate_job);

            LOG(DEBUG, "Added access interface %s\n", access_config->interface);
        }
        access_config->access_interface = interface->access;
        access_config = access_config->next;
    }
    return true;
}

/**
 * bbl_access_interface_get
 *
 * @brief This function returns the access interface
 * with the given name or the first access 
 * interface found if name is NULL.
 *
 * @param interface_name interface name
 * @return a10nsp interface
 */
bbl_access_interface_s*
bbl_access_interface_get(char *interface_name)
{
    struct bbl_interface_ *interface;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(interface_name) {
            if(strcmp(interface->name, interface_name) == 0) {
                return interface->access;
            }
        } else if(interface->access) {
            return interface->access;
        }
    }
    return NULL;
}

static void
bbl_access_update_eth(bbl_session_s *session,
                      bbl_ethernet_header_s *eth)
{
    uint8_t *dst = eth->dst;
    eth->dst = eth->src;
    eth->src = dst;
    eth->mpls = NULL;
    eth->src = session->client_mac;
    eth->qinq = session->access_config->qinq;
    eth->vlan_outer = session->vlan_key.outer_vlan_id;
    eth->vlan_inner = session->vlan_key.inner_vlan_id;
    eth->vlan_three = session->access_third_vlan;
}

static bbl_txq_result_t
bbl_access_icmp_reply(bbl_session_s *session,
                      bbl_ethernet_header_s *eth,
                      bbl_ipv4_s *ipv4,
                      bbl_icmp_s *icmp)
{
    uint32_t dst = ipv4->dst;
    bbl_access_update_eth(session, eth);
    ipv4->dst = ipv4->src;
    ipv4->src = dst;
    ipv4->ttl = 64;
    icmp->type = ICMP_TYPE_ECHO_REPLY;
    return bbl_txq_to_buffer(session->access_interface->txq, eth);
}

static bbl_txq_result_t
bbl_access_icmpv6_na(bbl_session_s *session,
                     bbl_ethernet_header_s *eth,
                     bbl_ipv6_s *ipv6,
                     bbl_icmpv6_s *icmpv6)
{
    bbl_access_update_eth(session, eth);
    ipv6->dst = ipv6->src;
    ipv6->src = icmpv6->prefix.address;
    ipv6->ttl = 255;
    icmpv6->type = IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT;
    icmpv6->mac = session->client_mac;
    icmpv6->flags = 0;
    icmpv6->data = NULL;
    icmpv6->data_len = 0;
    icmpv6->dns1 = NULL;
    icmpv6->dns2 = NULL;
    return bbl_txq_to_buffer(session->access_interface->txq, eth);
}

static bbl_txq_result_t
bbl_access_icmpv6_echo_reply(bbl_session_s *session,
                             bbl_ethernet_header_s *eth,
                             bbl_ipv6_s *ipv6,
                             bbl_icmpv6_s *icmpv6)
{
    uint8_t *dst = ipv6->dst;
    bbl_access_update_eth(session, eth);
    ipv6->dst = ipv6->src;
    ipv6->src = dst;
    ipv6->ttl = 255;
    icmpv6->type = IPV6_ICMPV6_ECHO_REPLY;
    return bbl_txq_to_buffer(session->access_interface->txq, eth);
}

void
bbl_access_igmp_zapping(timer_s *timer)
{
    bbl_session_s *session = timer->data;

    uint32_t next_group;
    bbl_igmp_group_s *group;

    uint32_t join_delay = 0;
    uint32_t leave_delay = 0;
    struct timespec time_diff;
    struct timespec time_now;

    uint32_t ms;

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

    if(!session->zapping_joined_group || !session->zapping_leaved_group) {
        return;
    }

    if(session->zapping_view_start_time.tv_sec) {
        clock_gettime(CLOCK_MONOTONIC, &time_now);
        timespec_sub(&time_diff, &time_now, &session->zapping_view_start_time);
        if(time_diff.tv_sec >= g_ctx->config.igmp_zap_view_duration) {
            session->zapping_view_start_time.tv_sec = 0;
            session->zapping_count = 0;
        } else {
            return;
        }
    }

    /* Calculate last join delay... */
    group = session->zapping_joined_group;
    if(group->first_mc_rx_time.tv_sec) {
        if(!group->zapping_result) {
            group->zapping_result = true;
            timespec_sub(&time_diff, &group->first_mc_rx_time, &group->join_tx_time);
            ms = time_diff.tv_nsec / 1000000; /* convert nanoseconds to milliseconds */
            if(time_diff.tv_nsec % 1000000) ms++; /* simple roundup function */
            join_delay = (time_diff.tv_sec * 1000) + ms;
            if(!join_delay) join_delay = 1; /* join delay must be at least one millisecond */
            session->zapping_join_delay_sum += join_delay;
            session->zapping_join_count++;
            if(join_delay > session->stats.max_join_delay) session->stats.max_join_delay = join_delay;
            if(session->stats.min_join_delay) {
                if(join_delay < session->stats.min_join_delay) session->stats.min_join_delay = join_delay;
            } else {
                session->stats.min_join_delay = join_delay;
            }
            session->stats.avg_join_delay = session->zapping_join_delay_sum / session->zapping_join_count;
            
            if(g_ctx->config.igmp_max_join_delay && join_delay > g_ctx->config.igmp_max_join_delay) {
                session->stats.join_delay_violations++;
            }

            if(join_delay > 2000) {
                session->stats.join_delay_violations_2s++;
            } else if(join_delay > 1000) {
                session->stats.join_delay_violations_1s++;
            } else if(join_delay > 500) {
                session->stats.join_delay_violations_500ms++;
            } else if(join_delay > 250) {
                session->stats.join_delay_violations_250ms++;
            } else if(join_delay > 125) {
                session->stats.join_delay_violations_125ms++;
            }

            LOG(IGMP, "IGMP (ID: %u) ZAPPING %u ms join delay for group %s\n",
                session->session_id, join_delay, format_ipv4_address(&group->group));
        }
    } else {
        if(g_ctx->config.igmp_zap_wait) {
            /* Wait until MC traffic is received ... */
            return;
        } else {
            group->zapping_result = true;
            session->stats.mc_not_received++;
            LOG(IGMP, "IGMP (ID: %u) ZAPPING join failed for group %s\n",
                session->session_id, format_ipv4_address(&group->group));
        }
    }

    if(!g_ctx->zapping && group->state < IGMP_GROUP_ACTIVE) {
        return;
    }

    /* Select next group to be joined ... */
    next_group = be32toh(group->group) + be32toh(g_ctx->config.igmp_group_iter);
    if(next_group > session->zapping_group_max) {
        next_group = g_ctx->config.igmp_group;
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
        ms = time_diff.tv_nsec / 1000000; /* convert nanoseconds to milliseconds */
        if(time_diff.tv_nsec % 1000000) ms++; /* simple roundup function */
        leave_delay = (time_diff.tv_sec * 1000) + ms;
        if(!leave_delay) leave_delay = 1; /* leave delay must be at least one millisecond */
        session->zapping_leave_delay_sum += leave_delay;
        session->zapping_leave_count++;
        if(leave_delay > session->stats.max_leave_delay) session->stats.max_leave_delay = leave_delay;
        if(session->stats.min_leave_delay) {
            if(leave_delay < session->stats.min_leave_delay) session->stats.min_leave_delay = leave_delay;
        } else {
            session->stats.min_leave_delay = leave_delay;
        }
        session->stats.avg_leave_delay = session->zapping_leave_delay_sum / session->zapping_leave_count;

        LOG(IGMP, "IGMP (ID: %u) ZAPPING %u ms leave delay for group %s\n",
            session->session_id, leave_delay, format_ipv4_address(&group->group));
    }

    if(g_ctx->zapping) {
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
        group->zapping_result = false;

        /* Swap join/leave */
        session->zapping_leaved_group = session->zapping_joined_group;
        session->zapping_joined_group = group;

        LOG(IGMP, "IGMP (ID: %u) ZAPPING leave %s join %s\n",
            session->session_id,
            format_ipv4_address(&session->zapping_leaved_group->group),
            format_ipv4_address(&session->zapping_joined_group->group));
    } else {
        /* Zapping has stopped */
        group->last_mc_rx_time.tv_sec = 0;
        group->leave_tx_time.tv_sec = 0;
        LOG(IGMP, "IGMP (ID: %u) ZAPPING leave %s\n",
            session->session_id,
            format_ipv4_address(&session->zapping_joined_group->group));
    }

    session->send_requests |= BBL_SEND_IGMP;
    bbl_session_tx_qnode_insert(session);


    /* Handle viewing profile */
    session->zapping_count++;
    if(g_ctx->config.igmp_zap_count && g_ctx->config.igmp_zap_view_duration) {
        if(session->zapping_count >= g_ctx->config.igmp_zap_count) {
            clock_gettime(CLOCK_MONOTONIC, &session->zapping_view_start_time);
        }
    }
}

void
bbl_access_igmp_initial_join(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    uint32_t initial_group;
    bbl_igmp_group_s *group;

    int group_start_index = 0;

    if(session->session_state != BBL_ESTABLISHED ||
       (session->access_type == ACCESS_TYPE_PPPOE && 
        session->ipcp_state != BBL_PPP_OPENED)) {
        return;
    }

    /* Get initial group */
    if(g_ctx->config.igmp_group_count > 1) {
        group_start_index = rand() % g_ctx->config.igmp_group_count;
    }
    initial_group = htobe32(be32toh(g_ctx->config.igmp_group) + (group_start_index * be32toh(g_ctx->config.igmp_group_iter)));

    group = &session->igmp_groups[0];
    memset(group, 0x0, sizeof(bbl_igmp_group_s));
    group->group = initial_group;
    group->source[0] = g_ctx->config.igmp_source;
    group->robustness_count = session->igmp_robustness;
    group->state = IGMP_GROUP_JOINING;
    group->send = true;
    session->zapping_count = 1;
    session->send_requests |= BBL_SEND_IGMP;
    bbl_session_tx_qnode_insert(session);

    LOG(IGMP, "IGMP (ID: %u) initial join for group %s\n",
        session->session_id, format_ipv4_address(&group->group));

    if(g_ctx->config.igmp_group_count > 1 && g_ctx->config.igmp_zap_interval > 0) {
        /* Start/Init Zapping Logic ... */
        group->zapping = true;
        session->zapping_joined_group = group;
        group = &session->igmp_groups[1];
        session->zapping_leaved_group = group;
        memset(group, 0x0, sizeof(bbl_igmp_group_s));
        group->zapping = true;
        group->source[0] = g_ctx->config.igmp_source;

        if(g_ctx->config.igmp_zap_count && g_ctx->config.igmp_zap_view_duration) {
            session->zapping_count = rand() % g_ctx->config.igmp_zap_count;
        }

        /* Adding 2 nanoseconds to enforce a dedicated timer bucket for zapping. */
        timer_add_periodic(&g_ctx->timer_root, &session->timer_zapping, "IGMP Zapping", g_ctx->config.igmp_zap_interval, 2, session, &bbl_access_igmp_zapping);
        LOG(IGMP, "IGMP (ID: %u) ZAPPING start zapping with interval %u\n",
            session->session_id, g_ctx->config.igmp_zap_interval);

        timer_smear_bucket(&g_ctx->timer_root, g_ctx->config.igmp_zap_interval, 2);
    }
}

static void
bbl_access_rx_udp_ipv6(bbl_access_interface_s *interface, 
                       bbl_session_s *session,
                       bbl_ethernet_header_s *eth, bbl_ipv6_s *ipv6)
{
    bbl_udp_s *udp = (bbl_udp_s*)ipv6->next;

    switch(udp->dst) {
        case DHCPV6_UDP_CLIENT:
        case DHCPV6_UDP_SERVER:
            interface->stats.dhcpv6_rx++;
            session->stats.dhcpv6_rx++;
            bbl_dhcpv6_rx(session, eth, (bbl_dhcpv6_s*)udp->next);
            return;
        default:
            session->stats.accounting_packets_rx++;
            session->stats.accounting_bytes_rx += eth->length;
            break;
    }
}

/**
 * bbl_access_rx_established_ipoe
 * 
 * @param interface receiving interface
 * @param session corresponding session
 * @param eth received packet
 */
void
bbl_access_rx_established_ipoe(bbl_access_interface_s *interface, 
                               bbl_session_s *session, bbl_ethernet_header_s *eth)
{
    bool ipv4 = true;
    bool ipv6 = true;

    UNUSED(interface);

    if(session->access_config->ipv4_enable) {
        if(!session->arp_resolved ||
           (session->dhcp_state > BBL_DHCP_DISABLED && session->dhcp_state < BBL_DHCP_BOUND)) {
            ipv4 = false;
        } else {
            if(session->ip_address) {
                ACTIVATE_ENDPOINT(session->endpoint.ipv4);
            }
        }
    }
    if(session->access_config->ipv6_enable) {
        if(!session->icmpv6_ra_received ||
           (session->dhcpv6_state > BBL_DHCP_DISABLED && session->dhcpv6_state < BBL_DHCP_BOUND)) {
            ipv6 = false;
        } else {
            if(*(uint64_t*)&session->ipv6_address) {
                ACTIVATE_ENDPOINT(session->endpoint.ipv6);
            }
            if(*(uint64_t*)&session->delegated_ipv6_address) {
                ACTIVATE_ENDPOINT(session->endpoint.ipv6pd);
            }
        }
    }

    if(ipv4 && ipv6) {
        if(session->session_state != BBL_ESTABLISHED) {
            if(g_ctx->sessions_established_max < g_ctx->sessions) {
                g_ctx->stats.last_session_established.tv_sec = eth->timestamp.tv_sec;
                g_ctx->stats.last_session_established.tv_nsec = eth->timestamp.tv_nsec;
            }
            bbl_session_update_state(session, BBL_ESTABLISHED);
            if(session->access_config->ipv4_enable) {
                if(g_ctx->config.igmp_group && g_ctx->config.igmp_autostart && g_ctx->config.igmp_start_delay) {
                    /* Start IGMP */
                    timer_add(&g_ctx->timer_root, &session->timer_igmp, "IGMP", g_ctx->config.igmp_start_delay, 0, session, &bbl_access_igmp_initial_join);
                }
            }
        }
    }
}

static void
bbl_access_rx_icmpv6(bbl_access_interface_s *interface, 
                     bbl_session_s *session, 
                     bbl_ethernet_header_s *eth, bbl_ipv6_s *ipv6)
{
    bbl_icmpv6_s *icmpv6 = (bbl_icmpv6_s*)ipv6->next;

    session->stats.icmpv6_rx++;

    if(session->access_type == ACCESS_TYPE_PPPOE &&
       session->ip6cp_state != BBL_PPP_OPENED) {
        return;
    }

    if(icmpv6->type == IPV6_ICMPV6_ROUTER_ADVERTISEMENT) {
        if(!session->icmpv6_ra_received) {
            /* The first RA received ... */
            session->icmpv6_ra_received = true;
            if(icmpv6->prefix.len) {
                memcpy(&session->ipv6_prefix, &icmpv6->prefix, sizeof(ipv6_prefix));
                *(uint64_t*)&session->ipv6_address[0] = *(uint64_t*)session->ipv6_prefix.address;
                *(uint64_t*)&session->ipv6_address[8] = session->ip6cp_ipv6_identifier;
                if(session->access_type == ACCESS_TYPE_PPPOE) {
                    ACTIVATE_ENDPOINT(session->endpoint.ipv6);
                }
                LOG(IP, "IPv6 (ID: %u) ICMPv6 RA prefix %s/%d\n",
                    session->session_id, format_ipv6_address(&session->ipv6_prefix.address), session->ipv6_prefix.len);
                if(icmpv6->dns1) {
                    memcpy(&session->ipv6_dns1, icmpv6->dns1, IPV6_ADDR_LEN);
                    if(icmpv6->dns2) {
                        memcpy(&session->ipv6_dns2, icmpv6->dns2, IPV6_ADDR_LEN);
                    }
                }
            }
            if(session->access_type == ACCESS_TYPE_IPOE) {
                if(!session->arp_resolved) {
                    memcpy(session->server_mac, eth->src, ETH_ADDR_LEN);
                }
                bbl_access_rx_established_ipoe(interface, session, eth);
            } else if(session->dhcpv6_state > BBL_DHCP_DISABLED && 
                      (icmpv6->flags & ICMPV6_FLAGS_MANAGED ||
                       icmpv6->flags & ICMPV6_FLAGS_OTHER_CONFIG)) {
                bbl_dhcpv6_start(session);
                bbl_session_tx_qnode_insert(session);
            }
        }
    } else if(icmpv6->type == IPV6_ICMPV6_NEIGHBOR_SOLICITATION) {
        if(memcmp(icmpv6->prefix.address, session->ipv6_address, IPV6_ADDR_LEN) == 0) {
            bbl_access_icmpv6_na(session, eth, ipv6, icmpv6);
        } else if(memcmp(icmpv6->prefix.address, session->link_local_ipv6_address, IPV6_ADDR_LEN) == 0) {
            bbl_access_icmpv6_na(session, eth, ipv6, icmpv6);
        }
    } else if(icmpv6->type == IPV6_ICMPV6_ECHO_REQUEST) {
        bbl_access_icmpv6_echo_reply(session, eth, ipv6, icmpv6);
    }
}

static void
bbl_access_rx_icmp(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4)
{
    bbl_icmp_s *icmp = (bbl_icmp_s*)ipv4->next;
    if(session->ip_address &&
       session->ip_address == ipv4->dst &&
       icmp->type == ICMP_TYPE_ECHO_REQUEST) {
        /* Send ICMP reply... */
        bbl_access_icmp_reply(session, eth, ipv4, icmp);
    }
}

static void
bbl_access_rx_ipv4_mc(bbl_access_interface_s *interface, 
                      bbl_session_s *session, 
                      bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4)
{
    bbl_bbl_s *bbl = eth->bbl;
    bbl_igmp_group_s *group = NULL;
    uint64_t loss;
    int i;

    for(i=0; i < IGMP_MAX_GROUPS; i++) {
        group = &session->igmp_groups[i];
        if(ipv4->dst == group->group) {
            group->packets++;
            group->last_mc_rx_time.tv_sec = eth->timestamp.tv_sec;
            group->last_mc_rx_time.tv_nsec = eth->timestamp.tv_nsec;
            if(group->state >= IGMP_GROUP_ACTIVE) {
                if(!group->first_mc_rx_time.tv_sec) {
                    group->first_mc_rx_time.tv_sec = eth->timestamp.tv_sec;
                    group->first_mc_rx_time.tv_nsec = eth->timestamp.tv_nsec;
                    if(bbl) {
                        session->mc_rx_last_seq = bbl->flow_seq;
                    }
                } else if(bbl) {
                    if((session->mc_rx_last_seq +1) < bbl->flow_seq) {
                        loss = bbl->flow_seq - (session->mc_rx_last_seq +1);
                        interface->stats.mc_loss += loss;
                        session->stats.mc_loss += loss;
                        group->loss += loss;
                        LOG(LOSS, "LOSS (ID: %u) Multicast flow: %lu seq: %lu last: %lu\n",
                            session->session_id, bbl->flow_id, bbl->flow_seq, session->mc_rx_last_seq);
                    }
                    session->mc_rx_last_seq = bbl->flow_seq;
                }
            } else {
                if(session->zapping_joined_group && (session->zapping_leaved_group == group)) {
                    if(session->zapping_joined_group->first_mc_rx_time.tv_sec) {
                        session->stats.mc_old_rx_after_first_new++;
                    }
                }
            }
        }
    }
}

static void
bbl_access_rx_ipv4(bbl_access_interface_s *interface, 
                   bbl_session_s *session, 
                   bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4) 
{
    bbl_udp_s *udp;

    if(ipv4->offset & ~IPV4_DF) {
        /* Reassembling of fragmented IPv4 packets is currently not supported. */
        session->stats.accounting_packets_rx++;
        session->stats.accounting_bytes_rx += eth->length;
        session->stats.ipv4_fragmented_rx++;
        interface->stats.ipv4_fragmented_rx++;
        return;
    }

    switch(ipv4->protocol) {
        case PROTOCOL_IPV4_IGMP:
            session->stats.igmp_rx++;
            interface->stats.igmp_rx++;
            bbl_igmp_rx(session, ipv4);
            return;
        case PROTOCOL_IPV4_ICMP:
            session->stats.icmp_rx++;
            interface->stats.icmp_rx++;
            bbl_access_rx_icmp(session, eth, ipv4);
            return;
        case PROTOCOL_IPV4_UDP:
            udp = (bbl_udp_s*)ipv4->next;
            if(udp->protocol == UDP_PROTOCOL_DHCP) {
                session->stats.dhcp_rx++;
                interface->stats.dhcp_rx++;
                bbl_dhcp_rx(session, eth, (bbl_dhcp_s*)udp->next);
                return;
            }
            break;
        default:
            break;
    }

    session->stats.accounting_packets_rx++;
    session->stats.accounting_bytes_rx += eth->length;

    /* All IPv4 multicast addresses start with 1110 */
    if((ipv4->dst & htobe32(0xf0000000)) == htobe32(0xe0000000)) {
        interface->stats.mc_rx++;
        session->stats.mc_rx++;
        bbl_access_rx_ipv4_mc(interface, session, eth, ipv4);
        return;
    }
}

static void
bbl_access_rx_ipv6(bbl_access_interface_s *interface, 
                   bbl_session_s *session,
                   bbl_ethernet_header_s *eth, bbl_ipv6_s *ipv6)
{
    switch(ipv6->protocol) {
        case IPV6_NEXT_HEADER_ICMPV6:
            interface->stats.icmpv6_rx++;
            bbl_access_rx_icmpv6(interface, session, eth, ipv6);
            return;
        case IPV6_NEXT_HEADER_UDP:
            bbl_access_rx_udp_ipv6(interface, session, eth, ipv6);
            return;
        default:
            break;
    }
    session->stats.accounting_packets_rx++;
    session->stats.accounting_bytes_rx += eth->length;
}

static void
bbl_access_rx_pap(bbl_access_interface_s *interface,
                  bbl_session_s *session, 
                  bbl_ethernet_header_s *eth)
{
    bbl_pppoe_session_s *pppoes;
    bbl_pap_s *pap;

    char substring[16];
    char *tok;
    char *save = NULL;

    l2tp_key_t key = {0};
    void **search = NULL;

    pppoes = (bbl_pppoe_session_s*)eth->next;
    pap = (bbl_pap_s*)pppoes->next;

    UNUSED(interface);

    if(session->session_state == BBL_PPP_AUTH) {
        switch(pap->code) {
            case PAP_CODE_ACK:
                if(pap->reply_message_len > 23) {
                    if(strncmp(pap->reply_message, L2TP_REPLY_MESSAGE, 20) == 0) {
                        session->l2tp = true;
                        memset(substring, 0x0, sizeof(substring));
                        memcpy(substring, pap->reply_message+21, pap->reply_message_len-21);
                        tok = strtok_r(substring, ":", &save);
                        if(tok) {
                            key.tunnel_id = atoi(tok);
                            tok = strtok_r(0, ":", &save);
                            if(tok) {
                                key.session_id = atoi(tok);
                                search = dict_search(g_ctx->l2tp_session_dict, &key);
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
                if(pap->reply_message_len) {
                    if(session->reply_message) {
                        free(session->reply_message);
                    }
                    session->reply_message = malloc(pap->reply_message_len+1);
                    memcpy(session->reply_message, pap->reply_message, pap->reply_message_len);
                    session->reply_message[pap->reply_message_len] = 0;
                }
                bbl_session_update_state(session, BBL_PPP_NETWORK);
                if(session->access_config->ipcp_enable) {
                    session->ipcp_state = BBL_PPP_INIT;
                    session->ipcp_request_code = PPP_CODE_CONF_REQUEST;
                    session->send_requests |= BBL_SEND_IPCP_REQUEST;
                    session->send_requests &= ~BBL_SEND_IPCP_RESPONSE;
                }
                if(session->access_config->ip6cp_enable) {
                    session->ip6cp_state = BBL_PPP_INIT;
                    session->ip6cp_request_code = PPP_CODE_CONF_REQUEST;
                    session->send_requests |= BBL_SEND_IP6CP_REQUEST;
                    session->send_requests &= ~BBL_SEND_IP6CP_RESPONSE;
                }
                bbl_session_tx_qnode_insert(session);
                break;
            default:
                bbl_session_update_state(session, BBL_PPP_TERMINATING);
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->lcp_options_len = 0;
                session->lcp_state = BBL_PPP_TERMINATE;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
        }
    }
}

static void
bbl_access_rx_chap(bbl_access_interface_s *interface,
                   bbl_session_s *session, 
                   bbl_ethernet_header_s *eth)
{
    bbl_pppoe_session_s *pppoes;
    bbl_chap_s *chap;

    MD5_CTX md5_ctx;

    char substring[16];
    char *tok;
    char *save = NULL;

    l2tp_key_t key = {0};
    void **search = NULL;

    UNUSED(interface);

    pppoes = (bbl_pppoe_session_s*)eth->next;
    chap = (bbl_chap_s*)pppoes->next;

    if(session->session_state == BBL_PPP_AUTH) {
        switch(chap->code) {
            case CHAP_CODE_CHALLENGE:
                if(chap->challenge_len == 0) {
                    /* TODO: Add support for variable CHAP challenge lengths. */
                    LOG(PPPOE, "CHAP (ID: %u) CHAP challenge length must be greater than 0\n", session->session_id);
                    bbl_session_update_state(session, BBL_PPP_TERMINATING);
                    session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                    session->lcp_options_len = 0;
                    session->lcp_state = BBL_PPP_TERMINATE;
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
                        tok = strtok_r(substring, ":", &save);
                        if(tok) {
                            key.tunnel_id = atoi(tok);
                            tok = strtok_r(0, ":", &save);
                            if(tok) {
                                key.session_id = atoi(tok);
                                search = dict_search(g_ctx->l2tp_session_dict, &key);
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
                if(chap->reply_message_len) {
                    if(session->reply_message) {
                        free(session->reply_message);
                    }
                    session->reply_message = malloc(chap->reply_message_len+1);
                    memcpy(session->reply_message, chap->reply_message, chap->reply_message_len);
                    session->reply_message[chap->reply_message_len] = 0;
                }
                bbl_session_update_state(session, BBL_PPP_NETWORK);
                if(session->access_config->ipcp_enable) {
                    session->ipcp_state = BBL_PPP_INIT;
                    session->ipcp_request_code = PPP_CODE_CONF_REQUEST;
                    session->send_requests |= BBL_SEND_IPCP_REQUEST;
                    session->send_requests &= ~BBL_SEND_IPCP_RESPONSE;
                }
                if(session->access_config->ip6cp_enable) {
                    session->ip6cp_state = BBL_PPP_INIT;
                    session->ip6cp_request_code = PPP_CODE_CONF_REQUEST;
                    session->send_requests |= BBL_SEND_IP6CP_REQUEST;
                    session->send_requests &= ~BBL_SEND_IP6CP_RESPONSE;
                }
                bbl_session_tx_qnode_insert(session);
                break;
            default:
                bbl_session_update_state(session, BBL_PPP_TERMINATING);
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->lcp_options_len = 0;
                session->lcp_state = BBL_PPP_TERMINATE;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
        }
    }
}

void
bbl_access_session_timeout(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_ESTABLISHED) {
        bbl_session_clear(session);
    }
}

void
bbl_access_lcp_echo(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    bbl_access_interface_s *interface = session->access_interface;

    if(session->session_state == BBL_ESTABLISHED) {
        if(session->lcp_retries) {
            interface->stats.lcp_echo_timeout++;
        }
        if(session->lcp_retries > g_ctx->config.lcp_keepalive_retry) {
            LOG(PPPOE, "LCP ECHO TIMEOUT (ID: %u)\n", session->session_id);
            /* Force terminate session after timeout. */
            session->lcp_state = BBL_PPP_CLOSED;
            if(session->ipcp_state > BBL_PPP_DISABLED) {
                session->ipcp_state = BBL_PPP_CLOSED;
            }
            if(session->ip6cp_state > BBL_PPP_DISABLED) {
                session->ip6cp_state = BBL_PPP_CLOSED;
            }
            session->send_requests = BBL_SEND_DISCOVERY;
            bbl_session_update_state(session, BBL_TERMINATING);
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

static bool
bbl_access_ncp_success(uint8_t state)
{
    switch(state) {
        case BBL_PPP_DISABLED:
        case BBL_PPP_REJECTED:
        case BBL_PPP_OPENED:
            return true;
        default:
            return false;
    }
}

/**
 * bbl_access_rx_established_pppoe
 * 
 * @param interface receiving interface
 * @param session corresponding session
 * @param eth received packet
 */
void
bbl_access_rx_established_pppoe(bbl_access_interface_s *interface, 
                                bbl_session_s *session, 
                                bbl_ethernet_header_s *eth)
{
    UNUSED(interface);

    bool ipcp = bbl_access_ncp_success(session->ipcp_state);
    bool ip6cp = bbl_access_ncp_success(session->ip6cp_state);

    if(ipcp && ip6cp) {
        if(session->session_state != BBL_ESTABLISHED) {
            if(g_ctx->sessions_established_max < g_ctx->sessions) {
                g_ctx->stats.last_session_established.tv_sec = eth->timestamp.tv_sec;
                g_ctx->stats.last_session_established.tv_nsec = eth->timestamp.tv_nsec;
            }
            bbl_session_update_state(session, BBL_ESTABLISHED);
            if(g_ctx->config.lcp_keepalive_interval) {
                /* Start LCP echo request / keep alive */
                timer_add_periodic(&g_ctx->timer_root, &session->timer_lcp_echo, "LCP ECHO", g_ctx->config.lcp_keepalive_interval, 1, session, &bbl_access_lcp_echo);
            }
            if(g_ctx->config.pppoe_session_time) {
                /* Start Session Timer */
                timer_add(&g_ctx->timer_root, &session->timer_session, "Session", g_ctx->config.pppoe_session_time, 0, session, &bbl_access_session_timeout);
            }
            if(session->ipcp_state == BBL_PPP_OPENED) {
                if(session->l2tp == false && !session->a10nsp_session &&
                   g_ctx->config.igmp_group && 
                   g_ctx->config.igmp_autostart && 
                   g_ctx->config.igmp_start_delay) {
                    /* Start IGMP */
                    timer_add(&g_ctx->timer_root, &session->timer_igmp, "IGMP", g_ctx->config.igmp_start_delay, 0, session, &bbl_access_igmp_initial_join);
                }
            }
        }
    }
}

static void
bbl_access_rx_ip6cp(bbl_access_interface_s *interface, 
                    bbl_session_s *session,
                    bbl_ethernet_header_s *eth)
{
    bbl_pppoe_session_s *pppoes;
    bbl_ip6cp_s *ip6cp;

    if(session->lcp_state != BBL_PPP_OPENED) {
        return;
    }

    if(!g_ctx->config.ip6cp_enable) {
        /* Protocol Reject */
        *(uint16_t*)session->lcp_options = htobe16(PROTOCOL_IP6CP);
        session->lcp_options_len = 2;
        session->lcp_peer_identifier = ++session->lcp_identifier;
        session->lcp_response_code = PPP_CODE_PROT_REJECT;
        session->send_requests |= BBL_SEND_LCP_RESPONSE;
        bbl_session_tx_qnode_insert(session);
        return;
    }

    pppoes = (bbl_pppoe_session_s*)eth->next;
    ip6cp = (bbl_ip6cp_s*)pppoes->next;

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
                    bbl_access_rx_established_pppoe(interface, session, eth);
                    session->link_local_ipv6_address[0] = 0xfe;
                    session->link_local_ipv6_address[1] = 0x80;
                    *(uint64_t*)&session->link_local_ipv6_address[8] = session->ip6cp_ipv6_identifier;
                    if(session->l2tp == false) {
                        session->send_requests |= BBL_SEND_ICMPV6_RS;
                        bbl_session_tx_qnode_insert(session);
                    }
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
            session->ip6cp_request_code = PPP_CODE_CONF_REQUEST;
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
                    bbl_access_rx_established_pppoe(interface, session, eth);
                    session->link_local_ipv6_address[0] = 0xfe;
                    session->link_local_ipv6_address[1] = 0x80;
                    *(uint64_t*)&session->link_local_ipv6_address[8] = session->ip6cp_ipv6_identifier;
                    if(session->l2tp == false) {
                        session->send_requests |= BBL_SEND_ICMPV6_RS;
                        bbl_session_tx_qnode_insert(session);
                    }
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

static void
bbl_access_rx_ipcp(bbl_access_interface_s *interface, 
                   bbl_session_s *session, 
                   bbl_ethernet_header_s *eth)
{
    bbl_pppoe_session_s *pppoes;
    bbl_ipcp_s *ipcp;

    if(session->lcp_state != BBL_PPP_OPENED) {
        return;
    }

    if(!g_ctx->config.ipcp_enable) {
        /* Protocol Reject */
        *(uint16_t*)session->lcp_options = htobe16(PROTOCOL_IPCP);
        session->lcp_options_len = 2;
        session->lcp_peer_identifier = ++session->lcp_identifier;
        session->lcp_response_code = PPP_CODE_PROT_REJECT;
        session->send_requests |= BBL_SEND_LCP_RESPONSE;
        bbl_session_tx_qnode_insert(session);
        return;
    }

    pppoes = (bbl_pppoe_session_s*)eth->next;
    ipcp = (bbl_ipcp_s*)pppoes->next;

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
                    bbl_access_rx_established_pppoe(interface, session, eth);
                    ACTIVATE_ENDPOINT(session->endpoint.ipv4);
                    LOG(IP, "IPv4 (ID: %u) address %s\n", session->session_id, 
                        format_ipv4_address(&session->ip_address));
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
                    bbl_access_rx_established_pppoe(interface, session, eth);
                    ACTIVATE_ENDPOINT(session->endpoint.ipv4);
                    LOG(IP, "IPv4 (ID: %u) address %s\n", session->session_id,
                        format_ipv4_address(&session->ip_address));
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

/**
 * bbl_access_rx_lcp_conf_reject
 * 
 * This function rejects all unknown LCP configuration
 * options by sending LCP conf-reject.  
 * 
 * @param session corresponding session
 * @param lcp received LCP packet
 */
static void
bbl_access_rx_lcp_conf_reject(bbl_session_s *session, bbl_lcp_s *lcp)
{
    uint8_t type;
    uint8_t len;
    session->lcp_options_len = 0;

    for(int i=0; i < PPP_MAX_OPTIONS; i++) {
        if(lcp->option[i]) {
            type = lcp->option[i][0];
            len = lcp->option[i][1];
            switch(type) {
                case PPP_LCP_OPTION_MRU:
                case PPP_LCP_OPTION_AUTH:
                case PPP_LCP_OPTION_MAGIC:
                    break;
                default:
                    if((session->lcp_options_len + len) <= PPP_OPTIONS_BUFFER) {                        
                        memcpy(&session->lcp_options[session->lcp_options_len], lcp->option[i], len);
                        session->lcp_options_len += len;
                    }
                    break;
            }
        }
    }
    session->lcp_peer_identifier = lcp->identifier;
    session->lcp_response_code = PPP_CODE_CONF_REJECT;
    session->send_requests |= BBL_SEND_LCP_RESPONSE;
    bbl_session_tx_qnode_insert(session);
    return;
}

static void
bbl_access_rx_lcp(bbl_access_interface_s *interface,
                  bbl_session_s *session, 
                  bbl_ethernet_header_s *eth)
{
    bbl_pppoe_session_s *pppoes;
    bbl_lcp_s *lcp;

    UNUSED(interface);

    pppoes = (bbl_pppoe_session_s*)eth->next;
    lcp = (bbl_lcp_s*)pppoes->next;

    if(session->session_state < BBL_PPP_LINK) {
        return;
    }

    if(session->session_state == BBL_PPP_TERMINATING && 
       !(lcp->code == PPP_CODE_TERM_REQUEST || lcp->code == PPP_CODE_TERM_ACK)) {
        /* Only term-request/ack is accepted in terminating phase */
        return;
    }

    switch(lcp->code) {
        case PPP_CODE_VENDOR_SPECIFIC:
            if(g_ctx->config.lcp_vendor_ignore) {
                return;
            }
            if(g_ctx->config.lcp_connection_status_message &&
               lcp->vendor_kind == 1 && lcp->vendor_value_len > 2) {
                /* Skip the 2 byte option header (type, length) */
                lcp->vendor_value_len -= 2;
                lcp->vendor_value += 2;
                if(session->connections_status_message) {
                    free(session->connections_status_message);
                }
                session->connections_status_message = malloc(lcp->vendor_value_len+1);
                memcpy(session->connections_status_message, lcp->vendor_value, lcp->vendor_value_len);
                session->connections_status_message[lcp->vendor_value_len] = 0;
                session->lcp_response_code = PPP_CODE_VENDOR_SPECIFIC;
                *(uint32_t*)session->lcp_options = session->magic_number;
                memcpy(session->lcp_options+sizeof(uint32_t), lcp->vendor_oui, OUI_LEN);
                session->lcp_options[7] = 2;
                session->lcp_options_len = 8;
            } else {
                session->lcp_response_code = PPP_CODE_CODE_REJECT;
                if(lcp->len > PPP_OPTIONS_BUFFER) {
                    memcpy(session->lcp_options, lcp->start, PPP_OPTIONS_BUFFER);
                    session->lcp_options_len = PPP_OPTIONS_BUFFER;
                } else {
                    memcpy(session->lcp_options, lcp->start, lcp->len);
                    session->lcp_options_len = lcp->len;
                }
            }
            session->lcp_peer_identifier = lcp->identifier;
            session->send_requests |= BBL_SEND_LCP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_CONF_REQUEST:
            if(lcp->unknown_options) {
                bbl_access_rx_lcp_conf_reject(session, lcp);
                return;
            }
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
                session->peer_mru = lcp->mru;
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
                    bbl_session_update_state(session, BBL_PPP_AUTH);
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
                    bbl_session_update_state(session, BBL_PPP_AUTH);
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
            session->lcp_peer_identifier = lcp->identifier;
            session->lcp_response_code = PPP_CODE_TERM_ACK;
            session->lcp_options_len = 0;
            session->lcp_state = BBL_PPP_TERMINATE;
            session->send_requests = BBL_SEND_LCP_RESPONSE;
            if(session->session_state != BBL_PPP_TERMINATING) {
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
            }
            bbl_session_update_state(session, BBL_PPP_TERMINATING);
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_TERM_ACK:
            session->lcp_retries = 0;
            session->lcp_state = BBL_PPP_CLOSED;
            if(session->ipcp_state > BBL_PPP_DISABLED) {
                session->ipcp_state = BBL_PPP_CLOSED;
            }
            if(session->ip6cp_state > BBL_PPP_DISABLED) {
                session->ip6cp_state = BBL_PPP_CLOSED;
            }
            session->send_requests = BBL_SEND_DISCOVERY;
            bbl_session_update_state(session, BBL_TERMINATING);
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_PROT_REJECT:
            if(lcp->protocol == PROTOCOL_IPCP) {
                session->ipcp_state = BBL_PPP_REJECTED;
                LOG(PPPOE, "LCP PROTOCOL REJECT (ID: %u) Protocol IPCP rejected\n", session->session_id);
            } else if(lcp->protocol == PROTOCOL_IP6CP) {
                session->ip6cp_state = BBL_PPP_REJECTED;
                LOG(PPPOE, "LCP PROTOCOL REJECT (ID: %u) Protocol IP6CP rejected\n", session->session_id);
            } else {
                LOG(PPPOE, "LCP PROTOCOL REJECT (ID: %u) Protocol 0x%04x rejected\n", 
                    session->session_id, lcp->protocol);
            }
            bbl_access_rx_established_pppoe(interface, session, eth);
            break;
        default:
            session->lcp_response_code = PPP_CODE_CODE_REJECT;
            if(lcp->len > PPP_OPTIONS_BUFFER) {
                memcpy(session->lcp_options, lcp->start, PPP_OPTIONS_BUFFER);
                session->lcp_options_len = PPP_OPTIONS_BUFFER;
            } else {
                memcpy(session->lcp_options, lcp->start, lcp->len);
                session->lcp_options_len = lcp->len;
            }
            session->lcp_peer_identifier = lcp->identifier;
            session->send_requests |= BBL_SEND_LCP_RESPONSE;
            bbl_session_tx_qnode_insert(session);
            break;
    }
}

static void
bbl_access_rx_session(bbl_access_interface_s *interface,
                      bbl_session_s *session,
                      bbl_ethernet_header_s *eth)
{
    bbl_pppoe_session_s *pppoes;

    pppoes = (bbl_pppoe_session_s*)eth->next;
    switch(pppoes->protocol) {
        case PROTOCOL_LCP:
            bbl_access_rx_lcp(interface, session, eth);
            interface->stats.lcp_rx++;
            break;
        case PROTOCOL_IPCP:
            bbl_access_rx_ipcp(interface, session, eth);
            interface->stats.ipcp_rx++;
            break;
        case PROTOCOL_IP6CP:
            bbl_access_rx_ip6cp(interface, session, eth);
            interface->stats.ip6cp_rx++;
            break;
        case PROTOCOL_PAP:
            bbl_access_rx_pap(interface, session, eth);
            interface->stats.pap_rx++;
            break;
        case PROTOCOL_CHAP:
            bbl_access_rx_chap(interface, session, eth);
            interface->stats.chap_rx++;
            break;
        case PROTOCOL_IPV4:
            bbl_access_rx_ipv4(interface, session, eth, (bbl_ipv4_s*)pppoes->next);
            break;
        case PROTOCOL_IPV6:
            bbl_access_rx_ipv6(interface, session, eth, (bbl_ipv6_s*)pppoes->next);
            break;
        default:
            interface->stats.unknown++;
            break;
    }
}

void
bbl_access_lcp_start_delay(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    session->send_requests |= BBL_SEND_LCP_REQUEST;
    session->lcp_request_code = PPP_CODE_CONF_REQUEST;
    bbl_session_tx_qnode_insert(session);
}

static void
bbl_access_rx_discovery(bbl_access_interface_s *interface,
                        bbl_session_s *session, 
                        bbl_ethernet_header_s *eth)
{
    bbl_pppoe_discovery_s *pppoed;

    pppoed = (bbl_pppoe_discovery_s*)eth->next;
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
                    if(session->pppoe_service_name_len) {
                        LOG(PPPOE, "PPPoE Error (ID: %u) Missing service name in PADO\n", session->session_id);
                        return;
                    }
                }
                if(session->pppoe_host_uniq) {
                    if(pppoed->host_uniq_len != sizeof(uint64_t) ||
                       *(uint64_t*)pppoed->host_uniq != session->pppoe_host_uniq) {
                        LOG(PPPOE, "PPPoE Error (ID: %u) Wrong host-uniq in PADO\n", session->session_id);
                        return;
                    }
                }
                bbl_session_update_state(session, BBL_PPPOE_REQUEST);
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
                    if(pppoed->service_name_len) {
                        if(pppoed->service_name_len != session->pppoe_service_name_len ||
                            memcmp(pppoed->service_name, session->pppoe_service_name, session->pppoe_service_name_len) != 0) {
                            LOG(PPPOE, "PPPoE Error (ID: %u) Wrong service name in PADS\n", session->session_id);
                            return;
                        }
                    } else {
                        if(session->pppoe_service_name_len) {
                            LOG(PPPOE, "PPPoE Error (ID: %u) Missing service name in PADS\n", session->session_id);
                            return;
                        }
                    }
                    session->pppoe_session_id = pppoed->session_id;
                    bbl_session_update_state(session, BBL_PPP_LINK);
                    session->send_requests = BBL_SEND_LCP_REQUEST;
                    session->lcp_request_code = PPP_CODE_CONF_REQUEST;
                    session->lcp_state = BBL_PPP_INIT;
                    if(g_ctx->config.lcp_start_delay) {
                        timer_add(&g_ctx->timer_root, &session->timer_lcp, "LCP timeout",
                                  0, g_ctx->config.lcp_start_delay * MSEC, session, &bbl_access_lcp_start_delay);
                    } else {
                        session->send_requests = BBL_SEND_LCP_REQUEST;
                        session->lcp_request_code = PPP_CODE_CONF_REQUEST;
                        bbl_session_tx_qnode_insert(session);
                    }
                } else {
                    LOG(PPPOE, "PPPoE Error (ID: %u) Invalid PADS\n", session->session_id);
                    return;
                }
            }
            break;
        case PPPOE_PADT:
            interface->stats.padt_rx++;
            bbl_session_update_state(session, BBL_TERMINATED);
            session->send_requests = 0;
            break;
        default:
            interface->stats.unknown++;
            break;
    }
}

static void
bbl_access_rx_arp(bbl_access_interface_s *interface,
                  bbl_session_s *session,
                  bbl_ethernet_header_s *eth)
{
    bbl_arp_s *arp = (bbl_arp_s*)eth->next;

    if(arp->sender_ip == session->peer_ip_address) {
        if(arp->code == ARP_REQUEST) {
            if(arp->target_ip == session->ip_address) {
                session->send_requests |= BBL_SEND_ARP_REPLY;
                bbl_session_tx_qnode_insert(session);
            }
        } else if(arp->code == ARP_REPLY) {
            if(!session->arp_resolved) {
                session->arp_resolved = true;
                memcpy(session->server_mac, arp->sender, ETH_ADDR_LEN);
                bbl_access_rx_established_ipoe(interface, session, eth);
                if(g_ctx->config.arp_interval) {
                    timer_add(&g_ctx->timer_root, &session->timer_arp, "ARP timeout", g_ctx->config.arp_interval, 0, session, &bbl_arp_timeout);
                } else {
                    timer_del(session->timer_arp);
                }
            }
        }
    }
}

static uint32_t
bbl_access_session_id_from_vlan(bbl_access_interface_s *interface, 
                                bbl_ethernet_header_s *eth)
{
    uint32_t session_id = 0;
    vlan_session_key_t key = {0};
    bbl_session_s *session;
    void **search;

    key.ifindex = interface->ifindex;
    key.outer_vlan_id = eth->vlan_outer;
    key.inner_vlan_id = eth->vlan_inner;

    search = dict_search(g_ctx->vlan_session_dict, &key);
    if(search) {
        session = *search;
        session_id = session->session_id;
    }
    return session_id;
}

static uint32_t
bbl_access_session_id_from_broadcast(bbl_access_interface_s *interface,
                                     bbl_ethernet_header_s *eth)
{
    uint32_t session_id = 0;
    bbl_ipv4_s *ipv4;
    bbl_udp_s *udp;
    bbl_dhcp_s *dhcp;

    if(eth->type == ETH_TYPE_IPV4) {
        ipv4 = (bbl_ipv4_s*)eth->next;
        if(ipv4->protocol == PROTOCOL_IPV4_UDP) {
            udp = (bbl_udp_s*)ipv4->next;
            if(udp->protocol == UDP_PROTOCOL_DHCP) {
                dhcp = (bbl_dhcp_s*)udp->next;
                session_id |= ((uint8_t*)(dhcp->header->chaddr))[5];
                session_id |= ((uint8_t*)(dhcp->header->chaddr))[4] << 8;
                session_id |= ((uint8_t*)(dhcp->header->chaddr))[3] << 16;
            }
        }
    }
    if(!session_id) {
        return(bbl_access_session_id_from_vlan(interface, eth));
    }
    return session_id;
}

static void
bbl_access_rx_handler_multicast(bbl_access_interface_s *interface, 
                                bbl_ethernet_header_s *eth)
{
    bbl_session_s *session;
    uint32_t session_index;

    for(session_index = 0; session_index < g_ctx->sessions; session_index++) {
        session = &g_ctx->session_list[session_index];

        if(session->access_interface != interface) {
            continue;
        }

        if(session->access_type == ACCESS_TYPE_IPOE) {
            if(session->session_state != BBL_TERMINATED &&
               session->session_state != BBL_IDLE) {
                session->stats.packets_rx++;
                session->stats.bytes_rx += eth->length;
                switch(eth->type) {
                    case ETH_TYPE_IPV4:
                        bbl_access_rx_ipv4(interface, session, eth, (bbl_ipv4_s*)eth->next);
                        break;
                    case ETH_TYPE_IPV6:
                        bbl_access_rx_ipv6(interface, session, eth, (bbl_ipv6_s*)eth->next);
                        break;
                    default:
                        interface->stats.unknown++;
                        break;
                }
            }
        }
    }
}

static void
bbl_access_rx_handler_broadcast(bbl_access_interface_s *interface, 
                                bbl_ethernet_header_s *eth)
{
    bbl_session_s *session;
    uint32_t session_index;

    for(session_index = 0; session_index < g_ctx->sessions; session_index++) {
        session = &g_ctx->session_list[session_index];

        if(session->access_interface != interface) {
            continue;
        }

        if(session->access_type == ACCESS_TYPE_IPOE) {
            if(session->session_state != BBL_TERMINATED &&
               session->session_state != BBL_IDLE) {
                session->stats.packets_rx++;
                session->stats.bytes_rx += eth->length;
                switch(eth->type) {
                    case ETH_TYPE_ARP:
                        interface->stats.arp_rx++;
                        bbl_access_rx_arp(interface, session, eth);
                        break;
                    case ETH_TYPE_IPV4:
                        bbl_access_rx_ipv4(interface, session, eth, (bbl_ipv4_s*)eth->next);
                        break;
                    default:
                        interface->stats.unknown++;
                        break;
                }
            }
        }
    }
}

/**
 * bbl_access_rx_handler
 *
 * This function handles all packets received on access interfaces.
 *
 * @param interface pointer to access interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 */
void
bbl_access_rx_handler(bbl_access_interface_s *interface, 
                      bbl_ethernet_header_s *eth)
{
    bbl_session_s *session;
    uint32_t session_id = 0;

    interface->stats.packets_rx++;
    interface->stats.bytes_rx += eth->length;

    if(memcmp(eth->dst, broadcast_mac, ETH_ADDR_LEN) == 0) {
        /* Broadcast destination MAC address (ff:ff:ff:ff:ff:ff) */
        session_id = bbl_access_session_id_from_broadcast(interface, eth);
        if(!session_id) {
            bbl_access_rx_handler_broadcast(interface, eth);
            return;
        }
    } else if(*eth->dst & 0x01) {
        /* Ethernet frames with a value of 1 in the least-significant bit
         * of the first octet of the destination MAC address are treated
         * as multicast frames. */
        session_id = bbl_access_session_id_from_vlan(interface, eth);
        if(!session_id) {
            bbl_access_rx_handler_multicast(interface, eth);
            return;
        }
    } else {
        /* The session-id is mapped into the last 3 bytes of
         * the client MAC address. The original approach using
         * VLAN identifiers was not working reliable as some NIC
         * drivers strip outer VLAN and it is also possible to have
         * multiple session per VLAN (N:1). */
        session_id |= eth->dst[5];
        session_id |= eth->dst[4] << 8;
        session_id |= eth->dst[3] << 16;
    }

    session = bbl_session_get(session_id);
    if(session) {
        if(session->session_state != BBL_TERMINATED &&
           session->session_state != BBL_IDLE) {
            session->stats.packets_rx++;
            session->stats.bytes_rx += eth->length;
            switch(session->access_type) {
                case ACCESS_TYPE_PPPOE:
                    switch(eth->type) {
                        case ETH_TYPE_PPPOE_DISCOVERY:
                            bbl_access_rx_discovery(interface, session, eth);
                            break;
                        case ETH_TYPE_PPPOE_SESSION:
                            bbl_access_rx_session(interface, session, eth);
                            break;
                        default:
                            interface->stats.unknown++;
                            break;
                    }
                    break;
                case ACCESS_TYPE_IPOE:
                    switch(eth->type) {
                        case ETH_TYPE_ARP:
                            interface->stats.arp_rx++;
                            bbl_access_rx_arp(interface, session, eth);
                            break;
                        case ETH_TYPE_IPV4:
                            bbl_access_rx_ipv4(interface, session, eth, (bbl_ipv4_s*)eth->next);
                            break;
                        case ETH_TYPE_IPV6:
                            bbl_access_rx_ipv6(interface, session, eth, (bbl_ipv6_s*)eth->next);
                            break;
                        default:
                            interface->stats.unknown++;
                            break;
                    }
                    break;
                default:
                    interface->stats.unknown++;
                    break;
            }
        }
    }
}

static json_t *
bbl_access_interface_json(bbl_access_interface_s *interface)
{
    return json_pack("{ss si ss sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI}",
                     "name", interface->name,
                     "ifindex", interface->ifindex,
                     "type", "Access",
                     "tx-packets", interface->stats.packets_tx,
                     "tx-bytes", interface->stats.bytes_tx, 
                     "tx-pps", interface->stats.rate_packets_tx.avg,
                     "tx-kbps", interface->stats.rate_bytes_tx.avg * 8 / 1000,
                     "rx-packets", interface->stats.packets_rx, 
                     "rx-bytes", interface->stats.bytes_rx,
                     "rx-pps", interface->stats.rate_packets_rx.avg,
                     "rx-kbps", interface->stats.rate_bytes_rx.avg * 8 / 1000,
                     "rx-packets-multicast", interface->stats.mc_rx,
                     "rx-pps-multicast", interface->stats.rate_mc_rx.avg,
                     "rx-loss-packets-multicast", interface->stats.mc_loss,
                     "tx-packets-session-ipv4", interface->stats.session_ipv4_tx,
                     "tx-pps-session-ipv4", interface->stats.rate_session_ipv4_tx.avg,
                     "rx-packets-session-ipv4", interface->stats.session_ipv4_rx,
                     "rx-pps-session-ipv4", interface->stats.rate_session_ipv4_rx.avg,
                     "rx-loss-packets-session-ipv4", interface->stats.session_ipv4_loss,
                     "tx-packets-session-ipv6", interface->stats.session_ipv6_tx,
                     "tx-pps-session-ipv6", interface->stats.rate_session_ipv6_tx.avg,
                     "rx-packets-session-ipv6", interface->stats.session_ipv6_rx,
                     "rx-pps-session-ipv6", interface->stats.rate_session_ipv6_rx.avg,
                     "rx-loss-packets-session-ipv6", interface->stats.session_ipv6_loss,
                     "tx-packets-session-ipv6pd", interface->stats.session_ipv6pd_tx,
                     "tx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_tx.avg,
                     "rx-packets-session-ipv6pd", interface->stats.session_ipv6pd_rx,
                     "rx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_rx.avg,
                     "rx-loss-packets-session-ipv6pd", interface->stats.session_ipv6pd_loss,
                     "tx-packets-streams", interface->stats.stream_tx,
                     "tx-pps-streams", interface->stats.rate_stream_tx.avg,
                     "rx-packets-streams", interface->stats.stream_rx,
                     "rx-pps-streams", interface->stats.rate_stream_rx.avg,
                     "rx-loss-packets-streams", interface->stats.stream_loss
                    );
}

/* Control Socket Commands */

int
bbl_access_ctrl_interfaces(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *interfaces;
    bbl_interface_s *interface;

    interfaces = json_array();
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(interface->access) {
            json_array_append(interfaces, bbl_access_interface_json(interface->access));
        }
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "access-interfaces", interfaces);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(interfaces);
    }
    return result;
}