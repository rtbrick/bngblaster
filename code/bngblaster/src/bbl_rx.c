/*
 * BNG Blaster (BBL) - RX Job
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_session.h"
#include "bbl_stream.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"
#include "bbl_tx.h"
#include "bbl_session_traffic.h"
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
            session->lcp_state = BBL_PPP_CLOSED;
            session->ipcp_state = BBL_PPP_CLOSED;
            session->ip6cp_state = BBL_PPP_CLOSED;
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
            
            if(ctx->config.igmp_max_join_delay && join_delay > ctx->config.igmp_max_join_delay) {
                session->stats.max_join_delay_violations++;
            }

            LOG(IGMP, "IGMP (ID: %u) ZAPPING %u ms join delay for group %s\n",
                session->session_id, join_delay, format_ipv4_address(&group->group));
        }
    } else {
        if(ctx->config.igmp_zap_wait) {
            /* Wait until MC traffic is received ... */
            return;
        } else {
            group->zapping_result = true;
            session->stats.mc_not_received++;
            LOG(IGMP, "IGMP (ID: %u) ZAPPING join failed for group %s\n",
                session->session_id, format_ipv4_address(&group->group));
        }
    }

    if(!ctx->zapping && group->state < IGMP_GROUP_ACTIVE) {
        return;
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

    if(ctx->zapping) {
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
        timer_add_periodic(&ctx->timer_root, &session->timer_zapping, "IGMP Zapping", ctx->config.igmp_zap_interval, 1, session, &bbl_igmp_zapping);
        LOG(IGMP, "IGMP (ID: %u) ZAPPING start zapping with interval %u\n",
            session->session_id, ctx->config.igmp_zap_interval);

        timer_smear_bucket(&ctx->timer_root, ctx->config.igmp_zap_interval, 1);
    }
}

static void
bbl_rx_stream(bbl_interface_s *interface, bbl_ethernet_header_t *eth, bbl_bbl_t *bbl, uint8_t tos) {

    bbl_ctx_s *ctx = interface->ctx;
    bbl_stream *stream;
    bbl_mpls_t *mpls;
    void **search = NULL;
    uint64_t loss;

    interface->stats.stream_rx++;
    search = dict_search(ctx->stream_flow_dict, &bbl->flow_id);
    if(search) {
        stream = *search;
        if(stream->rx_first_seq) {
            /* Stream already verified */
            if((stream->rx_last_seq +1) < bbl->flow_seq) {
                loss = bbl->flow_seq - (stream->rx_last_seq +1);
                stream->loss += loss;
                interface->stats.stream_loss += loss;
                LOG(LOSS, "LOSS flow: %lu seq: %lu last: %lu\n",
                    bbl->flow_id, bbl->flow_seq, stream->rx_last_seq);
            }
        } else {
            /* Verify stream ... */
            stream->rx_len = eth->length;
            stream->rx_priority = tos;
            stream->rx_outer_vlan_pbit = eth->vlan_outer_priority;
            stream->rx_inner_vlan_pbit = eth->vlan_inner_priority;
            mpls = eth->mpls;
            if(mpls) {
                stream->rx_mpls1 = true;
                stream->rx_mpls1_label = mpls->label;
                stream->rx_mpls1_exp = mpls->exp;
                stream->rx_mpls1_ttl = mpls->ttl;
                mpls = mpls->next;
                if(mpls) {
                    stream->rx_mpls2 = true;
                    stream->rx_mpls2_label = mpls->label;
                    stream->rx_mpls2_exp = mpls->exp;
                    stream->rx_mpls2_ttl = mpls->ttl;
                }
            }
            if(stream->config->rx_mpls1_label) {
                /* Check if expected outer label is received ... */
                if(stream->rx_mpls1_label != stream->config->rx_mpls1_label) {
                    /* Wrong outer label received! */
                    return;
                }
                if(stream->config->rx_mpls2_label) {
                    /* Check if expected inner label is received ... */
                    if(stream->rx_mpls2_label != stream->config->rx_mpls2_label) {
                        /* Wrong inner label received! */
                        return;
                    }
                }
            }
            stream->rx_first_seq = bbl->flow_seq;
            ctx->stats.stream_traffic_flows_verified++;
            if(ctx->stats.stream_traffic_flows_verified == ctx->stats.stream_traffic_flows) {
                LOG_NOARG(INFO, "ALL STREAM TRAFFIC FLOWS VERIFIED\n");
            }
            if(ctx->config.traffic_stop_verified) {
                stream->stop = true;
            }
        }
        stream->packets_rx++;
        stream->rx_last_seq = bbl->flow_seq;
        bbl_stream_delay(stream, &eth->timestamp, &bbl->timestamp);
    }
}

static void
bbl_rx_udp_ipv6(bbl_ethernet_header_t *eth, bbl_ipv6_t *ipv6, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_ctx_s *ctx = interface->ctx;
    bbl_udp_t *udp = (bbl_udp_t*)ipv6->next;
    bbl_bbl_t *bbl = NULL;
    uint64_t loss;

    switch(udp->dst) {
        case DHCPV6_UDP_CLIENT:
        case DHCPV6_UDP_SERVER:
            interface->stats.dhcpv6_rx++;
            session->stats.dhcpv6_rx++;
            bbl_dhcpv6_rx(eth, (bbl_dhcpv6_t*)udp->next, session);
            return;
        case BBL_UDP_PORT:
            bbl = (bbl_bbl_t*)udp->next;
            interface->io.ctrl = false;
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
                        session->session_traffic_flows_verified++;
                        ctx->stats.session_traffic_flows_verified++;
                        if(ctx->stats.session_traffic_flows_verified == ctx->stats.session_traffic_flows) {
                            LOG_NOARG(INFO, "ALL SESSION TRAFFIC FLOWS VERIFIED\n");
                        }
                    } else {
                        if((session->access_ipv6_rx_last_seq +1) < bbl->flow_seq) {
                            loss = bbl->flow_seq - (session->access_ipv6_rx_last_seq +1);
                            interface->stats.session_ipv6_loss += loss;
                            session->stats.access_ipv6_loss += loss;
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
                        session->session_traffic_flows_verified++;
                        ctx->stats.session_traffic_flows_verified++;
                        if(ctx->stats.session_traffic_flows_verified == ctx->stats.session_traffic_flows) {
                            LOG_NOARG(INFO, "ALL SESSION TRAFFIC FLOWS VERIFIED\n");
                        }
                    } else {
                        if((session->access_ipv6pd_rx_last_seq +1) < bbl->flow_seq) {
                            loss = bbl->flow_seq - (session->access_ipv6pd_rx_last_seq +1);
                            interface->stats.session_ipv6pd_loss += loss;
                            session->stats.access_ipv6pd_loss += loss;
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
bbl_cfm_cc(timer_s *timer) {
    bbl_session_s *session = timer->data;
    if(session->session_state == BBL_ESTABLISHED && session->cfm_cc) {
        session->send_requests |= BBL_SEND_CFM_CC;
        bbl_session_tx_qnode_insert(session);
    }
}

/**
 * bbl_rx_established_ipoe
 * 
 * @param eth received packet
 * @param interface receiving interface
 * @param session corresponding session
 */
void
bbl_rx_established_ipoe(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_ctx_s *ctx = interface->ctx;

    bool ipv4 = true;
    bool ipv6 = true;

    if(session->access_config->ipv4_enable) {
        if(!session->arp_resolved ||
           (session->access_config->dhcp_enable && session->dhcp_state < BBL_DHCP_BOUND)) {
            ipv4 = false;
        }
    }
    if(session->access_config->ipv6_enable) {
        if(!session->icmpv6_ra_received ||
           (session->access_config->dhcpv6_enable && session->dhcpv6_state < BBL_DHCP_BOUND)) {
            ipv6 = false;
        }
    }

    if(ipv4 && ipv6) {
        if(session->session_state != BBL_ESTABLISHED) {
            if(ctx->sessions_established_max < ctx->sessions) {
                ctx->stats.last_session_established.tv_sec = eth->timestamp.tv_sec;
                ctx->stats.last_session_established.tv_nsec = eth->timestamp.tv_nsec;
            }
            bbl_session_update_state(ctx, session, BBL_ESTABLISHED);
            if(session->access_config->ipv4_enable) {
                if(ctx->config.igmp_group && ctx->config.igmp_autostart && ctx->config.igmp_start_delay) {
                    /* Start IGMP */
                    timer_add(&ctx->timer_root, &session->timer_igmp, "IGMP", ctx->config.igmp_start_delay, 0, session, &bbl_igmp_initial_join);
                }
                bbl_session_traffic_start_ipv4(ctx, session);
            }
            if(session->access_config->ipv6_enable) {
                bbl_session_traffic_start_ipv6(ctx, session);
                bbl_session_traffic_start_ipv6pd(ctx, session);
            }
            if(session->cfm_cc) {
                /* Start CFM CC (currently fixed set to 1s) */
                timer_add_periodic(&ctx->timer_root, &session->timer_cfm_cc, "CFM-CC", 1, 0, session, &bbl_cfm_cc);
            }
        }
    }
}

static void
bbl_rx_icmpv6(bbl_ethernet_header_t *eth, bbl_ipv6_t *ipv6, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_icmpv6_t *icmpv6 = (bbl_icmpv6_t*)ipv6->next;
    bbl_ctx_s *ctx = interface->ctx;

    session->stats.icmpv6_rx++;

    if(session->a10nsp_session) {
        /* There is currently no IPv6 support
         * for A10NSP terminated sessions today. */
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
                LOG(IP, "IPv6 (ID: %u) ICMPv6 RA prefix %s/%d\n",
                    session->session_id, format_ipv6_address(&session->ipv6_prefix.address), session->ipv6_prefix.len);
                if(icmpv6->dns1) {
                    memcpy(&session->ipv6_dns1, icmpv6->dns1, IPV6_ADDR_LEN);
                    if(icmpv6->dns2) {
                        memcpy(&session->ipv6_dns2, icmpv6->dns2, IPV6_ADDR_LEN);
                    }
                }
                if(session->access_type == ACCESS_TYPE_PPPOE&& session->l2tp == false) {
                    bbl_session_traffic_start_ipv6(ctx, session);
                }
            }
            if(session->access_type == ACCESS_TYPE_IPOE) {
                if(!session->arp_resolved) {
                    memcpy(session->server_mac, eth->src, ETH_ADDR_LEN);
                }
                bbl_rx_established_ipoe(eth, interface, session);
            } else if(icmpv6->other && ctx->config.dhcpv6_enable) {
                bbl_dhcpv6_start(session);
                bbl_session_tx_qnode_insert(session);
            }
        }
    } else if(icmpv6->type == IPV6_ICMPV6_NEIGHBOR_SOLICITATION) {
        session->send_requests |= BBL_SEND_ICMPV6_NA;
    } else if(icmpv6->type == IPV6_ICMPV6_ECHO_REQUEST) {
        bbl_send_icmpv6_echo_reply(interface, session, eth, ipv6, icmpv6);
    }
}

static void
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

static void
bbl_rx_icmp(bbl_ethernet_header_t *eth, bbl_ipv4_t *ipv4, bbl_session_s *session) {
    bbl_icmp_t *icmp = (bbl_icmp_t*)ipv4->next;
    if(session->ip_address &&
       session->ip_address == ipv4->dst &&
       icmp->type == ICMP_TYPE_ECHO_REQUEST) {
        /* Send ICMP reply... */
        bbl_send_icmp_reply(session->interface, session, eth, ipv4, icmp);
    }
}

static void
bbl_rx_ipv4(bbl_ethernet_header_t *eth, bbl_ipv4_t *ipv4, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_ctx_s *ctx = interface->ctx;
    bbl_udp_t *udp;
    bbl_bbl_t *bbl = NULL;
    bbl_igmp_group_s *group = NULL;
    uint64_t loss;
    int i;

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
            bbl_rx_igmp(ipv4, session);
            return;
        case PROTOCOL_IPV4_ICMP:
            session->stats.icmp_rx++;
            interface->stats.icmp_rx++;
            bbl_rx_icmp(eth, ipv4, session);
            return;
        case PROTOCOL_IPV4_UDP:
            udp = (bbl_udp_t*)ipv4->next;
            if (udp->protocol == UDP_PROTOCOL_DHCP) {
                interface->stats.dhcp_rx++;
                session->stats.dhcp_rx++;
                bbl_dhcp_rx(eth, (bbl_dhcp_t*)udp->next, session);
                return;
            }
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
        interface->io.ctrl = false;
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
                    session->session_traffic_flows_verified++;
                    ctx->stats.session_traffic_flows_verified++;
                    if(ctx->stats.session_traffic_flows_verified == ctx->stats.session_traffic_flows) {
                        LOG_NOARG(INFO, "ALL SESSION TRAFFIC FLOWS VERIFIED\n");
                    }
                } else {
                    if((session->access_ipv4_rx_last_seq +1) < bbl->flow_seq) {
                        loss = bbl->flow_seq - (session->access_ipv4_rx_last_seq +1);
                        interface->stats.session_ipv4_loss += loss;
                        session->stats.access_ipv4_loss += loss;
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
                        } else if((session->mc_rx_last_seq +1) < bbl->flow_seq) {
                            loss = bbl->flow_seq - (session->mc_rx_last_seq +1);
                            interface->stats.mc_loss += loss;
                            session->stats.mc_loss += loss;
                            group->loss += loss;
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

static void
bbl_rx_ipv6(bbl_ethernet_header_t *eth, bbl_ipv6_t *ipv6, bbl_interface_s *interface, bbl_session_s *session) {
    switch(ipv6->protocol) {
        case IPV6_NEXT_HEADER_ICMPV6:
            interface->stats.icmpv6_rx++;
            bbl_rx_icmpv6(eth, ipv6, interface, session);
            return;
        case IPV6_NEXT_HEADER_UDP:
            bbl_rx_udp_ipv6(eth, ipv6, interface, session);
            return;
        default:
            break;
    }
    session->stats.accounting_packets_rx++;
    session->stats.accounting_bytes_rx += eth->length;
}

static void
bbl_rx_pap(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;
    bbl_pap_t *pap;
    bbl_ctx_s *ctx = interface->ctx;

    char substring[16];
    char *tok;
    char *save = NULL;

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
                        tok = strtok_r(substring, ":", &save);
                        if(tok) {
                            key.tunnel_id = atoi(tok);
                            tok = strtok_r(0, ":", &save);
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
                if(pap->reply_message_len) {
                    if(session->reply_message) {
                        free(session->reply_message);
                    }
                    session->reply_message = malloc(pap->reply_message_len+1);
                    memcpy(session->reply_message, pap->reply_message, pap->reply_message_len);
                    session->reply_message[pap->reply_message_len] = 0;
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
                session->lcp_state = BBL_PPP_TERMINATE;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
        }
    }
}

static void
bbl_rx_chap(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;
    bbl_chap_t *chap;
    bbl_ctx_s *ctx = interface->ctx;

    MD5_CTX md5_ctx;

    char substring[16];
    char *tok;
    char *save = NULL;

    l2tp_key_t key = {0};
    void **search = NULL;

    pppoes = (bbl_pppoe_session_t*)eth->next;
    chap = (bbl_chap_t*)pppoes->next;

    if(session->session_state == BBL_PPP_AUTH) {
        switch(chap->code) {
            case CHAP_CODE_CHALLENGE:
                if(chap->challenge_len != CHALLENGE_LEN) {
                    /* TODO: Add support for variable CHAP challenge lengths. */
                    LOG(PPPOE, "CHAP (ID: %u) unsupported CHAP challenge length received (expected 16)\n", session->session_id);
                    bbl_session_update_state(ctx, session, BBL_PPP_TERMINATING);
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
                if(chap->reply_message_len) {
                    if(session->reply_message) {
                        free(session->reply_message);
                    }
                    session->reply_message = malloc(chap->reply_message_len+1);
                    memcpy(session->reply_message, chap->reply_message, chap->reply_message_len);
                    session->reply_message[chap->reply_message_len] = 0;
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
                session->lcp_state = BBL_PPP_TERMINATE;
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

/**
 * bbl_rx_established
 * 
 * @param eth received packet
 * @param interface receiving interface
 * @param session corresponding session
 */
void
bbl_rx_established(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {

    bbl_ctx_s *ctx = interface->ctx;

    bool ipcp = false;
    bool ip6cp = false;

    if(ctx->config.ipcp_enable == false || session->ipcp_state == BBL_PPP_OPENED) ipcp = true;
    if(ctx->config.ip6cp_enable == false || session->ip6cp_state == BBL_PPP_OPENED) ip6cp = true;

    if(ipcp && ip6cp) {
        if(session->session_state != BBL_ESTABLISHED) {
            if(ctx->sessions_established_max < ctx->sessions) {
                ctx->stats.last_session_established.tv_sec = eth->timestamp.tv_sec;
                ctx->stats.last_session_established.tv_nsec = eth->timestamp.tv_nsec;
            }
            bbl_session_update_state(ctx, session, BBL_ESTABLISHED);
            if(ctx->config.lcp_keepalive_interval) {
                /* Start LCP echo request / keep alive */
                timer_add_periodic(&ctx->timer_root, &session->timer_lcp_echo, "LCP ECHO", ctx->config.lcp_keepalive_interval, 0, session, &bbl_lcp_echo);
            }
            if(ctx->config.pppoe_session_time) {
                /* Start Session Timer */
                timer_add(&ctx->timer_root, &session->timer_session, "Session", ctx->config.pppoe_session_time, 0, session, &bbl_session_timeout);
            }
            if(session->access_config->ipv4_enable) {
                if(session->l2tp == false && !session->a10nsp_session &&
                   ctx->config.igmp_group && ctx->config.igmp_autostart && ctx->config.igmp_start_delay) {
                    /* Start IGMP */
                    timer_add(&ctx->timer_root, &session->timer_igmp, "IGMP", ctx->config.igmp_start_delay, 0, session, &bbl_igmp_initial_join);
                }
                bbl_session_traffic_start_ipv4(ctx, session);
            }
        }
    }
}

static void
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
                    bbl_rx_established(eth, interface, session);
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
 * bbl_rx_lcp_conf_reject
 * 
 * This function rejects all unknown LCP configuration
 * options by sending LCP conf-reject.  
 * 
 * @param session corresponding session
 * @param lcp received LCP packet
 */
static void
bbl_rx_lcp_conf_reject(bbl_session_s *session, bbl_lcp_t *lcp) {

    uint8_t type;
    uint8_t len;
    session->lcp_options_len = 0;

    for(int i=0; i < PPP_MAX_OPTIONS; i++) {
        if(lcp->option[i]) {
            type = lcp->option[i][0];
            len = lcp->option[i][1];
            switch (type) {
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
bbl_rx_lcp(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_pppoe_session_t *pppoes;
    bbl_lcp_t *lcp;
    bbl_ctx_s *ctx = interface->ctx;

    pppoes = (bbl_pppoe_session_t*)eth->next;
    lcp = (bbl_lcp_t*)pppoes->next;

    if(session->session_state == BBL_PPP_TERMINATING && 
       !(lcp->code == PPP_CODE_TERM_REQUEST || lcp->code == PPP_CODE_TERM_ACK)) {
        /* Only term-request/ack is accepted in terminating phase */
        return;
    }

    switch(lcp->code) {
        case PPP_CODE_VENDOR_SPECIFIC:
            if(ctx->config.lcp_vendor_ignore) {
                return;
            }
            if(ctx->config.lcp_connection_status_message &&
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
                bbl_rx_lcp_conf_reject(session, lcp);
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
            session->lcp_peer_identifier = lcp->identifier;
            session->lcp_response_code = PPP_CODE_TERM_ACK;
            session->lcp_options_len = 0;
            session->lcp_state = BBL_PPP_TERMINATE;
            session->send_requests = BBL_SEND_LCP_RESPONSE;
            if(session->session_state != BBL_PPP_TERMINATING) {
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
            }
            bbl_session_update_state(ctx, session, BBL_PPP_TERMINATING);
            bbl_session_tx_qnode_insert(session);
            break;
        case PPP_CODE_TERM_ACK:
            session->lcp_retries = 0;
            session->lcp_state = BBL_PPP_CLOSED;
            session->ipcp_state = BBL_PPP_CLOSED;
            session->ip6cp_state = BBL_PPP_CLOSED;
            session->send_requests = BBL_SEND_DISCOVERY;
            bbl_session_update_state(ctx, session, BBL_TERMINATING);
            bbl_session_tx_qnode_insert(session);
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
bbl_lcp_start_delay(timer_s *timer) {
    bbl_session_s *session = timer->data;
    session->send_requests |= BBL_SEND_LCP_REQUEST;
    session->lcp_request_code = PPP_CODE_CONF_REQUEST;
    bbl_session_tx_qnode_insert(session);
}

static void
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
                    bbl_session_update_state(ctx, session, BBL_PPP_LINK);
                    session->send_requests = BBL_SEND_LCP_REQUEST;
                    session->lcp_request_code = PPP_CODE_CONF_REQUEST;
                    session->lcp_state = BBL_PPP_INIT;
                    if(ctx->config.lcp_start_delay) {
                        timer_add(&ctx->timer_root, &session->timer_lcp, "LCP timeout",
                                  0, ctx->config.lcp_start_delay * MSEC, session, &bbl_lcp_start_delay);
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
            bbl_session_update_state(ctx, session, BBL_TERMINATED);
            session->send_requests = 0;
            break;
        default:
            interface->stats.packets_rx_drop_unknown++;
            break;
    }
}

static void
bbl_rx_arp(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session) {
    bbl_arp_t *arp = (bbl_arp_t*)eth->next;
    bbl_ctx_s *ctx;

    if(arp->sender_ip == session->peer_ip_address) {
        if(!session->arp_resolved) {
            memcpy(session->server_mac, arp->sender, ETH_ADDR_LEN);
        }
        if(arp->code == ARP_REQUEST) {
            if(arp->target_ip == session->ip_address) {
                session->send_requests |= BBL_SEND_ARP_REPLY;
                bbl_session_tx_qnode_insert(session);
            }
        } else {
            if(!session->arp_resolved) {
                session->arp_resolved = true;
                ctx = session->interface->ctx;
                bbl_rx_established_ipoe(eth, interface, session);
                if(ctx->config.arp_interval) {
                    timer_add(&ctx->timer_root, &session->timer_arp, "ARP timeout", ctx->config.arp_interval, 0, session, &bbl_arp_timeout);
                } else {
                    timer_del(session->timer_arp);
                }
            }
        }
    }
}

static uint32_t
bbl_rx_session_id_from_vlan(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    uint32_t session_id = 0;
    vlan_session_key_t key = {0};
    bbl_session_s *session;
    void **search;

    key.ifindex = interface->ifindex;
    key.outer_vlan_id = eth->vlan_outer;
    key.inner_vlan_id = eth->vlan_inner;

    search = dict_search(interface->ctx->vlan_session_dict, &key);
    if(search) {
        session = *search;
        session_id = session->session_id;
    }
    return session_id;
}

static uint32_t
bbl_rx_session_id_from_broadcast(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    uint32_t session_id = 0;
    bbl_ipv4_t *ipv4;
    bbl_udp_t *udp;
    bbl_dhcp_t *dhcp;

    if(eth->type == ETH_TYPE_IPV4) {
        ipv4 = (bbl_ipv4_t*)eth->next;
        if(ipv4->protocol == PROTOCOL_IPV4_UDP) {
            udp = (bbl_udp_t*)ipv4->next;
            if (udp->protocol == UDP_PROTOCOL_DHCP) {
                dhcp = (bbl_dhcp_t*)udp->next;
                session_id |= ((uint8_t*)(dhcp->header->chaddr))[5];
                session_id |= ((uint8_t*)(dhcp->header->chaddr))[4] << 8;
                session_id |= ((uint8_t*)(dhcp->header->chaddr))[3] << 16;
            }
        }
    }
    if(!session_id) {
        return(bbl_rx_session_id_from_vlan(eth, interface));
    }
    return session_id;
}

static void
bbl_rx_handler_access_multicast(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_ctx_s *ctx;
    bbl_session_s *session;
    uint32_t session_index;

    ctx = interface->ctx;

    for(session_index = 0; session_index < ctx->sessions; session_index++) {
        session = ctx->session_list[session_index];
        if(session->access_type == ACCESS_TYPE_IPOE) {
            if(session->session_state != BBL_TERMINATED &&
               session->session_state != BBL_IDLE) {
                session->stats.packets_rx++;
                session->stats.bytes_rx += eth->length;
                switch(eth->type) {
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
            }
        }
    }
}

static void
bbl_rx_handler_access_broadcast(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_ctx_s *ctx;
    bbl_session_s *session;
    uint32_t session_index;

    ctx = interface->ctx;

    for(session_index = 0; session_index < ctx->sessions; session_index++) {
        session = ctx->session_list[session_index];
        if(session->access_type == ACCESS_TYPE_IPOE) {
            if(session->session_state != BBL_TERMINATED &&
               session->session_state != BBL_IDLE) {
                session->stats.packets_rx++;
                session->stats.bytes_rx += eth->length;
                switch(eth->type) {
                    case ETH_TYPE_ARP:
                        interface->stats.arp_rx++;
                        bbl_rx_arp(eth, interface, session);
                        break;
                    case ETH_TYPE_IPV4:
                        bbl_rx_ipv4(eth, (bbl_ipv4_t*)eth->next, interface, session);
                        break;
                    default:
                        interface->stats.packets_rx_drop_unknown++;
                        break;
                }
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

    if(memcmp(eth->dst, broadcast_mac, ETH_ADDR_LEN) == 0) {
        /* Broadcast destination MAC address (ff:ff:ff:ff:ff:ff) */
        session_id = bbl_rx_session_id_from_broadcast(eth, interface);
        if(!session_id) {
            bbl_rx_handler_access_broadcast(eth, interface);
            return;
        }
    } else if(*eth->dst & 0x01) {
        /* Ethernet frames with a value of 1 in the least-significant bit
         * of the first octet of the destination MAC address are treated
         * as multicast frames- */
        session_id = bbl_rx_session_id_from_vlan(eth, interface);
        if(!session_id) {
            bbl_rx_handler_access_multicast(eth, interface);
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

static void
bbl_rx_network_arp(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_secondary_ip_s *secondary_ip;

    bbl_arp_t *arp = (bbl_arp_t*)eth->next;
    if(arp->sender_ip == interface->gateway) {
        interface->arp_resolved = true;
        if(*(uint32_t*)interface->gateway_mac == 0) {
            memcpy(interface->gateway_mac, arp->sender, ETH_ADDR_LEN);
        }
        if(arp->code == ARP_REQUEST) {
            if(arp->target_ip == interface->ip.address) {
                bbl_send_arp_reply(interface, NULL, eth, arp);
            } else {
                secondary_ip = interface->ctx->config.secondary_ip_addresses;
                while(secondary_ip) {
                    if(arp->target_ip == secondary_ip->ip) {
                        bbl_send_arp_reply(interface, NULL, eth, arp);
                        return;
                    }
                    secondary_ip = secondary_ip->next;
                }
            }
        }
    }
}

static void
bbl_rx_network_icmpv6(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_ipv6_t *ipv6;
    bbl_icmpv6_t *icmpv6;
    bbl_secondary_ip6_s *secondary_ip6;

    ipv6 = (bbl_ipv6_t*)eth->next;
    icmpv6 = (bbl_icmpv6_t*)ipv6->next;

    if(memcmp(ipv6->src, interface->gateway6, IPV6_ADDR_LEN) == 0) {
        interface->icmpv6_nd_resolved = true;
        if(*(uint32_t*)interface->gateway_mac == 0) {
            memcpy(interface->gateway_mac, eth->src, ETH_ADDR_LEN);
        }
    }
    if(icmpv6->type == IPV6_ICMPV6_NEIGHBOR_SOLICITATION) {
        if(memcmp(icmpv6->prefix.address, interface->ip6.address, IPV6_ADDR_LEN) == 0) {
            bbl_send_icmpv6_na(interface, NULL, eth, ipv6, icmpv6);
        } else {
            secondary_ip6 = interface->ctx->config.secondary_ip6_addresses;
            while(secondary_ip6) {
                if(memcmp(icmpv6->prefix.address, secondary_ip6->ip, IPV6_ADDR_LEN) == 0) {
                    bbl_send_icmpv6_na(interface, NULL, eth, ipv6, icmpv6);
                    return;
                }
                secondary_ip6 = secondary_ip6->next;
            }
        }
    } else if(icmpv6->type == IPV6_ICMPV6_ECHO_REQUEST) {
        bbl_send_icmpv6_echo_reply(interface, NULL, eth, ipv6, icmpv6);
    }
}

static void
bbl_rx_network_icmp(bbl_ethernet_header_t *eth, bbl_ipv4_t *ipv4, bbl_interface_s *interface) {
    bbl_icmp_t *icmp = (bbl_icmp_t*)ipv4->next;
    if(icmp->type == ICMP_TYPE_ECHO_REQUEST) {
        /* Send ICMP reply... */
        bbl_send_icmp_reply(interface, NULL, eth, ipv4, icmp);
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

    bbl_ctx_s *ctx = interface->ctx;
    bbl_ipv4_t *ipv4 = NULL;
    bbl_ipv6_t *ipv6 = NULL;
    bbl_udp_t *udp = NULL;
    bbl_bbl_t *bbl = NULL;
    bbl_session_s *session;
    uint64_t loss;

    switch(eth->type) {
        case ETH_TYPE_ARP:
            bbl_rx_network_arp(eth, interface);
            return;
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
                    bbl_qmx_li_handler_rx(eth, (bbl_qmx_li_t*)udp->next, interface);
                    return;
                } else if(udp->protocol == UDP_PROTOCOL_L2TP) {
                    bbl_l2tp_handler_rx(eth, (bbl_l2tp_t*)udp->next, interface);
                    return;
                }
            } else if(ipv4->protocol == PROTOCOL_IPV4_ICMP) {
                interface->stats.icmp_rx++;
                bbl_rx_network_icmp(eth, ipv4, interface);
                return;
            } else if(ipv4->protocol == PROTOCOL_IPV4_TCP) {
                interface->stats.tcp_rx++;
                bbl_tcp_ipv4_rx(interface, eth, ipv4);
                return;
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
                bbl_rx_network_icmpv6(eth, interface);
                return;
            }
            break;
        case ISIS_PROTOCOL_IDENTIFIER:
            isis_handler_rx(eth, interface);
            return;
        default:
            break;
    }

    if(bbl) {
        interface->io.ctrl = false;
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
                                session->session_traffic_flows_verified++;
                                ctx->stats.session_traffic_flows_verified++;
                                if(ctx->stats.session_traffic_flows_verified == ctx->stats.session_traffic_flows) {
                                    LOG_NOARG(INFO, "ALL SESSION TRAFFIC FLOWS VERIFIED\n");
                                }
                            } else {
                                if((session->network_ipv4_rx_last_seq +1) < bbl->flow_seq) {
                                    loss = bbl->flow_seq - (session->network_ipv4_rx_last_seq +1);
                                    interface->stats.session_ipv4_loss += loss;
                                    session->stats.network_ipv4_loss += loss;
                                    LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                        session->session_id, bbl->flow_id, bbl->flow_seq, session->network_ipv4_rx_last_seq);
                                }
                            }
                            session->network_ipv4_rx_last_seq = bbl->flow_seq;
                        } else {
                            if(ipv4) {
                                bbl_rx_stream(interface, eth, bbl, ipv4->tos);
                            }
                        }
                        break;
                    case BBL_SUB_TYPE_IPV6:
                        if(session->access_ipv6_tx_flow_id == bbl->flow_id) {
                            interface->stats.session_ipv6_rx++;
                            session->stats.network_ipv6_rx++;
                            if(!session->network_ipv6_rx_first_seq) {
                                session->network_ipv6_rx_first_seq = bbl->flow_seq;
                                session->session_traffic_flows_verified++;
                                ctx->stats.session_traffic_flows_verified++;
                                if(ctx->stats.session_traffic_flows_verified == ctx->stats.session_traffic_flows) {
                                    LOG_NOARG(INFO, "ALL SESSION TRAFFIC FLOWS VERIFIED\n");
                                }
                            } else {
                                if((session->network_ipv6_rx_last_seq +1) < bbl->flow_seq) {
                                    loss = bbl->flow_seq - (session->network_ipv6_rx_last_seq +1);
                                    interface->stats.session_ipv6_loss += loss;
                                    session->stats.network_ipv6_loss += loss;
                                    LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                        session->session_id, bbl->flow_id, bbl->flow_seq, session->network_ipv6_rx_last_seq);
                                }
                            }
                            session->network_ipv6_rx_last_seq = bbl->flow_seq;
                        } else {
                            if(ipv6) {
                                bbl_rx_stream(interface, eth, bbl, ipv6->tos);
                            }
                        }
                        break;
                    case BBL_SUB_TYPE_IPV6PD:
                        if(session->access_ipv6pd_tx_flow_id == bbl->flow_id) {
                            interface->stats.session_ipv6pd_rx++;
                            session->stats.network_ipv6pd_rx++;
                            if(!session->network_ipv6pd_rx_first_seq) {
                                session->network_ipv6pd_rx_first_seq = bbl->flow_seq;
                                session->session_traffic_flows_verified++;
                                ctx->stats.session_traffic_flows_verified++;
                                if(ctx->stats.session_traffic_flows_verified == ctx->stats.session_traffic_flows) {
                                    LOG_NOARG(INFO, "ALL SESSION TRAFFIC FLOWS VERIFIED\n");
                                }
                            } else {
                                if((session->network_ipv6pd_rx_last_seq +1) < bbl->flow_seq) {
                                    loss = bbl->flow_seq - (session->network_ipv6pd_rx_last_seq +1);
                                    interface->stats.session_ipv6pd_loss += loss;
                                    session->stats.network_ipv6pd_loss += loss;
                                    LOG(LOSS, "LOSS (ID: %u) flow: %lu seq: %lu last: %lu\n",
                                        session->session_id, bbl->flow_id, bbl->flow_seq, session->network_ipv6pd_rx_last_seq);
                                }
                            }
                            session->network_ipv6pd_rx_last_seq = bbl->flow_seq;
                        } else {
                            if(ipv6) {
                                bbl_rx_stream(interface, eth, bbl, ipv6->tos);
                            }
                        }
                        break;
                    default:
                        break;
                }
            } else {
                /* Accept RAW streams */
                switch (bbl->sub_type) {
                    case BBL_SUB_TYPE_IPV4:
                        if(ipv4) {
                            bbl_rx_stream(interface, eth, bbl, ipv4->tos);
                        }
                        break;
                    case BBL_SUB_TYPE_IPV6:
                    case BBL_SUB_TYPE_IPV6PD:
                        if(ipv6) {
                            bbl_rx_stream(interface, eth, bbl, ipv6->tos);
                        }
                        break;
                }
            }
        }
    } else {
        interface->stats.packets_rx_drop_unknown++;
    }
}

/**
 * bbl_rx_handler_a10nsp
 *
 * This function handles all packets received on a10nsp interfaces.
 *
 * @param eth pointer to ethernet header structure of received packet
 * @param interface pointer to interface on which packet was received
 */
void
bbl_rx_handler_a10nsp(bbl_ethernet_header_t *eth, bbl_interface_s *interface) {
    bbl_ctx_s *ctx;
    bbl_session_s *session;
    uint32_t session_id = 0;

    ctx = interface->ctx;

    /* The session-id is mapped into the last 3 bytes of
     * the client MAC address. The original approach using
     * VLAN identifiers was not working reliable as some NIC
     * drivers strip outer VLAN and it is also possible to have
     * multiple session per VLAN (N:1). */
    session_id |= eth->src[5];
    session_id |= eth->src[4] << 8;
    session_id |= eth->src[3] << 16;

    session = bbl_session_get(ctx, session_id);
    if(session) {
        bbl_a10nsp_rx(interface, session, eth);
    }
}