/*
 * BNG Blaster (BBL) - Stats
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_stats.h"
#include "bbl_session.h"
#include "bbl_stream.h"

extern const char banner[];

void
bbl_stats_update_cps(bbl_ctx_s *ctx) {
    struct timespec time_diff = {0};
    uint32_t ms;
    double x, y;

    /* Session setup time and rate */
    if(ctx->sessions_established_max > ctx->stats.sessions_established_max) {
        ctx->stats.sessions_established_max = ctx->sessions_established_max;

        timespec_sub(&time_diff,
             &ctx->stats.last_session_established,
             &ctx->stats.first_session_tx);

        ms = time_diff.tv_nsec / 1000000; /* convert nanoseconds to milliseconds */
        if(time_diff.tv_nsec % 1000000) ms++; /* simple roundup function */
        ctx->stats.setup_time = (time_diff.tv_sec * 1000) + ms; /* Setup time in milliseconds */

        x = ctx->sessions_established_max;
        y = ctx->stats.setup_time;
        if(x > 0.0 && y > 0.0) {
            ctx->stats.cps = (x / y) * 1000.0;

            ctx->stats.cps_sum += ctx->stats.cps;
            ctx->stats.cps_count++;
            ctx->stats.cps_avg = ctx->stats.cps_sum / ctx->stats.cps_count;

            if(ctx->stats.cps_min) {
                if(ctx->stats.cps < ctx->stats.cps_min) ctx->stats.cps_min = ctx->stats.cps;
            } else {
                ctx->stats.cps_min = ctx->stats.cps;
            }
            if(ctx->stats.cps > ctx->stats.cps_max) ctx->stats.cps_max = ctx->stats.cps;
        }
    }
}

void
bbl_stats_generate_multicast(bbl_ctx_s *ctx, bbl_stats_t *stats, bool reset) {

    bbl_session_s *session;
    uint32_t i;

    uint32_t join_delays = 0;
    uint32_t leave_delays = 0;

    /* Iterate over all sessions */
    for(i = 0; i < ctx->sessions; i++) {
        session = &ctx->session_list[i];
        if(session) {
            /* Multicast */
            stats->mc_old_rx_after_first_new += session->stats.mc_old_rx_after_first_new;
            stats->mc_not_received += session->stats.mc_not_received;

            if(session->stats.avg_join_delay) {
                join_delays++;
                stats->avg_join_delay += session->stats.avg_join_delay;
                if(session->stats.max_join_delay > stats->max_join_delay) stats->max_join_delay = session->stats.max_join_delay;
                if(stats->min_join_delay) {
                    if(session->stats.min_join_delay < stats->min_join_delay) stats->min_join_delay = session->stats.min_join_delay;
                } else {
                    stats->min_join_delay = session->stats.min_join_delay;
                }

            }
            if(session->stats.avg_leave_delay) {
                leave_delays++;
                stats->avg_leave_delay += session->stats.avg_leave_delay;
                if(session->stats.max_leave_delay > stats->max_leave_delay) stats->max_leave_delay = session->stats.max_leave_delay;
                if(stats->min_leave_delay) {
                    if(session->stats.min_leave_delay < stats->min_leave_delay) stats->min_leave_delay = session->stats.min_leave_delay;
                } else {
                    stats->min_leave_delay = session->stats.min_leave_delay;
                }
            }

            stats->max_join_delay_violations += session->stats.max_join_delay_violations;
            stats->zapping_join_count += session->zapping_join_count;
            stats->zapping_leave_count += session->zapping_leave_count;

            if(reset) {
                session->zapping_count = 0;
                session->zapping_join_delay_sum = 0;
                session->zapping_join_count = 0;
                session->zapping_leave_delay_sum = 0;
                session->zapping_leave_count = 0;
                session->stats.min_join_delay = 0;
                session->stats.avg_join_delay = 0;
                session->stats.max_join_delay = 0;
                session->stats.max_join_delay_violations = 0;
                session->stats.min_leave_delay = 0;
                session->stats.avg_leave_delay = 0;
                session->stats.max_leave_delay = 0;
                session->stats.mc_old_rx_after_first_new = 0;
                session->stats.mc_not_received = 0;

            }
        }
    }

    if(join_delays) {
        stats->avg_join_delay = stats->avg_join_delay / join_delays;
    }
    if(leave_delays) {
        stats->avg_leave_delay = stats->avg_leave_delay / leave_delays;
    }
}

void
bbl_stats_generate(bbl_ctx_s *ctx, bbl_stats_t * stats) {

    bbl_session_s *session;
    bbl_stream *stream;
    struct bbl_interface_ *interface;
    bbl_access_traffic_statistics_s *access_stats;

    struct dict_itor *itor;
    uint32_t i;

    float pps;

    bbl_stats_update_cps(ctx);
    bbl_stats_generate_multicast(ctx, stats, false);

    /* Iterate over all sessions */
    for(i = 0; i < ctx->sessions; i++) {
        session = &ctx->session_list[i];
        if(session) {
            access_stats = &ctx->access_statistics[i];
            /* Session Traffic */
            if(access_stats->ipv4_rx_first_seq) {
                stats->sessions_access_ipv4_rx++;
                stats->avg_access_ipv4_rx_first_seq += access_stats->ipv4_rx_first_seq;
                if(stats->min_access_ipv4_rx_first_seq) {
                    if(access_stats->ipv4_rx_first_seq < stats->min_access_ipv4_rx_first_seq) stats->min_access_ipv4_rx_first_seq = access_stats->ipv4_rx_first_seq;
                } else {
                    stats->min_access_ipv4_rx_first_seq = access_stats->ipv4_rx_first_seq;
                }
                if(access_stats->ipv4_rx_first_seq > stats->max_access_ipv4_rx_first_seq) stats->max_access_ipv4_rx_first_seq = access_stats->ipv4_rx_first_seq;
            }

            if(session->network_ipv4_rx_first_seq) {
                stats->sessions_network_ipv4_rx++;
                stats->avg_network_ipv4_rx_first_seq += session->network_ipv4_rx_first_seq;
                if(stats->min_network_ipv4_rx_first_seq) {
                    if(session->network_ipv4_rx_first_seq < stats->min_network_ipv4_rx_first_seq) stats->min_network_ipv4_rx_first_seq = session->network_ipv4_rx_first_seq;
                } else {
                    stats->min_network_ipv4_rx_first_seq = session->network_ipv4_rx_first_seq;
                }
                if(session->network_ipv4_rx_first_seq > stats->max_network_ipv4_rx_first_seq) stats->max_network_ipv4_rx_first_seq = session->network_ipv4_rx_first_seq;
            }

            if(access_stats->ipv6_rx_first_seq) {
                stats->sessions_access_ipv6_rx++;
                stats->avg_access_ipv6_rx_first_seq += access_stats->ipv6_rx_first_seq;
                if(stats->min_access_ipv6_rx_first_seq) {
                    if(access_stats->ipv6_rx_first_seq < stats->min_access_ipv6_rx_first_seq) stats->min_access_ipv6_rx_first_seq = access_stats->ipv6_rx_first_seq;
                } else {
                    stats->min_access_ipv6_rx_first_seq = access_stats->ipv6_rx_first_seq;
                }
                if(access_stats->ipv6_rx_first_seq > stats->max_access_ipv6_rx_first_seq) stats->max_access_ipv6_rx_first_seq = access_stats->ipv6_rx_first_seq;
            }

            if(session->network_ipv6_rx_first_seq) {
                stats->sessions_network_ipv6_rx++;
                stats->avg_network_ipv6_rx_first_seq += session->network_ipv6_rx_first_seq;
                if(stats->min_network_ipv6_rx_first_seq) {
                    if(session->network_ipv6_rx_first_seq < stats->min_network_ipv6_rx_first_seq) stats->min_network_ipv6_rx_first_seq = session->network_ipv6_rx_first_seq;
                } else {
                    stats->min_network_ipv6_rx_first_seq = session->network_ipv6_rx_first_seq;
                }
                if(session->network_ipv6_rx_first_seq > stats->max_network_ipv6_rx_first_seq) stats->max_network_ipv6_rx_first_seq = session->network_ipv6_rx_first_seq;
            }

            if(access_stats->ipv6pd_rx_first_seq) {
                stats->sessions_access_ipv6pd_rx++;
                stats->avg_access_ipv6pd_rx_first_seq += access_stats->ipv6pd_rx_first_seq;
                if(stats->min_access_ipv6pd_rx_first_seq) {
                    if(access_stats->ipv6pd_rx_first_seq < stats->min_access_ipv6pd_rx_first_seq) stats->min_access_ipv6pd_rx_first_seq = access_stats->ipv6pd_rx_first_seq;
                } else {
                    stats->min_access_ipv6pd_rx_first_seq = access_stats->ipv6pd_rx_first_seq;
                }
                if(access_stats->ipv6pd_rx_first_seq > stats->max_access_ipv6pd_rx_first_seq) stats->max_access_ipv6pd_rx_first_seq = access_stats->ipv6pd_rx_first_seq;
            }

            if(session->network_ipv6pd_rx_first_seq) {
                stats->sessions_network_ipv6pd_rx++;
                stats->avg_network_ipv6pd_rx_first_seq += session->network_ipv6pd_rx_first_seq;
                if(stats->min_network_ipv6pd_rx_first_seq) {
                    if(session->network_ipv6pd_rx_first_seq < stats->min_network_ipv6pd_rx_first_seq) stats->min_network_ipv6pd_rx_first_seq = session->network_ipv6pd_rx_first_seq;
                } else {
                    stats->min_network_ipv6pd_rx_first_seq = session->network_ipv6pd_rx_first_seq;
                }
                if(session->network_ipv6pd_rx_first_seq > stats->max_network_ipv6pd_rx_first_seq) stats->max_network_ipv6pd_rx_first_seq = session->network_ipv6pd_rx_first_seq;
            }
        }
    }

    if(stats->sessions_access_ipv4_rx) {
        stats->avg_access_ipv4_rx_first_seq = stats->avg_access_ipv4_rx_first_seq / stats->sessions_access_ipv4_rx;
    }
    if(stats->sessions_network_ipv4_rx) {
        stats->avg_network_ipv4_rx_first_seq = stats->avg_network_ipv4_rx_first_seq / stats->sessions_network_ipv4_rx;
    }
    if(stats->sessions_access_ipv6_rx) {
        stats->avg_access_ipv6_rx_first_seq = stats->avg_access_ipv6_rx_first_seq / stats->sessions_access_ipv6_rx;
    }
    if(stats->sessions_network_ipv6_rx) {
        stats->avg_network_ipv6_rx_first_seq = stats->avg_network_ipv6_rx_first_seq / stats->sessions_network_ipv6_rx;
    }
    if(stats->sessions_access_ipv6pd_rx) {
        stats->avg_access_ipv6pd_rx_first_seq = stats->avg_access_ipv6pd_rx_first_seq / stats->sessions_access_ipv6pd_rx;
    }
    if(stats->sessions_network_ipv6pd_rx) {
        stats->avg_network_ipv6pd_rx_first_seq = stats->avg_network_ipv6pd_rx_first_seq / stats->sessions_network_ipv6pd_rx;
    }
    
    if(ctx->config.session_traffic_ipv4_pps) {
        pps = ctx->config.session_traffic_ipv4_pps;
        stats->min_access_ipv4_rx_seconds = stats->min_access_ipv4_rx_first_seq / pps;
        stats->avg_access_ipv4_rx_seconds = stats->avg_access_ipv4_rx_first_seq / pps;
        stats->max_access_ipv4_rx_seconds = stats->max_access_ipv4_rx_first_seq / pps;
        stats->min_network_ipv4_rx_seconds = stats->min_network_ipv4_rx_first_seq / pps;
        stats->avg_network_ipv4_rx_seconds = stats->avg_network_ipv4_rx_first_seq / pps;
        stats->max_network_ipv4_rx_seconds = stats->max_network_ipv4_rx_first_seq / pps;
    }
    if(ctx->config.session_traffic_ipv6_pps) {
        pps = ctx->config.session_traffic_ipv6_pps;
        stats->min_access_ipv6_rx_seconds = stats->min_access_ipv6_rx_first_seq / pps;
        stats->avg_access_ipv6_rx_seconds = stats->avg_access_ipv6_rx_first_seq / pps;
        stats->max_access_ipv6_rx_seconds = stats->max_access_ipv6_rx_first_seq / pps;
        stats->min_network_ipv6_rx_seconds = stats->min_network_ipv6_rx_first_seq / pps;
        stats->avg_network_ipv6_rx_seconds = stats->avg_network_ipv6_rx_first_seq / pps;
        stats->max_network_ipv6_rx_seconds = stats->max_network_ipv6_rx_first_seq / pps;
    }
    if(ctx->config.session_traffic_ipv6pd_pps) {
        pps = ctx->config.session_traffic_ipv6pd_pps;
        stats->min_access_ipv6pd_rx_seconds = stats->min_access_ipv6pd_rx_first_seq / pps;
        stats->avg_access_ipv6pd_rx_seconds = stats->avg_access_ipv6pd_rx_first_seq / pps;
        stats->max_access_ipv6pd_rx_seconds = stats->max_access_ipv6pd_rx_first_seq / pps;
        stats->min_network_ipv6pd_rx_seconds = stats->min_network_ipv6pd_rx_first_seq / pps;
        stats->avg_network_ipv6pd_rx_seconds = stats->avg_network_ipv6pd_rx_first_seq / pps;
        stats->max_network_ipv6pd_rx_seconds = stats->max_network_ipv6pd_rx_first_seq / pps;
    }

    for(i = 0; i < ctx->interfaces.network_if_count; i++) {
        interface = ctx->interfaces.network_if[i];
        stats->l2tp_control_tx += interface->stats.l2tp_control_tx;
        stats->l2tp_control_rx += interface->stats.l2tp_control_rx;
        stats->l2tp_control_rx_dup += interface->stats.l2tp_control_rx_dup;
        stats->l2tp_control_rx_ooo += interface->stats.l2tp_control_rx_ooo;
        stats->l2tp_control_retry += interface->stats.l2tp_control_retry;
        stats->l2tp_data_tx += interface->stats.l2tp_data_tx;
        stats->l2tp_data_rx += interface->stats.l2tp_data_rx;
        stats->li_rx += interface->stats.li_rx;
    }

    /* Iterate over all traffic streams */
    itor = dict_itor_new(ctx->stream_flow_dict);
    dict_itor_first(itor);
    for (; dict_itor_valid(itor); dict_itor_next(itor)) {
        stream = (bbl_stream*)*dict_itor_datum(itor);
        if(stream) {
            if(stats->min_stream_loss) {
                if(stream->loss < stats->min_stream_loss) stats->min_stream_loss = stream->loss;
            } else {
                stats->min_stream_loss = stream->loss;
            }
            if(stream->loss > stats->max_stream_loss) stats->max_stream_loss = stream->loss;

            if(stream->rx_first_seq) {
                if(stats->min_stream_rx_first_seq) {
                    if(stream->rx_first_seq < stats->min_stream_rx_first_seq) stats->min_stream_rx_first_seq = stream->rx_first_seq;
                } else {
                    stats->min_stream_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > stats->max_stream_rx_first_seq) stats->max_stream_rx_first_seq = stream->rx_first_seq;

                if(stats->min_stream_delay_ns) {
                    if(stream->min_delay_ns < stats->min_stream_delay_ns) stats->min_stream_delay_ns = stream->min_delay_ns;
                } else {
                    stats->min_stream_delay_ns = stream->min_delay_ns;
                }
                if(stream->max_delay_ns > stats->max_stream_delay_ns) stats->max_stream_delay_ns = stream->max_delay_ns;
            }
        }
    }
    dict_itor_free(itor);
}

void
bbl_stats_stdout(bbl_ctx_s *ctx, bbl_stats_t * stats) {
    struct bbl_interface_ *interface;
    int i;

    printf("%s", banner);
    printf("Report:\n\n");
    if(ctx->sessions) {
        printf("Sessions PPPoE: %u IPoE: %u\n", ctx->sessions_pppoe, ctx->sessions_ipoe);
        printf("Sessions established: %u/%u\n", ctx->sessions_established_max, ctx->sessions);
        printf("DHCPv6 sessions established: %u\n", ctx->dhcpv6_established_max);
        printf("Setup Time: %u ms\n", ctx->stats.setup_time);
        printf("Setup Rate: %0.02lf CPS (MIN: %0.02lf AVG: %0.02lf MAX: %0.02lf)\n",
            ctx->stats.cps, ctx->stats.cps_min, ctx->stats.cps_avg, ctx->stats.cps_max);
        printf("Flapped: %u\n", ctx->sessions_flapped);
    }

    if(dict_count(ctx->li_flow_dict)) {
        printf("\nLI Statistics:\n");
        printf("  Flows:        %10lu\n", dict_count(ctx->li_flow_dict));
        printf("  RX Packets:   %10lu\n", stats->li_rx);
    }
    if(ctx->config.l2tp_server) {
        printf("\nL2TP LNS Statistics:\n");
        printf("  Tunnels:      %10u\n", ctx->l2tp_tunnels_max);
        printf("  Established:  %10u\n", ctx->l2tp_tunnels_established_max);
        printf("  Sessions:     %10u\n", ctx->l2tp_sessions_max);
        printf("  Packets:\n");
        printf("    TX Control:      %10u packets (%u retries)\n",
            stats->l2tp_control_tx, stats->l2tp_control_retry);
        printf("    RX Control:      %10u packets (%u duplicate %u out-of-order)\n",
            stats->l2tp_control_rx, stats->l2tp_control_rx_dup, stats->l2tp_control_rx_ooo);
        printf("    TX Data:         %10lu packets\n", stats->l2tp_data_tx);
        printf("    RX Data:         %10lu packets\n", stats->l2tp_data_rx);
    }

    for(i=0; i < ctx->interfaces.network_if_count; i++) {
        interface = ctx->interfaces.network_if[i];
        if(interface) {
            printf("\nNetwork Interface ( %s ):\n", interface->name);
            printf("  TX:                %10lu packets\n", interface->stats.packets_tx);
            printf("  RX:                %10lu packets\n", interface->stats.packets_rx);
            if(ctx->stats.stream_traffic_flows) {
                printf("  TX Stream:         %10lu packets\n",
                    interface->stats.stream_tx);
                printf("  RX Stream:         %10lu packets (%lu loss)\n",
                    interface->stats.stream_rx, interface->stats.stream_loss);
            }
            if(ctx->stats.session_traffic_flows) {
                printf("  TX Session:        %10lu packets\n",
                    interface->stats.session_ipv4_tx);
                printf("  RX Session:        %10lu packets (%lu loss)\n",
                    interface->stats.session_ipv4_rx, interface->stats.session_ipv4_loss);
                printf("  TX Session IPv6:   %10lu packets\n",
                    interface->stats.session_ipv6_tx);
                printf("  RX Session IPv6:   %10lu packets (%lu loss)\n",
                    interface->stats.session_ipv6_rx, interface->stats.session_ipv6_loss);
                printf("  TX Session IPv6PD: %10lu packets\n",
                    interface->stats.session_ipv6pd_tx);
                printf("  RX Session IPv6PD: %10lu packets (%lu loss)\n",
                    interface->stats.session_ipv6pd_rx, interface->stats.session_ipv6pd_loss);
            }
            printf("  TX Multicast:      %10lu packets\n",
                interface->stats.mc_tx);
            printf("  RX Drop Unknown:   %10lu packets\n",
                interface->stats.packets_rx_drop_unknown);
            printf("  TX Encode Error:   %10lu\n", interface->stats.encode_errors);
            printf("  RX Decode Error:   %10lu packets\n",
                interface->stats.packets_rx_drop_decode_error);
            printf("  TX Send Failed:    %10lu\n", interface->stats.sendto_failed);
            printf("  TX No Buffer:      %10lu\n", interface->stats.no_tx_buffer);
            printf("  TX Poll Kernel:    %10lu\n", interface->stats.poll_tx);
            printf("  RX Poll Kernel:    %10lu\n", interface->stats.poll_rx);
        }
    }

    for(i=0; i < ctx->interfaces.access_if_count; i++) {
        interface = ctx->interfaces.access_if[i];
        if(interface) {
            printf("\nAccess Interface ( %s ):\n", interface->name);
            printf("  TX:                %10lu packets\n", interface->stats.packets_tx);
            printf("  RX:                %10lu packets\n", interface->stats.packets_rx);
            if(ctx->stats.stream_traffic_flows) {
                printf("  TX Stream:         %10lu packets\n",
                    interface->stats.stream_tx);
                printf("  RX Stream:         %10lu packets (%lu loss)\n",
                    interface->stats.stream_rx, interface->stats.stream_loss);
            }
            if(ctx->stats.session_traffic_flows) {
                printf("  TX Session:        %10lu packets\n", interface->stats.session_ipv4_tx);
                printf("  RX Session:        %10lu packets (%lu loss, %lu wrong session)\n", interface->stats.session_ipv4_rx,
                    interface->stats.session_ipv4_loss, interface->stats.session_ipv4_wrong_session);
                printf("  TX Session IPv6:   %10lu packets\n", interface->stats.session_ipv6_tx);
                printf("  RX Session IPv6:   %10lu packets (%lu loss, %lu wrong session)\n", interface->stats.session_ipv6_rx,
                    interface->stats.session_ipv6_loss, interface->stats.session_ipv6_wrong_session);
                printf("  TX Session IPv6PD: %10lu packets\n", interface->stats.session_ipv6pd_tx);
                printf("  RX Session IPv6PD: %10lu packets (%lu loss, %lu wrong session)\n", interface->stats.session_ipv6pd_rx,
                    interface->stats.session_ipv6pd_loss, interface->stats.session_ipv6pd_wrong_session);
            }
            printf("  RX Multicast:      %10lu packets (%lu loss)\n", interface->stats.mc_rx,
                interface->stats.mc_loss);
            printf("  RX Drop Unknown:   %10lu packets\n", interface->stats.packets_rx_drop_unknown);
            printf("  TX Encode Error:   %10lu packets\n", interface->stats.encode_errors);
            printf("  RX Decode Error:   %10lu packets\n", interface->stats.packets_rx_drop_decode_error);
            printf("  TX Send Failed:    %10lu\n", interface->stats.sendto_failed);
            printf("  TX No Buffer:      %10lu\n", interface->stats.no_tx_buffer);
            printf("  TX Poll Kernel:    %10lu\n", interface->stats.poll_tx);
            printf("  RX Poll Kernel:    %10lu\n", interface->stats.poll_rx);
            printf("\n  Access Interface Protocol Packet Stats:\n");
            printf("    ARP    TX: %10u RX: %10u\n", interface->stats.arp_tx, interface->stats.arp_rx);
            printf("    PADI   TX: %10u RX: %10u\n", interface->stats.padi_tx, 0);
            printf("    PADO   TX: %10u RX: %10u\n", 0, interface->stats.pado_rx);
            printf("    PADR   TX: %10u RX: %10u\n", interface->stats.padr_tx, 0);
            printf("    PADS   TX: %10u RX: %10u\n", 0, interface->stats.pads_rx);
            printf("    PADT   TX: %10u RX: %10u\n", interface->stats.padt_tx, interface->stats.padt_rx);
            printf("    LCP    TX: %10u RX: %10u\n", interface->stats.lcp_tx, interface->stats.lcp_rx);
            printf("    PAP    TX: %10u RX: %10u\n", interface->stats.pap_tx, interface->stats.pap_rx);
            printf("    CHAP   TX: %10u RX: %10u\n", interface->stats.chap_tx, interface->stats.chap_rx);
            printf("    IPCP   TX: %10u RX: %10u\n", interface->stats.ipcp_tx, interface->stats.ipcp_rx);
            printf("    IP6CP  TX: %10u RX: %10u\n", interface->stats.ip6cp_tx, interface->stats.ip6cp_rx);
            printf("    IGMP   TX: %10u RX: %10u\n", interface->stats.igmp_tx, interface->stats.igmp_rx);
            printf("    ICMP   TX: %10u RX: %10u\n", interface->stats.icmp_tx, interface->stats.icmp_rx);
            printf("    DHCP   TX: %10u RX: %10u\n", interface->stats.dhcp_tx, interface->stats.dhcp_rx);
            printf("    DHCPv6 TX: %10u RX: %10u\n", interface->stats.dhcpv6_tx, interface->stats.dhcpv6_rx);
            printf("    ICMPv6 TX: %10u RX: %10u\n", interface->stats.icmpv6_tx, interface->stats.icmpv6_rx);
            printf("    IPv4 Fragmented       RX: %10u\n", interface->stats.ipv4_fragmented_rx);
            printf("\n  Access Interface Protocol Timeout Stats:\n");
            printf("    LCP Echo Request: %10u\n", interface->stats.lcp_echo_timeout);
            printf("    LCP Request:      %10u\n", interface->stats.lcp_timeout);
            printf("    IPCP Request:     %10u\n", interface->stats.ipcp_timeout);
            printf("    IP6CP Request:    %10u\n", interface->stats.ip6cp_timeout);
            printf("    PAP:              %10u\n", interface->stats.pap_timeout);
            printf("    CHAP:             %10u\n", interface->stats.chap_timeout);
            printf("    DHCP Request:     %10u\n", interface->stats.dhcp_timeout);
            printf("    DHCPv6 Request:   %10u\n", interface->stats.dhcpv6_timeout);
            printf("    ICMPv6 RS:        %10u\n", interface->stats.icmpv6_rs_timeout);
        }
    }

    for(i=0; i < ctx->interfaces.a10nsp_if_count; i++) {
        interface = ctx->interfaces.a10nsp_if[i];
        if(interface) {
            printf("\nA10NSP Interface ( %s ):\n", interface->name);
            printf("  TX:                %10lu packets\n", interface->stats.packets_tx);
            printf("  RX:                %10lu packets\n", interface->stats.packets_rx);
            if(ctx->stats.stream_traffic_flows) {
                printf("  TX Stream:         %10lu packets\n",
                    interface->stats.stream_tx);
                printf("  RX Stream:         %10lu packets (%lu loss)\n",
                    interface->stats.stream_rx, interface->stats.stream_loss);
            }
            if(ctx->stats.session_traffic_flows) {
                printf("  TX Session:        %10lu packets\n",
                    interface->stats.session_ipv4_tx);
                printf("  RX Session:        %10lu packets (%lu loss)\n",
                    interface->stats.session_ipv4_rx, interface->stats.session_ipv4_loss);
                printf("  TX Session IPv6:   %10lu packets\n",
                    interface->stats.session_ipv6_tx);
                printf("  RX Session IPv6:   %10lu packets (%lu loss)\n",
                    interface->stats.session_ipv6_rx, interface->stats.session_ipv6_loss);
                printf("  TX Session IPv6PD: %10lu packets\n",
                    interface->stats.session_ipv6pd_tx);
                printf("  RX Session IPv6PD: %10lu packets (%lu loss)\n",
                    interface->stats.session_ipv6pd_rx, interface->stats.session_ipv6pd_loss);

            }
            printf("  RX Drop Unknown:   %10lu packets\n", interface->stats.packets_rx_drop_unknown);
            printf("  TX Encode Error:   %10lu packets\n", interface->stats.encode_errors);
            printf("  RX Decode Error:   %10lu packets\n", interface->stats.packets_rx_drop_decode_error);
            printf("  TX Send Failed:    %10lu\n", interface->stats.sendto_failed);
            printf("  TX No Buffer:      %10lu\n", interface->stats.no_tx_buffer);
            printf("  TX Poll Kernel:    %10lu\n", interface->stats.poll_tx);
            printf("  RX Poll Kernel:    %10lu\n", interface->stats.poll_rx);
        }
    }

    if(ctx->stats.session_traffic_flows) {
        printf("\nSession Traffic:\n");
        printf("  Config:\n");
        printf("    IPv4    PPS:    %8u\n", ctx->config.session_traffic_ipv4_pps);
        printf("    IPv6    PPS:    %8u\n", ctx->config.session_traffic_ipv6_pps);
        printf("    IPv6PD  PPS:    %8u\n", ctx->config.session_traffic_ipv6pd_pps);
        printf("  Verified Traffic Flows: %u/%u\n",
            ctx->stats.session_traffic_flows_verified, ctx->stats.session_traffic_flows);
        printf("    Access  IPv4:   %8u\n", stats->sessions_access_ipv4_rx);
        printf("    Access  IPv6:   %8u\n", stats->sessions_access_ipv6_rx);
        printf("    Access  IPv6PD: %8u\n", stats->sessions_access_ipv6pd_rx);
        printf("    Network IPv4:   %8u\n", stats->sessions_network_ipv4_rx);
        printf("    Network IPv6:   %8u\n", stats->sessions_network_ipv6_rx);
        printf("    Network IPv6PD: %8u\n", stats->sessions_network_ipv6pd_rx);
        printf("  First Sequence Number Received:\n");
        printf("    Access  IPv4    MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_access_ipv4_rx_first_seq, stats->min_access_ipv4_rx_seconds,
            stats->avg_access_ipv4_rx_first_seq, stats->avg_access_ipv4_rx_seconds,
            stats->max_access_ipv4_rx_first_seq, stats->max_access_ipv4_rx_seconds);
        printf("    Access  IPv6    MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_access_ipv6_rx_first_seq, stats->min_access_ipv6_rx_seconds,
            stats->avg_access_ipv6_rx_first_seq, stats->avg_access_ipv6_rx_seconds,
            stats->max_access_ipv6_rx_first_seq, stats->max_access_ipv6_rx_seconds);
        printf("    Access  IPv6PD  MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_access_ipv6pd_rx_first_seq, stats->min_access_ipv6pd_rx_seconds,
            stats->avg_access_ipv6pd_rx_first_seq, stats->avg_access_ipv6pd_rx_seconds,
            stats->max_access_ipv6pd_rx_first_seq, stats->max_access_ipv6pd_rx_seconds);
        printf("    Network IPv4    MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_network_ipv4_rx_first_seq, stats->min_network_ipv4_rx_seconds,
            stats->avg_network_ipv4_rx_first_seq, stats->avg_network_ipv4_rx_seconds,
            stats->max_network_ipv4_rx_first_seq, stats->max_network_ipv4_rx_seconds);
        printf("    Network IPv6    MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_network_ipv6_rx_first_seq, stats->min_network_ipv6_rx_seconds,
            stats->avg_network_ipv6_rx_first_seq, stats->avg_network_ipv6_rx_seconds,
            stats->max_network_ipv6_rx_first_seq, stats->max_network_ipv6_rx_seconds);
        printf("    Network IPv6PD  MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_network_ipv6pd_rx_first_seq, stats->min_network_ipv6pd_rx_seconds,
            stats->avg_network_ipv6pd_rx_first_seq, stats->avg_network_ipv6pd_rx_seconds,
            stats->max_network_ipv6pd_rx_first_seq, stats->max_network_ipv6pd_rx_seconds);
    }

    if(ctx->stats.stream_traffic_flows) {
        printf("\nTraffic Streams:\n");
        printf("  Verified Traffic Flows: %u/%u\n",
            ctx->stats.stream_traffic_flows_verified, ctx->stats.stream_traffic_flows);
        printf("  First Sequence Number Received  MIN: %8lu MAX: %8lu\n",
            stats->min_stream_rx_first_seq,
            stats->max_stream_rx_first_seq);
        printf("  Flow Receive Packet Loss        MIN: %8lu MAX: %8lu\n",
            stats->min_stream_loss,
            stats->max_stream_loss);
        printf("  Flow Receive Delay (msec)       MIN: %8.3f MAX: %8.3f\n",
               (double)stats->min_stream_delay_ns / (double)MSEC,
               (double)stats->max_stream_delay_ns / (double)MSEC);
    }

    if(ctx->config.igmp_group_count > 1) {
        printf("\nIGMP Config:\n");
        printf("  Version: %d\n", ctx->config.igmp_version);
        printf("  Start Delay: %us\n", ctx->config.igmp_start_delay);
        printf("  Group Count: %u \n", ctx->config.igmp_group_count);
        printf("  Zapping Interval: %us\n", ctx->config.igmp_zap_interval);
        printf("  Zapping Count: %u \n", ctx->config.igmp_zap_count);
        printf("  Zapping Channel View Duration: %us\n", ctx->config.igmp_zap_view_duration);
        if(ctx->config.igmp_zap_interval > 0) {
            printf("\nIGMP Zapping Stats:\n");
            printf("  Join Delay:\n");
            printf("    MIN: %u ms\n", stats->min_join_delay);
            printf("    AVG: %u ms\n", stats->avg_join_delay);
            printf("    MAX: %u ms\n", stats->max_join_delay);

            if(ctx->config.igmp_max_join_delay) {
                printf("    VIOLATIONS: %u/%u (> %u ms)\n", 
                    stats->max_join_delay_violations, 
                    stats->zapping_join_count,
                    ctx->config.igmp_max_join_delay);
            }

            printf("  Leave Delay:\n");
            printf("    MIN: %u ms\n", stats->min_leave_delay);
            printf("    AVG: %u ms\n", stats->avg_leave_delay);
            printf("    MAX: %u ms\n", stats->max_leave_delay);
            printf("  Multicast:\n");
            printf("    Overlap: %u packets\n", stats->mc_old_rx_after_first_new);
            printf("    Not Received: %u\n", stats->mc_not_received);
        }
    }
}

void
bbl_stats_json(bbl_ctx_s *ctx, bbl_stats_t * stats) {
    struct bbl_interface_ *interface;
    bbl_session_s *session;
    bbl_stream *stream;

    struct dict_itor *itor;
    uint32_t i;

    json_t *root        = NULL;
    json_t *jobj        = NULL;
    json_t *jobj_array  = NULL;
    json_t *jobj_sub    = NULL;
    json_t *jobj_sub2   = NULL;

    if(!ctx->config.json_report_filename) return;

    root = json_object();

    jobj = json_object();
    if(ctx->sessions) {
        json_object_set(jobj, "sessions", json_integer(ctx->config.sessions));
        json_object_set(jobj, "sessions-pppoe", json_integer(ctx->sessions_pppoe));
        json_object_set(jobj, "sessions-ipoe", json_integer(ctx->sessions_ipoe));
        json_object_set(jobj, "sessions-established", json_integer(ctx->sessions_established_max));
        json_object_set(jobj, "sessions-flapped", json_integer(ctx->sessions_flapped));
        json_object_set(jobj, "setup-time-ms", json_integer(ctx->stats.setup_time));
        json_object_set(jobj, "setup-rate-cps", json_real(ctx->stats.cps));
        json_object_set(jobj, "setup-rate-cps-min", json_real(ctx->stats.cps_min));
        json_object_set(jobj, "setup-rate-cps-avg", json_real(ctx->stats.cps_avg));
        json_object_set(jobj, "setup-rate-cps-max", json_real(ctx->stats.cps_max));
        json_object_set(jobj, "dhcp-sessions-established", json_integer(ctx->dhcp_established_max));
        json_object_set(jobj, "dhcpv6-sessions-established", json_integer(ctx->dhcpv6_established_max));
    }
    if(dict_count(ctx->li_flow_dict)) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "flows", json_integer(dict_count(ctx->li_flow_dict)));
        json_object_set(jobj_sub, "rx-packets", json_integer(stats->li_rx));
        json_object_set(jobj, "li-statistics", jobj_sub);
    }
    if(ctx->config.l2tp_server) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "tunnels", json_integer(ctx->l2tp_tunnels_max));
        json_object_set(jobj_sub, "tunnels-established", json_integer(ctx->l2tp_tunnels_established_max));
        json_object_set(jobj_sub, "sessions", json_integer(ctx->l2tp_sessions_max));
        json_object_set(jobj_sub, "tx-control-packets", json_integer(stats->l2tp_control_tx));
        json_object_set(jobj_sub, "tx-control-packets-retry", json_integer(stats->l2tp_control_retry));
        json_object_set(jobj_sub, "rx-control-packets", json_integer(stats->l2tp_control_rx));
        json_object_set(jobj_sub, "rx-control-packets-duplicate", json_integer(stats->l2tp_control_rx_dup));
        json_object_set(jobj_sub, "rx-control-packets-out-of-order", json_integer(stats->l2tp_control_rx_ooo));
        json_object_set(jobj_sub, "tx-data-packets", json_integer(stats->l2tp_data_tx));
        json_object_set(jobj_sub, "rx-data-packets", json_integer(stats->l2tp_data_rx));
        json_object_set(jobj, "l2tp", jobj_sub);
    }

    jobj_array = json_array();
    for(i=0; i < ctx->interfaces.network_if_count; i++) {
        interface = ctx->interfaces.network_if[i];
        if (interface) {
            jobj_sub = json_object();
            json_object_set(jobj_sub, "name", json_string(interface->name));
            json_object_set(jobj_sub, "tx-packets", json_integer(interface->stats.packets_tx));
            json_object_set(jobj_sub, "rx-packets", json_integer(interface->stats.packets_rx));
            if(ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-stream-packets", json_integer(interface->stats.stream_tx));
                json_object_set(jobj_sub, "rx-stream-packets", json_integer(interface->stats.stream_rx));
                json_object_set(jobj_sub, "rx-stream-packets-loss", json_integer(interface->stats.stream_loss));
            }
            if(ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-session-packets", json_integer(interface->stats.session_ipv4_tx));
                json_object_set(jobj_sub, "rx-session-packets", json_integer(interface->stats.session_ipv4_rx));
                json_object_set(jobj_sub, "rx-session-packets-loss", json_integer(interface->stats.session_ipv4_loss));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max", json_integer(interface->stats.rate_session_ipv4_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max", json_integer(interface->stats.rate_session_ipv4_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6", json_integer(interface->stats.session_ipv6_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6", json_integer(interface->stats.session_ipv6_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-loss", json_integer(interface->stats.session_ipv6_loss));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max-ipv6", json_integer(interface->stats.rate_session_ipv6_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max-ipv6", json_integer(interface->stats.rate_session_ipv6_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd", json_integer(interface->stats.session_ipv6pd_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd", json_integer(interface->stats.session_ipv6pd_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-loss", json_integer(interface->stats.session_ipv6pd_loss));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max-ipv6pd", json_integer(interface->stats.rate_session_ipv6pd_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max-ipv6pd", json_integer(interface->stats.rate_session_ipv6pd_rx.avg_max));
            }
            json_object_set(jobj_sub, "tx-multicast-packets", json_integer(interface->stats.mc_tx));
            json_array_append(jobj_array, jobj_sub);
        }
    }
    json_object_set(jobj, "network-interfaces", jobj_array);

    jobj_array = json_array();
    for(i=0; i < ctx->interfaces.access_if_count; i++) {
        interface = ctx->interfaces.access_if[i];
        if (interface) {
            jobj_sub = json_object();
            json_object_set(jobj_sub, "name", json_string(interface->name));
            json_object_set(jobj_sub, "tx-packets", json_integer(interface->stats.packets_tx));
            json_object_set(jobj_sub, "rx-packets", json_integer(interface->stats.packets_rx));
            if(ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-stream-packets", json_integer(interface->stats.stream_tx));
                json_object_set(jobj_sub, "rx-stream-packets", json_integer(interface->stats.stream_rx));
                json_object_set(jobj_sub, "rx-stream-packets-loss", json_integer(interface->stats.stream_loss));
            }
            if(ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-session-packets", json_integer(interface->stats.session_ipv4_tx));
                json_object_set(jobj_sub, "rx-session-packets", json_integer(interface->stats.session_ipv4_rx));
                json_object_set(jobj_sub, "rx-session-packets-loss", json_integer(interface->stats.session_ipv4_loss));
                json_object_set(jobj_sub, "rx-session-packets-wrong-session", json_integer(interface->stats.session_ipv4_wrong_session));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max", json_integer(interface->stats.rate_session_ipv4_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max", json_integer(interface->stats.rate_session_ipv4_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6", json_integer(interface->stats.session_ipv6_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6", json_integer(interface->stats.session_ipv6_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-loss", json_integer(interface->stats.session_ipv6_loss));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-wrong-session", json_integer(interface->stats.session_ipv6_wrong_session));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max-ipv6", json_integer(interface->stats.rate_session_ipv6_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max-ipv6", json_integer(interface->stats.rate_session_ipv6_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd", json_integer(interface->stats.session_ipv6pd_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd", json_integer(interface->stats.session_ipv6pd_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-loss", json_integer(interface->stats.session_ipv6pd_loss));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-wrong-session", json_integer(interface->stats.session_ipv6pd_wrong_session));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max-ipv6pd", json_integer(interface->stats.rate_session_ipv6pd_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max-ipv6pd", json_integer(interface->stats.rate_session_ipv6pd_rx.avg_max));
            }
            json_object_set(jobj_sub, "rx-multicast-packets", json_integer(interface->stats.mc_rx));
            json_object_set(jobj_sub, "rx-multicast-packets-loss", json_integer(interface->stats.mc_loss));
            jobj_sub2 = json_object();
            json_object_set(jobj_sub2, "arp-tx", json_integer(interface->stats.arp_tx));
            json_object_set(jobj_sub2, "arp-rx", json_integer(interface->stats.arp_rx));
            json_object_set(jobj_sub2, "padi-tx", json_integer(interface->stats.padi_tx));
            json_object_set(jobj_sub2, "pado-rx", json_integer(interface->stats.pado_rx));
            json_object_set(jobj_sub2, "padr-tx", json_integer(interface->stats.padr_tx));
            json_object_set(jobj_sub2, "pads-rx", json_integer(interface->stats.pads_rx));
            json_object_set(jobj_sub2, "padt-tx", json_integer(interface->stats.padt_tx));
            json_object_set(jobj_sub2, "padt-rx", json_integer(interface->stats.padt_rx));
            json_object_set(jobj_sub2, "lcp-tx", json_integer(interface->stats.lcp_tx));
            json_object_set(jobj_sub2, "lcp-rx", json_integer(interface->stats.lcp_rx));
            json_object_set(jobj_sub2, "pap-tx", json_integer(interface->stats.pap_tx));
            json_object_set(jobj_sub2, "pap-rx", json_integer(interface->stats.pap_rx));
            json_object_set(jobj_sub2, "chap-tx", json_integer(interface->stats.chap_tx));
            json_object_set(jobj_sub2, "chap-rx", json_integer(interface->stats.chap_rx));
            json_object_set(jobj_sub2, "ipcp-tx", json_integer(interface->stats.ipcp_tx));
            json_object_set(jobj_sub2, "ipcp-rx", json_integer(interface->stats.ipcp_rx));
            json_object_set(jobj_sub2, "ip6cp-tx", json_integer(interface->stats.ip6cp_tx));
            json_object_set(jobj_sub2, "ip6cp-rx", json_integer(interface->stats.ip6cp_rx));
            json_object_set(jobj_sub2, "igmp-tx", json_integer(interface->stats.igmp_tx));
            json_object_set(jobj_sub2, "igmp-rx", json_integer(interface->stats.igmp_rx));
            json_object_set(jobj_sub2, "icmp-tx", json_integer(interface->stats.icmp_tx));
            json_object_set(jobj_sub2, "icmp-rx", json_integer(interface->stats.icmp_rx));
            json_object_set(jobj_sub2, "dhcp-tx", json_integer(interface->stats.dhcp_tx));
            json_object_set(jobj_sub2, "dhcp-rx", json_integer(interface->stats.dhcp_rx));
            json_object_set(jobj_sub2, "dhcpv6-tx", json_integer(interface->stats.dhcpv6_tx));
            json_object_set(jobj_sub2, "dhcpv6-rx", json_integer(interface->stats.dhcpv6_rx));
            json_object_set(jobj_sub2, "icmpv6-tx", json_integer(interface->stats.icmpv6_tx));
            json_object_set(jobj_sub2, "icmpv6-rx", json_integer(interface->stats.icmpv6_rx));
            json_object_set(jobj_sub2, "ipv4-fragmented-rx", json_integer(interface->stats.ipv4_fragmented_rx));
            json_object_set(jobj_sub2, "lcp-echo-timeout", json_integer(interface->stats.lcp_echo_timeout));
            json_object_set(jobj_sub2, "lcp-request-timeout", json_integer(interface->stats.lcp_timeout));
            json_object_set(jobj_sub2, "ipcp-request-timeout", json_integer(interface->stats.ipcp_timeout));
            json_object_set(jobj_sub2, "ip6cp-request-timeout", json_integer(interface->stats.ip6cp_timeout));
            json_object_set(jobj_sub2, "pap-timeout", json_integer(interface->stats.pap_timeout));
            json_object_set(jobj_sub2, "chap-timeout", json_integer(interface->stats.chap_timeout));
            json_object_set(jobj_sub2, "dhcp-timeout", json_integer(interface->stats.dhcp_timeout));
            json_object_set(jobj_sub2, "dhcpv6-timeout", json_integer(interface->stats.dhcpv6_timeout));
            json_object_set(jobj_sub2, "icmpv6-rs-timeout", json_integer(interface->stats.dhcpv6_timeout));
            json_object_set(jobj_sub, "protocol-stats", jobj_sub2);
            json_array_append(jobj_array, jobj_sub);
        }
    }
    json_object_set(jobj, "access-interfaces", jobj_array);

    jobj_array = json_array();
    for(i=0; i < ctx->interfaces.a10nsp_if_count; i++) {
        interface = ctx->interfaces.a10nsp_if[i];
        if (interface) {
            jobj_sub = json_object();
            json_object_set(jobj_sub, "name", json_string(interface->name));
            json_object_set(jobj_sub, "tx-packets", json_integer(interface->stats.packets_tx));
            json_object_set(jobj_sub, "rx-packets", json_integer(interface->stats.packets_rx));
            if(ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-stream-packets", json_integer(interface->stats.stream_tx));
                json_object_set(jobj_sub, "rx-stream-packets", json_integer(interface->stats.stream_rx));
                json_object_set(jobj_sub, "rx-stream-packets-loss", json_integer(interface->stats.stream_loss));
            }
            if(ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-session-packets", json_integer(interface->stats.session_ipv4_tx));
                json_object_set(jobj_sub, "rx-session-packets", json_integer(interface->stats.session_ipv4_rx));
                json_object_set(jobj_sub, "rx-session-packets-loss", json_integer(interface->stats.session_ipv4_loss));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max", json_integer(interface->stats.rate_session_ipv4_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max", json_integer(interface->stats.rate_session_ipv4_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6", json_integer(interface->stats.session_ipv6_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6", json_integer(interface->stats.session_ipv6_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-loss", json_integer(interface->stats.session_ipv6_loss));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max-ipv6", json_integer(interface->stats.rate_session_ipv6_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max-ipv6", json_integer(interface->stats.rate_session_ipv6_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd", json_integer(interface->stats.session_ipv6pd_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd", json_integer(interface->stats.session_ipv6pd_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-loss", json_integer(interface->stats.session_ipv6pd_loss));
                json_object_set(jobj_sub, "tx-session-packets-avg-pps-max-ipv6pd", json_integer(interface->stats.rate_session_ipv6pd_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-avg-pps-max-ipv6pd", json_integer(interface->stats.rate_session_ipv6pd_rx.avg_max));
            }
            json_array_append(jobj_array, jobj_sub);
        }
    }
    json_object_set(jobj, "a10nsp-interfaces", jobj_array);

    if(ctx->stats.session_traffic_flows) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "config-ipv4-pps", json_integer(ctx->config.session_traffic_ipv4_pps));
        json_object_set(jobj_sub, "config-ipv6-pps", json_integer(ctx->config.session_traffic_ipv6_pps));
        json_object_set(jobj_sub, "config-ipv6pd-pps", json_integer(ctx->config.session_traffic_ipv6pd_pps));
        json_object_set(jobj_sub, "total-flows", json_integer(ctx->stats.session_traffic_flows));
        json_object_set(jobj_sub, "verified-flows", json_integer(ctx->stats.session_traffic_flows_verified));
        json_object_set(jobj_sub, "verified-flows-access-ipv4", json_integer(stats->sessions_access_ipv4_rx));
        json_object_set(jobj_sub, "verified-flows-access-ipv6", json_integer(stats->sessions_access_ipv6_rx));
        json_object_set(jobj_sub, "verified-flows-access-ipv6pd", json_integer(stats->sessions_access_ipv6pd_rx));
        json_object_set(jobj_sub, "verified-flows-network-ipv4", json_integer(stats->sessions_network_ipv4_rx));
        json_object_set(jobj_sub, "verified-flows-network-ipv6", json_integer(stats->sessions_network_ipv6_rx));
        json_object_set(jobj_sub, "verified-flows-network-ipv6pd", json_integer(stats->sessions_network_ipv6pd_rx));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv4-min", json_integer(stats->min_access_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv4-avg", json_integer(stats->avg_access_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv4-max", json_integer(stats->max_access_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6-min", json_integer(stats->min_access_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6-avg", json_integer(stats->avg_access_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6-max", json_integer(stats->max_access_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6pd-min", json_integer(stats->min_access_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6pd-avg", json_integer(stats->avg_access_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6pd-max", json_integer(stats->max_access_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv4-min", json_integer(stats->min_network_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv4-avg", json_integer(stats->avg_network_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv4-max", json_integer(stats->max_network_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6-min", json_integer(stats->min_network_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6-avg", json_integer(stats->avg_network_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6-max", json_integer(stats->max_network_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6pd-min", json_integer(stats->min_network_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6pd-avg", json_integer(stats->avg_network_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6pd-max", json_integer(stats->max_network_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv4-min-seconds", json_real(stats->min_access_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv4-avg-seconds", json_real(stats->avg_access_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv4-max-seconds", json_real(stats->max_access_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6-min-seconds", json_real(stats->min_access_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6-avg-seconds", json_real(stats->avg_access_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6-max-seconds", json_real(stats->max_access_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6pd-min-seconds", json_real(stats->min_access_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6pd-avg-seconds", json_real(stats->avg_access_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-access-ipv6pd-max-seconds", json_real(stats->max_access_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv4-min-seconds", json_real(stats->min_network_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv4-avg-seconds", json_real(stats->avg_network_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv4-max-seconds", json_real(stats->max_network_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6-min-seconds", json_real(stats->min_network_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6-avg-seconds", json_real(stats->avg_network_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6-max-seconds", json_real(stats->max_network_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6pd-min-seconds", json_real(stats->min_network_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6pd-avg-seconds", json_real(stats->avg_network_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-network-ipv6pd-max-seconds", json_real(stats->max_network_ipv6pd_rx_seconds));
        json_object_set(jobj, "session-traffic", jobj_sub);
    }

    if(ctx->stats.stream_traffic_flows) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "total-flows", json_integer(ctx->stats.stream_traffic_flows));
        json_object_set(jobj_sub, "verified-flows", json_integer(ctx->stats.stream_traffic_flows_verified));
        json_object_set(jobj_sub, "first-seq-rx-min", json_integer(stats->min_stream_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-max", json_integer(stats->max_stream_rx_first_seq));
        json_object_set(jobj_sub, "flow-rx-packet-loss-min", json_integer(stats->min_stream_loss));
        json_object_set(jobj_sub, "flow-rx-packet-loss-max", json_integer(stats->max_stream_loss));
        json_object_set(jobj_sub, "flow-rx-delay-min", json_integer(stats->min_stream_delay_ns));
        json_object_set(jobj_sub, "flow-rx-delay-max", json_integer(stats->max_stream_delay_ns));
        json_object_set(jobj, "traffic-streams", jobj_sub);
    }

    if(ctx->config.igmp_group_count > 1) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "config-version", json_integer(ctx->config.igmp_version));
        json_object_set(jobj_sub, "config-start-delay", json_integer(ctx->config.igmp_start_delay));
        json_object_set(jobj_sub, "config-group-count", json_integer(ctx->config.igmp_group_count));
        json_object_set(jobj_sub, "config-zapping-interval", json_integer(ctx->config.igmp_zap_interval));
        json_object_set(jobj_sub, "config-zapping-count", json_integer(ctx->config.igmp_zap_count));
        json_object_set(jobj_sub, "config-zapping-view-duration", json_integer(ctx->config.igmp_zap_view_duration));
        if(ctx->config.igmp_zap_interval > 0) {
            json_object_set(jobj_sub, "zapping-join-delay-ms-min", json_integer(stats->min_join_delay));
            json_object_set(jobj_sub, "zapping-join-delay-ms-avg", json_integer(stats->avg_join_delay));
            json_object_set(jobj_sub, "zapping-join-delay-ms-max", json_integer(stats->max_join_delay));
            json_object_set(jobj_sub, "zapping-join-delay-violations", json_integer(stats->max_join_delay_violations));
            json_object_set(jobj_sub, "zapping-join-count", json_integer(stats->zapping_join_count));
            json_object_set(jobj_sub, "zapping-leave-delay-ms-min", json_integer(stats->min_leave_delay));
            json_object_set(jobj_sub, "zapping-leave-delay-ms-avg", json_integer(stats->avg_leave_delay));
            json_object_set(jobj_sub, "zapping-leave-delay-ms-max", json_integer(stats->max_leave_delay));
            json_object_set(jobj_sub, "zapping-leave-count", json_integer(stats->zapping_leave_count));
            json_object_set(jobj_sub, "zapping-multicast-packets-overlap", json_integer(stats->mc_old_rx_after_first_new));
            json_object_set(jobj_sub, "zapping-multicast-not-received", json_integer(stats->mc_not_received));
            json_object_set(jobj, "multicast", jobj_sub);
        }
    }

    if(ctx->config.json_report_sessions) {
        jobj_array = json_array();
        for(i = 0; i < ctx->sessions; i++) {
            session = &ctx->session_list[i];
            if(session) {
                jobj_sub = bbl_session_json(session);
                if(jobj_sub) {
                    json_array_append(jobj_array, jobj_sub);
                }
            }
        }
        json_object_set(jobj, "sessions", jobj_array);
    }

    if(ctx->config.json_report_streams) {
        jobj_array = json_array();

        itor = dict_itor_new(ctx->stream_flow_dict);
        dict_itor_first(itor);
        for (; dict_itor_valid(itor); dict_itor_next(itor)) {
            stream = (bbl_stream*)*dict_itor_datum(itor);
            if(stream) {
                jobj_sub = bbl_stream_json(stream);
                if(jobj_sub) {
                    json_array_append(jobj_array, jobj_sub);
                }
            }
        }
        dict_itor_free(itor);
        json_object_set(jobj, "streams", jobj_array);
    }


    json_object_set(root, "report", jobj);
    if(json_dump_file(root, ctx->config.json_report_filename, JSON_REAL_PRECISION(4)) != 0) {
        LOG(ERROR, "Failed to create JSON report file %s\n", ctx->config.json_report_filename);
    }
    json_decref(root);
}

/*
 * Compute a PPS rate using a moving average of <BBL_AVG_SAMPLE> samples.
 */
void
bbl_compute_avg_rate(bbl_rate_s *rate, uint64_t current_value) {
    uint8_t idx;
    uint64_t div;
    uint64_t sum;

    if(current_value == 0) return;

    rate->diff_value[rate->cursor] = current_value - rate->last_value;

    sum = 0;
    div = 0;
    for (idx = 0; idx < BBL_AVG_SAMPLES; idx++) {
        if (rate->diff_value[idx]) {
            sum += rate->diff_value[idx];
            div++;
        }
    }
    if (div) {
        rate->avg = sum / div;
    } else {
        rate->avg = 0;
    }
    if(rate->avg > rate->avg_max) {
        rate->avg_max = rate->avg;
    }
    rate->cursor = (rate->cursor + 1) % BBL_AVG_SAMPLES;
    rate->last_value = current_value;
}

void
bbl_compute_interface_rate_job(timer_s *timer) {
    bbl_interface_s *interface;

    interface = timer->data;

    bbl_compute_avg_rate(&interface->stats.rate_packets_tx, interface->stats.packets_tx);
    bbl_compute_avg_rate(&interface->stats.rate_packets_rx, interface->stats.packets_rx);
    bbl_compute_avg_rate(&interface->stats.rate_bytes_tx, interface->stats.bytes_tx);
    bbl_compute_avg_rate(&interface->stats.rate_bytes_rx, interface->stats.bytes_rx);

    if(interface->type == INTERFACE_TYPE_NETWORK) {
        bbl_compute_avg_rate(&interface->stats.rate_mc_tx, interface->stats.mc_tx);
        bbl_compute_avg_rate(&interface->stats.rate_li_rx, interface->stats.li_rx);
        bbl_compute_avg_rate(&interface->stats.rate_l2tp_data_rx, interface->stats.l2tp_data_rx);
        bbl_compute_avg_rate(&interface->stats.rate_l2tp_data_tx, interface->stats.l2tp_data_tx);
    } else if(interface->type == INTERFACE_TYPE_ACCESS) {
        bbl_compute_avg_rate(&interface->stats.rate_mc_rx, interface->stats.mc_rx);
    }

    if(interface->ctx->stats.stream_traffic_flows) {
        bbl_compute_avg_rate(&interface->stats.rate_stream_tx, interface->stats.stream_tx);
        bbl_compute_avg_rate(&interface->stats.rate_stream_rx, interface->stats.stream_rx);
    }
    if(interface->ctx->stats.session_traffic_flows) {
        bbl_compute_avg_rate(&interface->stats.rate_session_ipv4_tx, interface->stats.session_ipv4_tx);
        bbl_compute_avg_rate(&interface->stats.rate_session_ipv4_rx, interface->stats.session_ipv4_rx);
        bbl_compute_avg_rate(&interface->stats.rate_session_ipv6_tx, interface->stats.session_ipv6_tx);
        bbl_compute_avg_rate(&interface->stats.rate_session_ipv6_rx, interface->stats.session_ipv6_rx);
        bbl_compute_avg_rate(&interface->stats.rate_session_ipv6pd_tx, interface->stats.session_ipv6pd_tx);
        bbl_compute_avg_rate(&interface->stats.rate_session_ipv6pd_rx, interface->stats.session_ipv6pd_rx);
    }
}
