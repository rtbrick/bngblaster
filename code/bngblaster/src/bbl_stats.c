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
bbl_stats_update_cps()
{
    struct timespec time_diff = {0};
    uint32_t ms;
    double x, y;

    /* Session setup time and rate */
    if(g_ctx->sessions_established_max > g_ctx->stats.sessions_established_max) {
        g_ctx->stats.sessions_established_max = g_ctx->sessions_established_max;

        timespec_sub(&time_diff,
             &g_ctx->stats.last_session_established,
             &g_ctx->stats.first_session_tx);

        ms = time_diff.tv_nsec / 1000000; /* convert nanoseconds to milliseconds */
        if(time_diff.tv_nsec % 1000000) ms++; /* simple roundup function */
        g_ctx->stats.setup_time = (time_diff.tv_sec * 1000) + ms; /* Setup time in milliseconds */

        x = g_ctx->sessions_established_max;
        y = g_ctx->stats.setup_time;
        if(x > 0.0 && y > 0.0) {
            g_ctx->stats.cps = (x / y) * 1000.0;

            g_ctx->stats.cps_sum += g_ctx->stats.cps;
            g_ctx->stats.cps_count++;
            g_ctx->stats.cps_avg = g_ctx->stats.cps_sum / g_ctx->stats.cps_count;

            if(g_ctx->stats.cps_min) {
                if(g_ctx->stats.cps < g_ctx->stats.cps_min) g_ctx->stats.cps_min = g_ctx->stats.cps;
            } else {
                g_ctx->stats.cps_min = g_ctx->stats.cps;
            }
            if(g_ctx->stats.cps > g_ctx->stats.cps_max) g_ctx->stats.cps_max = g_ctx->stats.cps;
        }
    }
}

void
bbl_stats_generate_interface(io_handle_s *io, bbl_interface_stats_s *stats)
{
    memset(stats, 0x0, sizeof(bbl_interface_stats_s));
    while(io) {
        stats->packets += io->stats.packets;
        stats->bytes += io->stats.bytes;
        stats->unknown += io->stats.unknown;
        stats->protocol_errors += io->stats.protocol_errors;
        stats->io_errors += io->stats.io_errors;
        stats->no_buffer += io->stats.no_buffer;
        stats->polled += io->stats.polled;
        io = io->next;
    }
}

void
bbl_stats_generate_multicast(bbl_stats_s *stats, bool reset)
{
    bbl_session_s *session;
    uint32_t i;

    uint32_t join_delays = 0;
    uint32_t leave_delays = 0;

    /* Iterate over all sessions */
    for(i = 0; i < g_ctx->sessions; i++) {
        session = &g_ctx->session_list[i];
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

            stats->join_delay_violations += session->stats.join_delay_violations;
            stats->join_delay_violations_125ms += session->stats.join_delay_violations_125ms;
            stats->join_delay_violations_250ms += session->stats.join_delay_violations_250ms;
            stats->join_delay_violations_500ms += session->stats.join_delay_violations_500ms;
            stats->join_delay_violations_1s += session->stats.join_delay_violations_1s;
            stats->join_delay_violations_2s += session->stats.join_delay_violations_2s;

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
                session->stats.join_delay_violations = 0;
                session->stats.join_delay_violations_125ms = 0;
                session->stats.join_delay_violations_250ms = 0;
                session->stats.join_delay_violations_500ms = 0;
                session->stats.join_delay_violations_1s = 0;
                session->stats.join_delay_violations_2s = 0;
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
bbl_stats_generate(bbl_stats_s * stats)
{
    bbl_stream_s *stream;
    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;
    bbl_session_s *session;
    uint32_t i;

    float pps;

    bbl_stats_update_cps();
    bbl_stats_generate_multicast(stats, false);

    struct dict_itor *itor;

    /* Iterate over all sessions */
    for(i = 0; i < g_ctx->sessions; i++) {
        session = &g_ctx->session_list[i];
        if(session) {
            /* Session Traffic */
            stream = session->session_traffic.ipv4_down;
            if(stream && stream->rx_first_seq) {
                stats->sessions_down_ipv4_rx++;
                stats->avg_down_ipv4_rx_first_seq += stream->rx_first_seq;
                if(stats->min_down_ipv4_rx_first_seq) {
                    if(stream->rx_first_seq < stats->min_down_ipv4_rx_first_seq) {
                        stats->min_down_ipv4_rx_first_seq = stream->rx_first_seq;
                    }
                } else {
                    stats->min_down_ipv4_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > stats->max_down_ipv4_rx_first_seq) {
                    stats->max_down_ipv4_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > g_ctx->config.session_traffic_ipv4_pps) {
                    stats->violations_down_ipv4_1s++;
                }
            }
            stream = session->session_traffic.ipv4_up;
            if(stream && stream->rx_first_seq) {
                stats->sessions_up_ipv4_rx++;
                stats->avg_up_ipv4_rx_first_seq += stream && stream->rx_first_seq;
                if(stats->min_up_ipv4_rx_first_seq) {
                    if(stream && stream->rx_first_seq < stats->min_up_ipv4_rx_first_seq) {
                        stats->min_up_ipv4_rx_first_seq = stream && stream->rx_first_seq;
                    }
                } else {
                    stats->min_up_ipv4_rx_first_seq = stream && stream->rx_first_seq;
                }
                if(stream && stream->rx_first_seq > stats->max_up_ipv4_rx_first_seq) {
                    stats->max_up_ipv4_rx_first_seq = stream && stream->rx_first_seq;
                }
                if(stream->rx_first_seq > g_ctx->config.session_traffic_ipv4_pps) {
                    stats->violations_up_ipv4_1s++;
                }
            }
            stream = session->session_traffic.ipv6_down;
            if(stream && stream->rx_first_seq) {
                stats->sessions_down_ipv6_rx++;
                stats->avg_down_ipv6_rx_first_seq += stream->rx_first_seq;
                if(stats->min_down_ipv6_rx_first_seq) {
                    if(stream->rx_first_seq < stats->min_down_ipv6_rx_first_seq) {
                        stats->min_down_ipv6_rx_first_seq = stream->rx_first_seq;
                    }
                } else {
                    stats->min_down_ipv6_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > stats->max_down_ipv6_rx_first_seq) {
                    stats->max_down_ipv6_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > g_ctx->config.session_traffic_ipv6_pps) {
                    stats->violations_down_ipv6_1s++;
                }
            }
            stream = session->session_traffic.ipv6_up;
            if(stream && stream->rx_first_seq) {
                stats->sessions_up_ipv6_rx++;
                stats->avg_up_ipv6_rx_first_seq += stream->rx_first_seq;
                if(stats->min_up_ipv6_rx_first_seq) {
                    if(stream->rx_first_seq < stats->min_up_ipv6_rx_first_seq) {
                        stats->min_up_ipv6_rx_first_seq = stream->rx_first_seq;
                    }
                } else {
                    stats->min_up_ipv6_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > stats->max_up_ipv6_rx_first_seq) {
                    stats->max_up_ipv6_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > g_ctx->config.session_traffic_ipv6_pps) {
                    stats->violations_up_ipv6_1s++;
                }
            }
            stream = session->session_traffic.ipv6pd_down;
            if(stream && stream->rx_first_seq) {
                stats->sessions_down_ipv6pd_rx++;
                stats->avg_down_ipv6pd_rx_first_seq += stream->rx_first_seq;
                if(stats->min_down_ipv6pd_rx_first_seq) {
                    if(stream->rx_first_seq < stats->min_down_ipv6pd_rx_first_seq) {
                        stats->min_down_ipv6pd_rx_first_seq = stream->rx_first_seq;
                    }
                } else {
                    stats->min_down_ipv6pd_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > stats->max_down_ipv6pd_rx_first_seq) {
                    stats->max_down_ipv6pd_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > g_ctx->config.session_traffic_ipv6pd_pps) {
                    stats->violations_down_ipv6pd_1s++;
                }
            }
            stream = session->session_traffic.ipv6pd_up;
            if(stream && stream->rx_first_seq) {
                stats->sessions_up_ipv6pd_rx++;
                stats->avg_up_ipv6pd_rx_first_seq += stream->rx_first_seq;
                if(stats->min_up_ipv6pd_rx_first_seq) {
                    if(stream->rx_first_seq < stats->min_up_ipv6pd_rx_first_seq) {
                        stats->min_up_ipv6pd_rx_first_seq = stream->rx_first_seq;
                    }
                } else {
                    stats->min_up_ipv6pd_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > stats->max_up_ipv6pd_rx_first_seq) {
                    stats->max_up_ipv6pd_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > g_ctx->config.session_traffic_ipv6pd_pps) {
                    stats->violations_up_ipv6pd_1s = stream->rx_first_seq;
                }
            }
        }
    }

    if(stats->sessions_down_ipv4_rx) {
        stats->avg_down_ipv4_rx_first_seq = stats->avg_down_ipv4_rx_first_seq / stats->sessions_down_ipv4_rx;
    }
    if(stats->sessions_up_ipv4_rx) {
        stats->avg_up_ipv4_rx_first_seq = stats->avg_up_ipv4_rx_first_seq / stats->sessions_up_ipv4_rx;
    }
    if(stats->sessions_down_ipv6_rx) {
        stats->avg_down_ipv6_rx_first_seq = stats->avg_down_ipv6_rx_first_seq / stats->sessions_down_ipv6_rx;
    }
    if(stats->sessions_up_ipv6_rx) {
        stats->avg_up_ipv6_rx_first_seq = stats->avg_up_ipv6_rx_first_seq / stats->sessions_up_ipv6_rx;
    }
    if(stats->sessions_down_ipv6pd_rx) {
        stats->avg_down_ipv6pd_rx_first_seq = stats->avg_down_ipv6pd_rx_first_seq / stats->sessions_down_ipv6pd_rx;
    }
    if(stats->sessions_up_ipv6pd_rx) {
        stats->avg_up_ipv6pd_rx_first_seq = stats->avg_up_ipv6pd_rx_first_seq / stats->sessions_up_ipv6pd_rx;
    }
    
    if(g_ctx->config.session_traffic_ipv4_pps) {
        pps = g_ctx->config.session_traffic_ipv4_pps;
        stats->min_down_ipv4_rx_seconds = stats->min_down_ipv4_rx_first_seq / pps;
        stats->avg_down_ipv4_rx_seconds = stats->avg_down_ipv4_rx_first_seq / pps;
        stats->max_down_ipv4_rx_seconds = stats->max_down_ipv4_rx_first_seq / pps;
        stats->min_up_ipv4_rx_seconds = stats->min_up_ipv4_rx_first_seq / pps;
        stats->avg_up_ipv4_rx_seconds = stats->avg_up_ipv4_rx_first_seq / pps;
        stats->max_up_ipv4_rx_seconds = stats->max_up_ipv4_rx_first_seq / pps;
    }
    if(g_ctx->config.session_traffic_ipv6_pps) {
        pps = g_ctx->config.session_traffic_ipv6_pps;
        stats->min_down_ipv6_rx_seconds = stats->min_down_ipv6_rx_first_seq / pps;
        stats->avg_down_ipv6_rx_seconds = stats->avg_down_ipv6_rx_first_seq / pps;
        stats->max_down_ipv6_rx_seconds = stats->max_down_ipv6_rx_first_seq / pps;
        stats->min_up_ipv6_rx_seconds = stats->min_up_ipv6_rx_first_seq / pps;
        stats->avg_up_ipv6_rx_seconds = stats->avg_up_ipv6_rx_first_seq / pps;
        stats->max_up_ipv6_rx_seconds = stats->max_up_ipv6_rx_first_seq / pps;
    }
    if(g_ctx->config.session_traffic_ipv6pd_pps) {
        pps = g_ctx->config.session_traffic_ipv6pd_pps;
        stats->min_down_ipv6pd_rx_seconds = stats->min_down_ipv6pd_rx_first_seq / pps;
        stats->avg_down_ipv6pd_rx_seconds = stats->avg_down_ipv6pd_rx_first_seq / pps;
        stats->max_down_ipv6pd_rx_seconds = stats->max_down_ipv6pd_rx_first_seq / pps;
        stats->min_up_ipv6pd_rx_seconds = stats->min_up_ipv6pd_rx_first_seq / pps;
        stats->avg_up_ipv6pd_rx_seconds = stats->avg_up_ipv6pd_rx_first_seq / pps;
        stats->max_up_ipv6pd_rx_seconds = stats->max_up_ipv6pd_rx_first_seq / pps;
    }

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        while(network_interface) {
            stats->l2tp_control_tx += network_interface->stats.l2tp_control_tx;
            stats->l2tp_control_rx += network_interface->stats.l2tp_control_rx;
            stats->l2tp_control_rx_dup += network_interface->stats.l2tp_control_rx_dup;
            stats->l2tp_control_rx_ooo += network_interface->stats.l2tp_control_rx_ooo;
            stats->l2tp_control_retry += network_interface->stats.l2tp_control_retry;
            stats->l2tp_data_tx += network_interface->stats.l2tp_data_tx;
            stats->l2tp_data_rx += network_interface->stats.l2tp_data_rx;
            stats->li_rx += network_interface->stats.li_rx;
            network_interface = network_interface->next;
        }
    }

    /* Iterate over all traffic streams */
    itor = dict_itor_new(g_ctx->stream_flow_dict);
    dict_itor_first(itor);
    for (; dict_itor_valid(itor); dict_itor_next(itor)) {
        stream = (bbl_stream_s*)*dict_itor_datum(itor);
        if(stream) {
            if(stats->min_stream_loss) {
                if(stream->rx_loss < stats->min_stream_loss) stats->min_stream_loss = stream->rx_loss;
            } else {
                stats->min_stream_loss = stream->rx_loss;
            }
            if(stream->rx_loss > stats->max_stream_loss) stats->max_stream_loss = stream->rx_loss;

            if(stream->rx_first_seq) {
                if(stats->min_stream_rx_first_seq) {
                    if(stream->rx_first_seq < stats->min_stream_rx_first_seq) stats->min_stream_rx_first_seq = stream->rx_first_seq;
                } else {
                    stats->min_stream_rx_first_seq = stream->rx_first_seq;
                }
                if(stream->rx_first_seq > stats->max_stream_rx_first_seq) stats->max_stream_rx_first_seq = stream->rx_first_seq;

                if(stats->min_stream_delay_ns) {
                    if(stream->rx_min_delay_ns < stats->min_stream_delay_ns) stats->min_stream_delay_ns = stream->rx_min_delay_ns;
                } else {
                    stats->min_stream_delay_ns = stream->rx_min_delay_ns;
                }
                if(stream->rx_max_delay_ns > stats->max_stream_delay_ns) stats->max_stream_delay_ns = stream->rx_max_delay_ns;
            }
        }
    }
    dict_itor_free(itor);
}

void
bbl_stats_stdout(bbl_stats_s *stats) {
    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;
    bbl_access_interface_s *access_interface;
    bbl_a10nsp_interface_s *a10nsp_interface;
    bbl_interface_stats_s interface_stats_tx;
    bbl_interface_stats_s interface_stats_rx;

    printf("%s", banner);
    printf("Report:\n=======\n");
    printf("Test Duration: %lus\n", test_duration());
    if(g_ctx->sessions) {
        printf("Sessions PPPoE: %u IPoE: %u\n", g_ctx->sessions_pppoe, g_ctx->sessions_ipoe);
        printf("Sessions established: %u/%u\n", g_ctx->sessions_established_max, g_ctx->sessions);
        printf("DHCPv6 sessions established: %u\n", g_ctx->dhcpv6_established_max);
        printf("Setup Time: %u ms\n", g_ctx->stats.setup_time);
        printf("Setup Rate: %0.02lf CPS (MIN: %0.02lf AVG: %0.02lf MAX: %0.02lf)\n",
            g_ctx->stats.cps, g_ctx->stats.cps_min, g_ctx->stats.cps_avg, g_ctx->stats.cps_max);
        printf("Flapped: %u\n", g_ctx->sessions_flapped);
    }

    if(dict_count(g_ctx->li_flow_dict)) {
        printf("\nLI Statistics:");
        printf("\n--------------------------------------------------------------\n");
        printf("  Flows:        %10lu\n", dict_count(g_ctx->li_flow_dict));
        printf("  RX Packets:   %10lu\n", stats->li_rx);
    }
    if(g_ctx->config.l2tp_server) {
        printf("\nL2TP LNS Statistics:");
        printf("\n--------------------------------------------------------------\n");
        printf("  Tunnels:      %10u\n", g_ctx->l2tp_tunnels_max);
        printf("  Established:  %10u\n", g_ctx->l2tp_tunnels_established_max);
        printf("  Sessions:     %10u\n", g_ctx->l2tp_sessions_max);
        printf("  Packets:\n");
        printf("    TX Control:      %10u packets (%u retries)\n",
            stats->l2tp_control_tx, stats->l2tp_control_retry);
        printf("    RX Control:      %10u packets (%u duplicate %u out-of-order)\n",
            stats->l2tp_control_rx, stats->l2tp_control_rx_dup, stats->l2tp_control_rx_ooo);
        printf("    TX Data:         %10lu packets\n", stats->l2tp_data_tx);
        printf("    RX Data:         %10lu packets\n", stats->l2tp_data_rx);
    }

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        access_interface = interface->access;
        a10nsp_interface = interface->a10nsp;

        printf("\nInterface: %s", interface->name);
        if(interface->type == LAG_INTERFACE) {
            printf(" (LAG)");
        } else if(interface->type == LAG_MEMBER_INTERFACE) {
            printf(" (%s)", interface->lag->interface->name);
        }
        printf("\n--------------------------------------------------------------\n");

        if(interface->type != LAG_INTERFACE) {
            bbl_stats_generate_interface(interface->io.tx, &interface_stats_tx);
            bbl_stats_generate_interface(interface->io.rx, &interface_stats_rx);

            printf("  TX:                %10lu packets %16lu bytes\n", 
                interface_stats_tx.packets, interface_stats_tx.bytes);
            printf("  TX Polled:         %10lu\n", interface_stats_tx.polled);
            printf("  TX IO Error:       %10lu\n", interface_stats_tx.io_errors);
            printf("  RX:                %10lu packets %16lu bytes\n",
                interface_stats_rx.packets, interface_stats_rx.bytes);
            printf("  RX Protocol Error: %10lu packets\n", interface_stats_rx.protocol_errors);
            printf("  RX Unknown:        %10lu packets\n", interface_stats_rx.unknown);
            printf("  RX Polled:         %10lu\n", interface_stats_rx.polled);
            printf("  RX IO Error:       %10lu\n", interface_stats_rx.io_errors);
        }

        if(interface->type == LAG_MEMBER_INTERFACE && 
           interface->lag_member->lacp_state) {
            printf("\n  LACP:\n");
            printf("    TX:              %10u packets\n", interface->lag_member->stats.lacp_tx);
            printf("    RX:              %10u packets\n", interface->lag_member->stats.lacp_rx);
            printf("    Dropped:         %10u packets\n", interface->lag_member->stats.lacp_dropped);
        }

        while(network_interface) {
            printf("\nNetwork Interface: %s\n", network_interface->name);
            printf("  TX:                %10lu packets %16lu bytes\n", 
                network_interface->stats.packets_tx, network_interface->stats.bytes_tx);
            printf("  RX:                %10lu packets %16lu bytes\n", 
                network_interface->stats.packets_rx, network_interface->stats.bytes_rx);
            printf("  TX Multicast:      %10lu packets\n", network_interface->stats.mc_tx);
            if(g_ctx->stats.stream_traffic_flows) {
                printf("  TX Stream:         %10lu packets\n",
                    network_interface->stats.stream_tx);
                printf("  RX Stream:         %10lu packets (%lu loss)\n",
                    network_interface->stats.stream_rx, network_interface->stats.stream_loss);
            }
            if(g_ctx->stats.session_traffic_flows) {
                printf("  Session-Traffic:\n");
                printf("    TX IPv4:         %10lu packets\n",
                    network_interface->stats.session_ipv4_tx);
                printf("    RX IPv4:         %10lu packets (%lu loss)\n",
                    network_interface->stats.session_ipv4_rx, 
                    network_interface->stats.session_ipv4_loss);
                printf("    TX IPv6:         %10lu packets\n",
                    network_interface->stats.session_ipv6_tx);
                printf("    RX IPv6:         %10lu packets (%lu loss)\n",
                    network_interface->stats.session_ipv6_rx,
                    network_interface->stats.session_ipv6_loss);
                printf("    TX IPv6PD:       %10lu packets\n",
                    network_interface->stats.session_ipv6pd_tx);
                printf("    RX IPv6PD:       %10lu packets (%lu loss)\n",
                    network_interface->stats.session_ipv6pd_rx,
                    network_interface->stats.session_ipv6pd_loss);
            }

            network_interface = network_interface->next;
        }
        if(access_interface) {
            printf("\nAccess Interface: %s\n", interface->name);
            printf("  TX:                %10lu packets %16lu bytes\n", 
                access_interface->stats.packets_tx, access_interface->stats.bytes_tx);
            printf("  RX:                %10lu packets %16lu bytes\n", 
                access_interface->stats.packets_rx, access_interface->stats.bytes_rx);
            printf("  RX Multicast:      %10lu packets %16lu loss\n", 
                access_interface->stats.mc_rx, access_interface->stats.mc_loss);
            if(g_ctx->stats.stream_traffic_flows) {
                printf("  TX Stream:         %10lu packets\n",
                    access_interface->stats.stream_tx);
                printf("  RX Stream:         %10lu packets %16lu loss\n",
                    access_interface->stats.stream_rx, 
                    access_interface->stats.stream_loss);
            }
            if(g_ctx->stats.session_traffic_flows) {
                printf("  Session-Traffic:\n");
                printf("    TX IPv4:         %10lu packets\n", 
                    access_interface->stats.session_ipv4_tx);
                printf("    RX IPv4:         %10lu packets %16lu loss\n", 
                    access_interface->stats.session_ipv4_rx,
                    access_interface->stats.session_ipv4_loss);
                if(access_interface->stats.session_ipv4_wrong_session) {
                    printf("    RX IPv4:         %10lu wrong session\n", 
                        access_interface->stats.session_ipv4_wrong_session);
                }
                printf("    TX IPv6:         %10lu packets\n",
                    access_interface->stats.session_ipv6_tx);
                printf("    RX IPv6:         %10lu packets %16lu loss\n", 
                access_interface->stats.session_ipv6_rx,
                    access_interface->stats.session_ipv6_loss);
                if(access_interface->stats.session_ipv6_wrong_session) {
                    printf("    RX IPv6:         %10lu wrong session\n", 
                        access_interface->stats.session_ipv6_wrong_session);
                }
                printf("    TX IPv6PD:       %10lu packets\n",
                    access_interface->stats.session_ipv6pd_tx);
                printf("    RX IPv6PD:       %10lu packets %16lu loss\n", 
                    access_interface->stats.session_ipv6pd_rx,
                    access_interface->stats.session_ipv6pd_loss);
                if(access_interface->stats.session_ipv6pd_wrong_session) {
                    printf("    RX IPv6PD:       %10lu wrong session\n", 
                        access_interface->stats.session_ipv6pd_wrong_session);
                }
            }

            printf("\nAccess Interface Protocol Packet Stats:\n");
            printf("  ARP    TX: %10u RX: %10u\n", access_interface->stats.arp_tx, access_interface->stats.arp_rx);
            printf("  PADI   TX: %10u RX: %10u\n", access_interface->stats.padi_tx, 0);
            printf("  PADO   TX: %10u RX: %10u\n", 0, access_interface->stats.pado_rx);
            printf("  PADR   TX: %10u RX: %10u\n", access_interface->stats.padr_tx, 0);
            printf("  PADS   TX: %10u RX: %10u\n", 0, access_interface->stats.pads_rx);
            printf("  PADT   TX: %10u RX: %10u\n", access_interface->stats.padt_tx, access_interface->stats.padt_rx);
            printf("  LCP    TX: %10u RX: %10u\n", access_interface->stats.lcp_tx, access_interface->stats.lcp_rx);
            printf("  PAP    TX: %10u RX: %10u\n", access_interface->stats.pap_tx, access_interface->stats.pap_rx);
            printf("  CHAP   TX: %10u RX: %10u\n", access_interface->stats.chap_tx, access_interface->stats.chap_rx);
            printf("  IPCP   TX: %10u RX: %10u\n", access_interface->stats.ipcp_tx, access_interface->stats.ipcp_rx);
            printf("  IP6CP  TX: %10u RX: %10u\n", access_interface->stats.ip6cp_tx, access_interface->stats.ip6cp_rx);
            printf("  IGMP   TX: %10u RX: %10u\n", access_interface->stats.igmp_tx, access_interface->stats.igmp_rx);
            printf("  ICMP   TX: %10u RX: %10u\n", access_interface->stats.icmp_tx, access_interface->stats.icmp_rx);
            printf("  DHCP   TX: %10u RX: %10u\n", access_interface->stats.dhcp_tx, access_interface->stats.dhcp_rx);
            printf("  DHCPv6 TX: %10u RX: %10u\n", access_interface->stats.dhcpv6_tx, access_interface->stats.dhcpv6_rx);
            printf("  ICMPv6 TX: %10u RX: %10u\n", access_interface->stats.icmpv6_tx, access_interface->stats.icmpv6_rx);
            printf("  IPv4 Fragmented       RX: %10u\n", access_interface->stats.ipv4_fragmented_rx);
            printf("\nAccess Interface Protocol Timeout Stats:\n");
            printf("  LCP Echo Request: %10u\n", access_interface->stats.lcp_echo_timeout);
            printf("  LCP Request:      %10u\n", access_interface->stats.lcp_timeout);
            printf("  IPCP Request:     %10u\n", access_interface->stats.ipcp_timeout);
            printf("  IP6CP Request:    %10u\n", access_interface->stats.ip6cp_timeout);
            printf("  PAP:              %10u\n", access_interface->stats.pap_timeout);
            printf("  CHAP:             %10u\n", access_interface->stats.chap_timeout);
            printf("  DHCP Request:     %10u\n", access_interface->stats.dhcp_timeout);
            printf("  DHCPv6 Request:   %10u\n", access_interface->stats.dhcpv6_timeout);
            printf("  ICMPv6 RS:        %10u\n", access_interface->stats.icmpv6_rs_timeout);
        }
        if(a10nsp_interface) {
            printf("\nA10NSP Interface: %s\n", interface->name);
            printf("  TX:                %10lu packets %10lu bytes\n", 
                a10nsp_interface->stats.packets_tx, a10nsp_interface->stats.bytes_tx);
            printf("  RX:                %10lu packets %10lu bytes\n", 
                a10nsp_interface->stats.packets_rx, a10nsp_interface->stats.bytes_rx);
            if(g_ctx->stats.stream_traffic_flows) {
                printf("  TX Stream:         %10lu packets\n",
                    a10nsp_interface->stats.stream_tx);
                printf("  RX Stream:         %10lu packets (%lu loss)\n",
                    a10nsp_interface->stats.stream_rx, a10nsp_interface->stats.stream_loss);
            }
            if(g_ctx->stats.session_traffic_flows) {
                printf("  Session-Traffic:\n");
                printf("    TX IPv4:         %10lu packets\n",
                    a10nsp_interface->stats.session_ipv4_tx);
                printf("    RX IPv4:         %10lu packets (%lu loss)\n",
                    a10nsp_interface->stats.session_ipv4_rx, 
                    a10nsp_interface->stats.session_ipv4_loss);
                printf("    TX IPv6:         %10lu packets\n",
                    a10nsp_interface->stats.session_ipv6_tx);
                printf("    RX IPv6:         %10lu packets (%lu loss)\n",
                    a10nsp_interface->stats.session_ipv6_rx, 
                    a10nsp_interface->stats.session_ipv6_loss);
                printf("    TX IPv6PD:       %10lu packets\n",
                    a10nsp_interface->stats.session_ipv6pd_tx);
                printf("    RX IPv6PD:       %10lu packets (%lu loss)\n",
                    a10nsp_interface->stats.session_ipv6pd_rx, 
                    a10nsp_interface->stats.session_ipv6pd_loss);
            }
        }
    }

    if(g_ctx->stats.session_traffic_flows) {
        printf("\nSession Traffic (Global):");
        printf("\n--------------------------------------------------------------\n");
        printf("  Config:\n");
        printf("    IPv4    PPS:    %8u\n", g_ctx->config.session_traffic_ipv4_pps);
        printf("    IPv6    PPS:    %8u\n", g_ctx->config.session_traffic_ipv6_pps);
        printf("    IPv6PD  PPS:    %8u\n", g_ctx->config.session_traffic_ipv6pd_pps);
        printf("  Verified Traffic Flows: %u/%u\n",
            g_ctx->stats.session_traffic_flows_verified, g_ctx->stats.session_traffic_flows);
        printf("    Downstream IPv4:   %8u\n", stats->sessions_down_ipv4_rx);
        printf("    Downstream IPv6:   %8u\n", stats->sessions_down_ipv6_rx);
        printf("    Downstream IPv6PD: %8u\n", stats->sessions_down_ipv6pd_rx);
        printf("    Upstream IPv4:     %8u\n", stats->sessions_up_ipv4_rx);
        printf("    Upstream IPv6:     %8u\n", stats->sessions_up_ipv6_rx);
        printf("    Upstream IPv6PD:   %8u\n", stats->sessions_up_ipv6pd_rx);
        printf("  Violations (>1s): %lu\n", 
            (stats->violations_down_ipv4_1s + stats->violations_down_ipv6_1s + stats->violations_down_ipv6pd_1s + \
             stats->violations_up_ipv4_1s + stats->violations_up_ipv6_1s + stats->violations_up_ipv6pd_1s));
        printf("    Downstream IPv4:   %8lu\n", stats->violations_down_ipv4_1s);
        printf("    Downstream IPv6:   %8lu\n", stats->violations_down_ipv6_1s);
        printf("    Downstream IPv6PD: %8lu\n", stats->violations_down_ipv6pd_1s);
        printf("    Upstream IPv4:     %8lu\n", stats->violations_up_ipv4_1s);
        printf("    Upstream IPv6:     %8lu\n", stats->violations_up_ipv4_1s);
        printf("    Upstream IPv6PD:   %8lu\n", stats->violations_up_ipv6pd_1s);
        printf("  First Sequence Number Received:\n");
        printf("    Downstream IPv4    MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_down_ipv4_rx_first_seq, stats->min_down_ipv4_rx_seconds,
            stats->avg_down_ipv4_rx_first_seq, stats->avg_down_ipv4_rx_seconds,
            stats->max_down_ipv4_rx_first_seq, stats->max_down_ipv4_rx_seconds);
        printf("    Downstream IPv6    MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_down_ipv6_rx_first_seq, stats->min_down_ipv6_rx_seconds,
            stats->avg_down_ipv6_rx_first_seq, stats->avg_down_ipv6_rx_seconds,
            stats->max_down_ipv6_rx_first_seq, stats->max_down_ipv6_rx_seconds);
        printf("    Downstream IPv6PD  MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_down_ipv6pd_rx_first_seq, stats->min_down_ipv6pd_rx_seconds,
            stats->avg_down_ipv6pd_rx_first_seq, stats->avg_down_ipv6pd_rx_seconds,
            stats->max_down_ipv6pd_rx_first_seq, stats->max_down_ipv6pd_rx_seconds);
        printf("    Upstream IPv4      MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_up_ipv4_rx_first_seq, stats->min_up_ipv4_rx_seconds,
            stats->avg_up_ipv4_rx_first_seq, stats->avg_up_ipv4_rx_seconds,
            stats->max_up_ipv4_rx_first_seq, stats->max_up_ipv4_rx_seconds);
        printf("    Upstream IPv6      MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_up_ipv6_rx_first_seq, stats->min_up_ipv6_rx_seconds,
            stats->avg_up_ipv6_rx_first_seq, stats->avg_up_ipv6_rx_seconds,
            stats->max_up_ipv6_rx_first_seq, stats->max_up_ipv6_rx_seconds);
        printf("    Upstream IPv6PD    MIN: %6lu (%5.2fs) AVG: %6lu (%5.2fs) MAX: %6lu (%5.2fs)\n",
            stats->min_up_ipv6pd_rx_first_seq, stats->min_up_ipv6pd_rx_seconds,
            stats->avg_up_ipv6pd_rx_first_seq, stats->avg_up_ipv6pd_rx_seconds,
            stats->max_up_ipv6pd_rx_first_seq, stats->max_up_ipv6pd_rx_seconds);
    }

    if(g_ctx->stats.stream_traffic_flows) {
        printf("\nTraffic Streams:");
        printf("\n--------------------------------------------------------------\n");
        printf("  Verified Traffic Flows: %u/%u\n",
            g_ctx->stats.stream_traffic_flows_verified, g_ctx->stats.stream_traffic_flows);
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

    if(g_ctx->config.igmp_group_count > 1) {
        printf("\nMulticast:");
        printf("\n--------------------------------------------------------------\n");
        printf("\nIGMP Config:\n");
        printf("  Version: %d\n", g_ctx->config.igmp_version);
        printf("  Start Delay: %us\n", g_ctx->config.igmp_start_delay);
        printf("  Group Count: %u \n", g_ctx->config.igmp_group_count);
        printf("  Zapping Interval: %us\n", g_ctx->config.igmp_zap_interval);
        printf("  Zapping Count: %u \n", g_ctx->config.igmp_zap_count);
        printf("  Zapping Channel View Duration: %us\n", g_ctx->config.igmp_zap_view_duration);
        if(g_ctx->config.igmp_zap_interval > 0) {
            printf("\nIGMP Zapping Stats:\n");
            printf("  Join Delay:\n");
            printf("    COUNT: %u\n", stats->zapping_join_count);
            printf("    MIN: %ums\n", stats->min_join_delay);
            printf("    AVG: %ums\n", stats->avg_join_delay);
            printf("    MAX: %ums\n", stats->max_join_delay);
            printf("    VIOLATIONS:\n");
            if(g_ctx->config.igmp_max_join_delay) {
                printf("      > %u ms: %u\n", g_ctx->config.igmp_max_join_delay, stats->join_delay_violations);
            }
            printf("      > 125ms: %u\n", stats->join_delay_violations_125ms);
            printf("      > 250ms: %u\n", stats->join_delay_violations_250ms);
            printf("      > 500ms: %u\n", stats->join_delay_violations_500ms);
            printf("      > 1s: %u\n", stats->join_delay_violations_1s);
            printf("      > 2s: %u\n", stats->join_delay_violations_2s);
            printf("  Leave Delay:\n");
            printf("    COUNT: %u\n", stats->zapping_leave_count);
            printf("    MIN: %ums\n", stats->min_leave_delay);
            printf("    AVG: %ums\n", stats->avg_leave_delay);
            printf("    MAX: %ums\n", stats->max_leave_delay);
            printf("  Multicast:\n");
            printf("    Overlap: %u packets\n", stats->mc_old_rx_after_first_new);
            printf("    Not Received: %u\n", stats->mc_not_received);
        }
    }
}

void
bbl_stats_json(bbl_stats_s * stats)
{
    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;
    bbl_access_interface_s *access_interface;
    bbl_a10nsp_interface_s *a10nsp_interface;
    bbl_interface_stats_s interface_stats_tx;
    bbl_interface_stats_s interface_stats_rx;
    bbl_session_s *session;
    bbl_stream_s *stream;

    struct dict_itor *itor;

    json_t *root        = NULL;
    json_t *jobj        = NULL;
    json_t *jobj_array  = NULL;
    json_t *jobj_sub    = NULL;
    json_t *jobj_sub2   = NULL;

    uint32_t i;
    uint32_t array_size;

    if(!g_ctx->config.json_report_filename) return;

    root = json_object();
    jobj = json_object();
    if(g_ctx->sessions) {
        json_object_set(jobj, "sessions", json_integer(g_ctx->config.sessions));
        json_object_set(jobj, "sessions-pppoe", json_integer(g_ctx->sessions_pppoe));
        json_object_set(jobj, "sessions-ipoe", json_integer(g_ctx->sessions_ipoe));
        json_object_set(jobj, "sessions-established", json_integer(g_ctx->sessions_established_max));
        json_object_set(jobj, "sessions-flapped", json_integer(g_ctx->sessions_flapped));
        json_object_set(jobj, "setup-time-ms", json_integer(g_ctx->stats.setup_time));
        json_object_set(jobj, "setup-rate-cps", json_real(g_ctx->stats.cps));
        json_object_set(jobj, "setup-rate-cps-min", json_real(g_ctx->stats.cps_min));
        json_object_set(jobj, "setup-rate-cps-avg", json_real(g_ctx->stats.cps_avg));
        json_object_set(jobj, "setup-rate-cps-max", json_real(g_ctx->stats.cps_max));
        json_object_set(jobj, "dhcp-sessions-established", json_integer(g_ctx->dhcp_established_max));
        json_object_set(jobj, "dhcpv6-sessions-established", json_integer(g_ctx->dhcpv6_established_max));
    }
    if(dict_count(g_ctx->li_flow_dict)) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "flows", json_integer(dict_count(g_ctx->li_flow_dict)));
        json_object_set(jobj_sub, "rx-packets", json_integer(stats->li_rx));
        json_object_set(jobj, "li-statistics", jobj_sub);
    }
    if(g_ctx->config.l2tp_server) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "tunnels", json_integer(g_ctx->l2tp_tunnels_max));
        json_object_set(jobj_sub, "tunnels-established", json_integer(g_ctx->l2tp_tunnels_established_max));
        json_object_set(jobj_sub, "sessions", json_integer(g_ctx->l2tp_sessions_max));
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
    array_size = 0;
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "name", json_string(interface->name));
        json_object_set(jobj_sub, "type", json_string(interface_type_string(interface->type)));
        if(interface->type != LAG_INTERFACE) {
            bbl_stats_generate_interface(interface->io.tx, &interface_stats_tx);
            bbl_stats_generate_interface(interface->io.rx, &interface_stats_rx);
            json_object_set(jobj_sub, "tx-packets", json_integer(interface_stats_tx.packets));
            json_object_set(jobj_sub, "tx-bytes", json_integer(interface_stats_tx.bytes));
            json_object_set(jobj_sub, "tx-polled", json_integer(interface_stats_tx.polled));
            json_object_set(jobj_sub, "tx-io-error", json_integer(interface_stats_tx.io_errors));
            json_object_set(jobj_sub, "rx-packets", json_integer(interface_stats_rx.packets));
            json_object_set(jobj_sub, "rx-bytes", json_integer(interface_stats_rx.bytes));
            json_object_set(jobj_sub, "rx-protocol-error", json_integer(interface_stats_rx.protocol_errors));
            json_object_set(jobj_sub, "rx-unknown", json_integer(interface_stats_rx.unknown));
            json_object_set(jobj_sub, "rx-polled", json_integer(interface_stats_rx.bytes));
            json_object_set(jobj_sub, "rx-io-error", json_integer(interface_stats_rx.io_errors));
        }
        if(interface->type == LAG_MEMBER_INTERFACE && 
           interface->lag_member->lacp_state) {
            jobj_sub2 = json_object();
            json_object_set(jobj_sub2, "tx", json_integer(interface->lag_member->stats.lacp_tx));
            json_object_set(jobj_sub2, "rx", json_integer(interface->lag_member->stats.lacp_rx));
            json_object_set(jobj_sub2, "dropped", json_integer(interface->lag_member->stats.lacp_dropped));
            json_object_set(jobj_sub, "lacp", jobj_sub2);
        }
        json_array_append(jobj_array, jobj_sub);
        array_size++;
    }
    json_object_set(jobj, "interfaces", jobj_array);

    jobj_array = json_array();
    array_size = 0;
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        while(network_interface) {
            jobj_sub = json_object();
            json_object_set(jobj_sub, "name", json_string(network_interface->name));
            json_object_set(jobj_sub, "tx-packets", json_integer(network_interface->stats.packets_tx));
            json_object_set(jobj_sub, "tx-multicast-packets", json_integer(network_interface->stats.mc_tx));
            json_object_set(jobj_sub, "rx-packets", json_integer(network_interface->stats.packets_rx));
            if(g_ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-stream-packets", json_integer(network_interface->stats.stream_tx));
                json_object_set(jobj_sub, "rx-stream-packets", json_integer(network_interface->stats.stream_rx));
                json_object_set(jobj_sub, "rx-stream-packets-loss", json_integer(network_interface->stats.stream_loss));
            }
            if(g_ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-session-packets-ipv4", json_integer(network_interface->stats.session_ipv4_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv4", json_integer(network_interface->stats.session_ipv4_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv4-loss", json_integer(network_interface->stats.session_ipv4_loss));
                json_object_set(jobj_sub, "tx-session-packets-ipv4-avg-pps-max", json_integer(network_interface->stats.rate_session_ipv4_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv4-avg-pps-max", json_integer(network_interface->stats.rate_session_ipv4_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6", json_integer(network_interface->stats.session_ipv6_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6", json_integer(network_interface->stats.session_ipv6_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-loss", json_integer(network_interface->stats.session_ipv6_loss));
                json_object_set(jobj_sub, "tx-session-packets-ipv6-avg-pps-max", json_integer(network_interface->stats.rate_session_ipv6_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-avg-pps-max", json_integer(network_interface->stats.rate_session_ipv6_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd", json_integer(network_interface->stats.session_ipv6pd_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd", json_integer(network_interface->stats.session_ipv6pd_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-loss", json_integer(network_interface->stats.session_ipv6pd_loss));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd-avg-pps-max", json_integer(network_interface->stats.rate_session_ipv6pd_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-avg-pps-max", json_integer(network_interface->stats.rate_session_ipv6pd_rx.avg_max));
            }
            json_array_append(jobj_array, jobj_sub);
            array_size++;
            network_interface = network_interface->next;
        }
    }
    if(array_size) {
        json_object_set(jobj, "network-interfaces", jobj_array);
    } else {
        json_decref(jobj_array);
    }

    jobj_array = json_array();
    array_size = 0;
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        access_interface = interface->access;
        if(access_interface) {
            jobj_sub = json_object();
            json_object_set(jobj_sub, "name", json_string(interface->name));
            json_object_set(jobj_sub, "tx-packets", json_integer(access_interface->stats.packets_tx));
            json_object_set(jobj_sub, "rx-packets", json_integer(access_interface->stats.packets_rx));
            json_object_set(jobj_sub, "rx-multicast-packets", json_integer(access_interface->stats.mc_rx));
            json_object_set(jobj_sub, "rx-multicast-packets-loss", json_integer(access_interface->stats.mc_loss));
            if(g_ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-stream-packets", json_integer(access_interface->stats.stream_tx));
                json_object_set(jobj_sub, "rx-stream-packets", json_integer(access_interface->stats.stream_rx));
                json_object_set(jobj_sub, "rx-stream-packets-loss", json_integer(access_interface->stats.stream_loss));
            }
            if(g_ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-session-packets-ipv4", json_integer(access_interface->stats.session_ipv4_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv4", json_integer(access_interface->stats.session_ipv4_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv4-loss", json_integer(access_interface->stats.session_ipv4_loss));
                json_object_set(jobj_sub, "rx-session-packets-ipv4-wrong-session", json_integer(access_interface->stats.session_ipv4_wrong_session));
                json_object_set(jobj_sub, "tx-session-packets-ipv4-avg-pps-max", json_integer(access_interface->stats.rate_session_ipv4_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv4-avg-pps-max", json_integer(access_interface->stats.rate_session_ipv4_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6", json_integer(access_interface->stats.session_ipv6_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6", json_integer(access_interface->stats.session_ipv6_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-loss", json_integer(access_interface->stats.session_ipv6_loss));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-wrong-session", json_integer(access_interface->stats.session_ipv6_wrong_session));
                json_object_set(jobj_sub, "tx-session-packets-ipv6-avg-pps-max", json_integer(access_interface->stats.rate_session_ipv6_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv6avg-pps-max", json_integer(access_interface->stats.rate_session_ipv6_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd", json_integer(access_interface->stats.session_ipv6pd_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd", json_integer(access_interface->stats.session_ipv6pd_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-loss", json_integer(access_interface->stats.session_ipv6pd_loss));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-wrong-session", json_integer(access_interface->stats.session_ipv6pd_wrong_session));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd-avg-pps-max", json_integer(access_interface->stats.rate_session_ipv6pd_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-avg-pps-max", json_integer(access_interface->stats.rate_session_ipv6pd_rx.avg_max));
            }
            jobj_sub2 = json_object();
            json_object_set(jobj_sub2, "tx-arp", json_integer(access_interface->stats.arp_tx));
            json_object_set(jobj_sub2, "rx-arp", json_integer(access_interface->stats.arp_rx));
            json_object_set(jobj_sub2, "tx-padi", json_integer(access_interface->stats.padi_tx));
            json_object_set(jobj_sub2, "rx-pado", json_integer(access_interface->stats.pado_rx));
            json_object_set(jobj_sub2, "tx-padr", json_integer(access_interface->stats.padr_tx));
            json_object_set(jobj_sub2, "rx-pads", json_integer(access_interface->stats.pads_rx));
            json_object_set(jobj_sub2, "tx-padt", json_integer(access_interface->stats.padt_tx));
            json_object_set(jobj_sub2, "rx-padt", json_integer(access_interface->stats.padt_rx));
            json_object_set(jobj_sub2, "tx-lcp", json_integer(access_interface->stats.lcp_tx));
            json_object_set(jobj_sub2, "rx-lcp", json_integer(access_interface->stats.lcp_rx));
            json_object_set(jobj_sub2, "tx-pap", json_integer(access_interface->stats.pap_tx));
            json_object_set(jobj_sub2, "rx-pap", json_integer(access_interface->stats.pap_rx));
            json_object_set(jobj_sub2, "tx-chap", json_integer(access_interface->stats.chap_tx));
            json_object_set(jobj_sub2, "rx-chap", json_integer(access_interface->stats.chap_rx));
            json_object_set(jobj_sub2, "tx-ipcp", json_integer(access_interface->stats.ipcp_tx));
            json_object_set(jobj_sub2, "rx-ipcp", json_integer(access_interface->stats.ipcp_rx));
            json_object_set(jobj_sub2, "tx-ip6cp", json_integer(access_interface->stats.ip6cp_tx));
            json_object_set(jobj_sub2, "rx-ip6cp", json_integer(access_interface->stats.ip6cp_rx));
            json_object_set(jobj_sub2, "tx-igmp", json_integer(access_interface->stats.igmp_tx));
            json_object_set(jobj_sub2, "rx-igmp", json_integer(access_interface->stats.igmp_rx));
            json_object_set(jobj_sub2, "tx-icmp", json_integer(access_interface->stats.icmp_tx));
            json_object_set(jobj_sub2, "rx-icmp", json_integer(access_interface->stats.icmp_rx));
            json_object_set(jobj_sub2, "tx-dhcp", json_integer(access_interface->stats.dhcp_tx));
            json_object_set(jobj_sub2, "rx-dhcp", json_integer(access_interface->stats.dhcp_rx));
            json_object_set(jobj_sub2, "tx-dhcpv6", json_integer(access_interface->stats.dhcpv6_tx));
            json_object_set(jobj_sub2, "rx-dhcpv6", json_integer(access_interface->stats.dhcpv6_rx));
            json_object_set(jobj_sub2, "tx-icmpv6", json_integer(access_interface->stats.icmpv6_tx));
            json_object_set(jobj_sub2, "rx-icmpv6", json_integer(access_interface->stats.icmpv6_rx));
            json_object_set(jobj_sub2, "rx-ipv4-fragmented", json_integer(access_interface->stats.ipv4_fragmented_rx));
            json_object_set(jobj_sub2, "lcp-echo-timeout", json_integer(access_interface->stats.lcp_echo_timeout));
            json_object_set(jobj_sub2, "lcp-request-timeout", json_integer(access_interface->stats.lcp_timeout));
            json_object_set(jobj_sub2, "ipcp-request-timeout", json_integer(access_interface->stats.ipcp_timeout));
            json_object_set(jobj_sub2, "ip6cp-request-timeout", json_integer(access_interface->stats.ip6cp_timeout));
            json_object_set(jobj_sub2, "pap-timeout", json_integer(access_interface->stats.pap_timeout));
            json_object_set(jobj_sub2, "chap-timeout", json_integer(access_interface->stats.chap_timeout));
            json_object_set(jobj_sub2, "dhcp-timeout", json_integer(access_interface->stats.dhcp_timeout));
            json_object_set(jobj_sub2, "dhcpv6-timeout", json_integer(access_interface->stats.dhcpv6_timeout));
            json_object_set(jobj_sub2, "icmpv6-rs-timeout", json_integer(access_interface->stats.dhcpv6_timeout));
            json_object_set(jobj_sub, "protocol-stats", jobj_sub2);
            json_array_append(jobj_array, jobj_sub);
            array_size++;
        }
    }
    if(array_size) {
        json_object_set(jobj, "access-interfaces", jobj_array);
    } else {
        json_decref(jobj_array);
    }

    jobj_array = json_array();
    array_size = 0;
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        a10nsp_interface = interface->a10nsp;
        if(a10nsp_interface) {
            jobj_sub = json_object();
            json_object_set(jobj_sub, "name", json_string(interface->name));
            json_object_set(jobj_sub, "tx-packets", json_integer(a10nsp_interface->stats.packets_tx));
            json_object_set(jobj_sub, "rx-packets", json_integer(a10nsp_interface->stats.packets_rx));
            if(g_ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-stream-packets", json_integer(a10nsp_interface->stats.stream_tx));
                json_object_set(jobj_sub, "rx-stream-packets", json_integer(a10nsp_interface->stats.stream_rx));
                json_object_set(jobj_sub, "rx-stream-packets-loss", json_integer(a10nsp_interface->stats.stream_loss));
            }
            if(g_ctx->stats.session_traffic_flows) {
                json_object_set(jobj_sub, "tx-session-packets-ipv4", json_integer(a10nsp_interface->stats.session_ipv4_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv4", json_integer(a10nsp_interface->stats.session_ipv4_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv4-loss", json_integer(a10nsp_interface->stats.session_ipv4_loss));
                json_object_set(jobj_sub, "tx-session-packets-ipv4-avg-pps-max", json_integer(a10nsp_interface->stats.rate_session_ipv4_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv4-avg-pps-max", json_integer(a10nsp_interface->stats.rate_session_ipv4_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6", json_integer(a10nsp_interface->stats.session_ipv6_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6", json_integer(a10nsp_interface->stats.session_ipv6_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-loss", json_integer(a10nsp_interface->stats.session_ipv6_loss));
                json_object_set(jobj_sub, "tx-session-packets-ipv6-avg-pps-max", json_integer(a10nsp_interface->stats.rate_session_ipv6_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv6-avg-pps-max", json_integer(a10nsp_interface->stats.rate_session_ipv6_rx.avg_max));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd", json_integer(a10nsp_interface->stats.session_ipv6pd_tx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd", json_integer(a10nsp_interface->stats.session_ipv6pd_rx));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-loss", json_integer(a10nsp_interface->stats.session_ipv6pd_loss));
                json_object_set(jobj_sub, "tx-session-packets-ipv6pd-avg-pps-max", json_integer(a10nsp_interface->stats.rate_session_ipv6pd_tx.avg_max));
                json_object_set(jobj_sub, "rx-session-packets-ipv6pd-avg-pps-max", json_integer(a10nsp_interface->stats.rate_session_ipv6pd_rx.avg_max));
            }
            json_array_append(jobj_array, jobj_sub);
            array_size++;
        }
    }
    if(array_size) {
        json_object_set(jobj, "a10nsp-interfaces", jobj_array);
    } else {
        json_decref(jobj_array);
    }

    if(g_ctx->stats.session_traffic_flows) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "config-ipv4-pps", json_integer(g_ctx->config.session_traffic_ipv4_pps));
        json_object_set(jobj_sub, "config-ipv6-pps", json_integer(g_ctx->config.session_traffic_ipv6_pps));
        json_object_set(jobj_sub, "config-ipv6pd-pps", json_integer(g_ctx->config.session_traffic_ipv6pd_pps));
        json_object_set(jobj_sub, "total-flows", json_integer(g_ctx->stats.session_traffic_flows));
        json_object_set(jobj_sub, "verified-flows", json_integer(g_ctx->stats.session_traffic_flows_verified));
        json_object_set(jobj_sub, "verified-flows-downstream-ipv4", json_integer(stats->sessions_down_ipv4_rx));
        json_object_set(jobj_sub, "verified-flows-downstream-ipv6", json_integer(stats->sessions_down_ipv6_rx));
        json_object_set(jobj_sub, "verified-flows-downstream-ipv6pd", json_integer(stats->sessions_down_ipv6pd_rx));
        json_object_set(jobj_sub, "verified-flows-upstream-ipv4", json_integer(stats->sessions_up_ipv4_rx));
        json_object_set(jobj_sub, "verified-flows-upstream-ipv6", json_integer(stats->sessions_up_ipv6_rx));
        json_object_set(jobj_sub, "verified-flows-upstream-ipv6pd", json_integer(stats->sessions_up_ipv6pd_rx));
        json_object_set(jobj_sub, "violated-flows-downstream-ipv4", json_integer(stats->violations_down_ipv4_1s));
        json_object_set(jobj_sub, "violated-flows-downstream-ipv6", json_integer(stats->violations_down_ipv6_1s));
        json_object_set(jobj_sub, "violated-flows-downstream-ipv6pd", json_integer(stats->violations_down_ipv6pd_1s));
        json_object_set(jobj_sub, "violated-flows-upstream-ipv4", json_integer(stats->violations_up_ipv4_1s));
        json_object_set(jobj_sub, "violated-flows-upstream-ipv6", json_integer(stats->violations_up_ipv4_1s));
        json_object_set(jobj_sub, "violated-flows-upstream-ipv6pd", json_integer(stats->violations_up_ipv6pd_1s));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv4-min", json_integer(stats->min_down_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv4-avg", json_integer(stats->avg_down_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv4-max", json_integer(stats->max_down_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6-min", json_integer(stats->min_down_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6-avg", json_integer(stats->avg_down_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6-max", json_integer(stats->max_down_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6pd-min", json_integer(stats->min_down_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6pd-avg", json_integer(stats->avg_down_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6pd-max", json_integer(stats->max_down_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv4-min", json_integer(stats->min_up_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv4-avg", json_integer(stats->avg_up_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv4-max", json_integer(stats->max_up_ipv4_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6-min", json_integer(stats->min_up_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6-avg", json_integer(stats->avg_up_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6-max", json_integer(stats->max_up_ipv6_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6pd-min", json_integer(stats->min_up_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6pd-avg", json_integer(stats->avg_up_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6pd-max", json_integer(stats->max_up_ipv6pd_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv4-min-seconds", json_real(stats->min_down_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv4-avg-seconds", json_real(stats->avg_down_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv4-max-seconds", json_real(stats->max_down_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6-min-seconds", json_real(stats->min_down_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6-avg-seconds", json_real(stats->avg_down_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6-max-seconds", json_real(stats->max_down_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6pd-min-seconds", json_real(stats->min_down_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6pd-avg-seconds", json_real(stats->avg_down_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-downstream-ipv6pd-max-seconds", json_real(stats->max_down_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv4-min-seconds", json_real(stats->min_up_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv4-avg-seconds", json_real(stats->avg_up_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv4-max-seconds", json_real(stats->max_up_ipv4_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6-min-seconds", json_real(stats->min_up_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6-avg-seconds", json_real(stats->avg_up_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6-max-seconds", json_real(stats->max_up_ipv6_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6pd-min-seconds", json_real(stats->min_up_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6pd-avg-seconds", json_real(stats->avg_up_ipv6pd_rx_seconds));
        json_object_set(jobj_sub, "first-seq-rx-upstream-ipv6pd-max-seconds", json_real(stats->max_up_ipv6pd_rx_seconds));
        json_object_set(jobj, "session-traffic", jobj_sub);
    }

    if(g_ctx->stats.stream_traffic_flows) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "total-flows", json_integer(g_ctx->stats.stream_traffic_flows));
        json_object_set(jobj_sub, "verified-flows", json_integer(g_ctx->stats.stream_traffic_flows_verified));
        json_object_set(jobj_sub, "first-seq-rx-min", json_integer(stats->min_stream_rx_first_seq));
        json_object_set(jobj_sub, "first-seq-rx-max", json_integer(stats->max_stream_rx_first_seq));
        json_object_set(jobj_sub, "flow-rx-packet-loss-min", json_integer(stats->min_stream_loss));
        json_object_set(jobj_sub, "flow-rx-packet-loss-max", json_integer(stats->max_stream_loss));
        json_object_set(jobj_sub, "flow-rx-delay-min", json_integer(stats->min_stream_delay_ns));
        json_object_set(jobj_sub, "flow-rx-delay-max", json_integer(stats->max_stream_delay_ns));
        json_object_set(jobj, "traffic-streams", jobj_sub);
    }

    if(g_ctx->config.igmp_group_count > 1) {
        jobj_sub = json_object();
        json_object_set(jobj_sub, "config-version", json_integer(g_ctx->config.igmp_version));
        json_object_set(jobj_sub, "config-start-delay", json_integer(g_ctx->config.igmp_start_delay));
        json_object_set(jobj_sub, "config-group-count", json_integer(g_ctx->config.igmp_group_count));
        json_object_set(jobj_sub, "config-zapping-interval", json_integer(g_ctx->config.igmp_zap_interval));
        json_object_set(jobj_sub, "config-zapping-count", json_integer(g_ctx->config.igmp_zap_count));
        json_object_set(jobj_sub, "config-zapping-view-duration", json_integer(g_ctx->config.igmp_zap_view_duration));
        if(g_ctx->config.igmp_zap_interval > 0) {
            json_object_set(jobj_sub, "zapping-join-delay-ms-min", json_integer(stats->min_join_delay));
            json_object_set(jobj_sub, "zapping-join-delay-ms-avg", json_integer(stats->avg_join_delay));
            json_object_set(jobj_sub, "zapping-join-delay-ms-max", json_integer(stats->max_join_delay));
            if(g_ctx->config.igmp_max_join_delay) {
                json_object_set(jobj_sub, "zapping-join-delay-violations", json_integer(stats->join_delay_violations));
                json_object_set(jobj_sub, "zapping-join-delay-violations-threshold", json_integer(g_ctx->config.igmp_max_join_delay));
            }
            json_object_set(jobj_sub, "zapping-join-delay-violations-125ms", json_integer(stats->join_delay_violations_125ms));
            json_object_set(jobj_sub, "zapping-join-delay-violations-250ms", json_integer(stats->join_delay_violations_250ms));
            json_object_set(jobj_sub, "zapping-join-delay-violations-500ms", json_integer(stats->join_delay_violations_500ms));
            json_object_set(jobj_sub, "zapping-join-delay-violations-1s", json_integer(stats->join_delay_violations_1s));
            json_object_set(jobj_sub, "zapping-join-delay-violations-2s", json_integer(stats->join_delay_violations_2s));
            json_object_set(jobj_sub, "zapping-join-count", json_integer(stats->zapping_join_count));
            json_object_set(jobj_sub, "zapping-leave-delay-ms-min", json_integer(stats->min_leave_delay));
            json_object_set(jobj_sub, "zapping-leave-delay-ms-avg", json_integer(stats->avg_leave_delay));
            json_object_set(jobj_sub, "zapping-leave-delay-ms-max", json_integer(stats->max_leave_delay));
            json_object_set(jobj_sub, "zapping-leave-count", json_integer(stats->zapping_leave_count));
            json_object_set(jobj_sub, "zapping-multicast-packets-overlap", json_integer(stats->mc_old_rx_after_first_new));
            json_object_set(jobj_sub, "zapping-multicast-not-received", json_integer(stats->mc_not_received));
        }
        json_object_set(jobj, "multicast", jobj_sub);
    }

    if(g_ctx->config.json_report_sessions) {
        jobj_array = json_array();
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                jobj_sub = bbl_session_json(session);
                if(jobj_sub) {
                    json_array_append(jobj_array, jobj_sub);
                }
            }
        }
        json_object_set(jobj, "sessions", jobj_array);
    }

    if(g_ctx->config.json_report_streams) {
        jobj_array = json_array();

        itor = dict_itor_new(g_ctx->stream_flow_dict);
        dict_itor_first(itor);
        for (; dict_itor_valid(itor); dict_itor_next(itor)) {
            stream = (bbl_stream_s*)*dict_itor_datum(itor);
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
    if(json_dump_file(root, g_ctx->config.json_report_filename, JSON_REAL_PRECISION(4)) != 0) {
        LOG(ERROR, "Failed to create JSON report file %s\n", g_ctx->config.json_report_filename);
    }
    json_decref(root);
}

/*
 * Compute a PPS rate using a moving average of <BBL_AVG_SAMPLE> samples.
 */
void
bbl_compute_avg_rate(bbl_rate_s *rate, uint64_t current_value)
{
    uint8_t idx;
    uint64_t div;
    uint64_t sum;

    if(current_value == 0) return;

    rate->diff_value[rate->cursor] = current_value - rate->last_value;

    sum = 0;
    div = 0;
    for(idx = 0; idx < BBL_AVG_SAMPLES; idx++) {
        if(rate->diff_value[idx]) {
            sum += rate->diff_value[idx];
            div++;
        }
    }
    if(div) {
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