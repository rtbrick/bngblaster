/*
 * BNG Blaster (BBL) - Interactive Mode
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

#define PROGRESS_BAR_SIZE   60
#define STATS_WIN_SIZE      90
#define STRING_SP_SIZE      64

#define VISIBLE(_expression) \
    visible = false; \
    if(_expression) { \
        if(pos > stats_win_postion) { \
            visible = true; \
        } \
        pos++; \
    } \
    if(visible)

typedef enum {
    UI_VIEW_DEFAULT = 0,
    UI_VIEW_ACCESS_IF_STATS,
    UI_VIEW_SESSION,
    UI_VIEW_MAX,
} __attribute__ ((__packed__)) bbl_ui_view;

/* ncurses */
WINDOW *stats_win = NULL;
WINDOW *log_win = NULL;

int stats_win_postion;

extern volatile bool g_teardown;
extern volatile bool g_teardown_request;
extern bool g_banner;
extern bool g_interactive;

/* This global variable is used to switch between access interfaces. */
uint8_t g_access_if_selected  = 0;
uint8_t g_network_if_selected = 0;
uint8_t g_a10nsp_if_selected  = 0;
/* This global variable is used to switch between views. */
bbl_ui_view g_view_selected   = 0;
/* This global variable is used to switch vetween sessions in some views. */
uint32_t g_session_selected   = 1;

extern const char banner[];

void
bbl_init_stats_win(bbl_ctx_s *ctx)
{
    wclear(stats_win);
    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
    wprintw(stats_win, "F1: Select View  F7/F8: Start/Stop Traffic  F9: Terminate Sessions\n");
    if(g_view_selected == UI_VIEW_SESSION) {
        wprintw(stats_win, "Left/Right: Select Session\n");
    } else {
        if(ctx->interfaces.network_if_count) {
            wprintw(stats_win, "F2: Network Interface  ");
        }
        if(ctx->interfaces.a10nsp_if_count) {
            wprintw(stats_win, "F3: Select A10NSP Interface  ");
        }
        if(ctx->interfaces.access_if_count) {
            wprintw(stats_win, "Left/Right: Access Interface");
        }
        wprintw(stats_win, "\n");
    }
    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
    if(g_banner) {
        wprintw(stats_win, "%s", banner);
    }
}

/*
 * Interactive keyboard reader
 */
void
bbl_read_key_job (timer_s *timer)
{
    bbl_ctx_s *ctx = timer->data;
    int ch;

    ch = getch();
    switch (ch) {
        case KEY_F(1):
            stats_win_postion = 0;
            g_view_selected++;
            if(g_view_selected >= UI_VIEW_MAX) {
                g_view_selected = UI_VIEW_DEFAULT;
            }
            /* Skip access interface and session views
             * if there is no access interface. */
            if(ctx->interfaces.access_if_count == 0) {
                switch (g_view_selected) {
                    case UI_VIEW_ACCESS_IF_STATS:
                    case UI_VIEW_SESSION:
                        g_view_selected = UI_VIEW_DEFAULT;
                        break;
                    default:
                        break;
                }
            }
            bbl_init_stats_win(ctx);
            break;
        case KEY_F(2):
            if(ctx->interfaces.network_if_count > 1) {
                g_network_if_selected++;
                if(g_network_if_selected >= ctx->interfaces.network_if_count) {
                    g_network_if_selected = 0;
                }
                bbl_init_stats_win(ctx);
            }
            break;
        case KEY_F(3):
            if(ctx->interfaces.a10nsp_if_count > 1) {
                g_a10nsp_if_selected++;
                if(g_a10nsp_if_selected >= ctx->interfaces.a10nsp_if_count) {
                    g_a10nsp_if_selected = 0;
                }
                bbl_init_stats_win(ctx);
            }
            break;
        case KEY_LEFT:
            if(g_view_selected == UI_VIEW_SESSION) {
                if(g_session_selected > 1) {
                    g_session_selected--;
                } else {
                    g_session_selected = ctx->sessions;
                }
            } else {
                if(g_access_if_selected == 0) {
                    g_access_if_selected = ctx->interfaces.access_if_count;
                }
                g_access_if_selected--;
            }
            bbl_init_stats_win(ctx);
            break;
        case KEY_RIGHT:
            if(g_view_selected == UI_VIEW_SESSION) {
                g_session_selected++;
                if(g_session_selected > ctx->sessions) {
                    g_session_selected = 1;
                }
            } else {
                g_access_if_selected++;
                if(g_access_if_selected >= ctx->interfaces.access_if_count) {
                    g_access_if_selected = 0;
                }
            }
            bbl_init_stats_win(ctx);
            break;
        case KEY_F(7):
            enable_disable_traffic(ctx, true);
            LOG_NOARG(INFO, "Start traffic\n");
            break;
        case KEY_F(8):
            enable_disable_traffic(ctx, false);
            LOG_NOARG(INFO, "Stop traffic\n");
            break;
        case KEY_F(9):
            g_teardown = true;
            g_teardown_request = true;
            LOG_NOARG(INFO, "Teardown request\n");
            break;
        case KEY_DOWN:
            if(g_view_selected == UI_VIEW_DEFAULT) {
                if(stats_win_postion < 6) {
                    stats_win_postion++;
                }
                bbl_init_stats_win(ctx);
            } else if(g_view_selected == UI_VIEW_SESSION) {
                stats_win_postion++;
                bbl_init_stats_win(ctx);
            }
            break;
        case KEY_UP:
            if(stats_win_postion) stats_win_postion--;
            bbl_init_stats_win(ctx);
            break;
        default:
            break;
    }
}

/*
 * Format a progress bar.
 */
static char *
bbl_format_progress (uint32_t complete, uint32_t current)
{
    static char buf[PROGRESS_BAR_SIZE+1];
    float percentage;
    uint16_t idx;

    if (!complete || !current) {
        memset(buf, ' ', sizeof(buf));
        goto EXIT;
    }

    percentage = (float)current / (float)complete;
    for (idx = 0; idx < sizeof(buf); idx++) {
        if (idx <= (percentage * PROGRESS_BAR_SIZE)) {
            buf[idx] = '#';
            continue;
        }
        buf[idx] = ' ';
    }

 EXIT:
    buf[PROGRESS_BAR_SIZE] = 0;
    return buf;
}

/*
 * Display meaningful stats in a curses window.
 */
void
bbl_stats_job (timer_s *timer)
{
    bbl_ctx_s *ctx = timer->data;
    struct bbl_interface_ *access_if;
    struct bbl_interface_ *network_if;
    struct bbl_interface_ *a10nsp_if;

    char strsp[STRING_SP_SIZE];

    bbl_session_s *session;
    int i;

    int pos = 1; /* position */
    bool visible = false;

    access_if = ctx->interfaces.access_if[g_access_if_selected];
    network_if = ctx->interfaces.network_if[g_network_if_selected];
    a10nsp_if = ctx->interfaces.a10nsp_if[g_a10nsp_if_selected];

    if(g_banner) {
        wmove(stats_win, 14, 0);
    } else {
        wmove(stats_win, 2, 0);
    }

    if(g_view_selected == UI_VIEW_DEFAULT) {
        VISIBLE((ctx->sessions)) {
            wprintw(stats_win, "\nSessions      %10lu (%lu PPPoE / %lu IPoE)\n", ctx->sessions, ctx->sessions_pppoe, ctx->sessions_ipoe);

            /* Progress bar established sessions */
            wprintw(stats_win, "  Established %10lu [", ctx->sessions_established);
            if(ctx->sessions == ctx->sessions_established) {
                wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                wprintw(stats_win, "%s", bbl_format_progress(ctx->sessions, ctx->sessions_established));
                wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
            } else {
                wattron(stats_win, COLOR_PAIR(COLOR_BLACK));
                wprintw(stats_win, "%s", bbl_format_progress(ctx->sessions, ctx->sessions_established));
                wattroff(stats_win, COLOR_PAIR(COLOR_BLACK));
            }
            wprintw(stats_win, "]\n");

            /* Progress bar outstanding sessions */
            wprintw(stats_win, "  Outstanding %10lu [", ctx->sessions_outstanding);
            wattron(stats_win, COLOR_PAIR(COLOR_BLACK));
            wprintw(stats_win, "%s", bbl_format_progress(ctx->config.sessions_max_outstanding, ctx->sessions_outstanding));
            wattroff(stats_win, COLOR_PAIR(COLOR_BLACK));
            wprintw(stats_win, "]\n");

            /* Progress bar terminated sessions */
            wprintw(stats_win, "  Terminated  %10lu [", ctx->sessions_terminated);
            wattron(stats_win, COLOR_PAIR(COLOR_RED));
            wprintw(stats_win, "%s", bbl_format_progress(ctx->sessions, ctx->sessions_terminated));
            wattroff(stats_win, COLOR_PAIR(COLOR_RED));
            wprintw(stats_win, "]\n");

            /* DHCPv4 */
            if(ctx->dhcp_requested || ctx->dhcp_established_max) {

                snprintf(strsp, STRING_SP_SIZE, "%u/%u", ctx->dhcp_established, ctx->dhcp_requested);
                wprintw(stats_win, "  DHCPv4 %15s [", strsp);
                if(ctx->dhcp_requested == ctx->dhcp_established) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, "%s", bbl_format_progress(ctx->dhcp_requested, ctx->dhcp_established));
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wattron(stats_win, COLOR_PAIR(COLOR_BLACK));
                    wprintw(stats_win, "%s", bbl_format_progress(ctx->dhcp_requested, ctx->dhcp_established));
                    wattroff(stats_win, COLOR_PAIR(COLOR_BLACK));
                }
                wprintw(stats_win, "]\n");
            }
            /* DHCPv6 */
            if(ctx->dhcpv6_requested || ctx->dhcpv6_established_max) {
                snprintf(strsp, STRING_SP_SIZE, "%u/%u", ctx->dhcpv6_established, ctx->dhcpv6_requested);
                wprintw(stats_win, "  DHCPv6 %15s [", strsp);
                if(ctx->dhcpv6_requested == ctx->dhcpv6_established) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, "%s", bbl_format_progress(ctx->dhcpv6_requested, ctx->dhcpv6_established));
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wattron(stats_win, COLOR_PAIR(COLOR_BLACK));
                    wprintw(stats_win, "%s", bbl_format_progress(ctx->dhcpv6_requested, ctx->dhcpv6_established));
                    wattroff(stats_win, COLOR_PAIR(COLOR_BLACK));
                }
                wprintw(stats_win, "]\n");
            }
            /* Session stats */
            wprintw(stats_win, "  Setup Time  %10lu ms\n", ctx->stats.setup_time);
            wprintw(stats_win, "  Setup Rate  %10.02lf CPS (MIN: %0.02lf AVG: %0.02lf MAX: %0.02lf)\n",
                    ctx->stats.cps, ctx->stats.cps_min, ctx->stats.cps_avg, ctx->stats.cps_max);
            wprintw(stats_win, "  Flapped     %10lu\n", ctx->sessions_flapped);
        }

        if(network_if) {
            VISIBLE((dict_count(ctx->li_flow_dict))) {
                wprintw(stats_win, "\nLI Statistics\n");
                wprintw(stats_win, "  Flows                     %10lu\n", dict_count(ctx->li_flow_dict));
                wprintw(stats_win, "  Rx Packets                %10lu (%7lu PPS)\n",
                    network_if->stats.li_rx, network_if->stats.rate_li_rx.avg);
            }
            VISIBLE((ctx->config.l2tp_server)) {
                wprintw(stats_win, "\nL2TP LNS Statistics\n");
                wprintw(stats_win, "  Tunnels     %10lu\n", ctx->l2tp_tunnels);
                wprintw(stats_win, "  Established %10lu\n", ctx->l2tp_tunnels_established);
                wprintw(stats_win, "  Sessions    %10lu\n", ctx->l2tp_sessions);
                wprintw(stats_win, "  Packets:\n");
                wprintw(stats_win, "    Tx Control              %10lu Retries: %lu\n",
                    network_if->stats.l2tp_control_tx, network_if->stats.l2tp_control_retry);
                wprintw(stats_win, "    Rx Control              %10lu Duplicate: %lu Out-of-Order: %lu\n",
                    network_if->stats.l2tp_control_rx,
                    network_if->stats.l2tp_control_rx_dup,
                    network_if->stats.l2tp_control_rx_ooo);
                wprintw(stats_win, "    Tx Data                 %10lu (%7lu PPS)\n",
                    network_if->stats.l2tp_data_tx, network_if->stats.rate_l2tp_data_tx.avg);
                wprintw(stats_win, "    Rx Data                 %10lu (%7lu PPS)\n",
                    network_if->stats.l2tp_data_rx, network_if->stats.rate_l2tp_data_rx.avg);
            }
        }

        VISIBLE((ctx->stats.session_traffic_flows || ctx->stats.stream_traffic_flows)) {
            wprintw(stats_win, "\nTraffic Flows Verified\n");
            if(ctx->stats.session_traffic_flows) {
                snprintf(strsp, STRING_SP_SIZE, "%u/%u", ctx->stats.session_traffic_flows_verified, ctx->stats.session_traffic_flows);
                wprintw(stats_win, "  Session %14s [", strsp);
                if(ctx->stats.session_traffic_flows == ctx->stats.session_traffic_flows_verified) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, "%s", bbl_format_progress(ctx->stats.session_traffic_flows, ctx->stats.session_traffic_flows_verified));
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wattron(stats_win, COLOR_PAIR(COLOR_BLACK));
                    wprintw(stats_win, "%s", bbl_format_progress(ctx->stats.session_traffic_flows, ctx->stats.session_traffic_flows_verified));
                    wattroff(stats_win, COLOR_PAIR(COLOR_BLACK));
                }
                wprintw(stats_win, "]\n");
            }
            if(ctx->stats.stream_traffic_flows) {
                snprintf(strsp, STRING_SP_SIZE, "%u/%u", ctx->stats.stream_traffic_flows_verified, ctx->stats.stream_traffic_flows);
                wprintw(stats_win, "  Stream %15s [", strsp);
                if(ctx->stats.stream_traffic_flows == ctx->stats.stream_traffic_flows_verified) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, "%s", bbl_format_progress(ctx->stats.stream_traffic_flows, ctx->stats.stream_traffic_flows_verified));
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wattron(stats_win, COLOR_PAIR(COLOR_BLACK));
                    wprintw(stats_win, "%s", bbl_format_progress(ctx->stats.stream_traffic_flows, ctx->stats.stream_traffic_flows_verified));
                    wattroff(stats_win, COLOR_PAIR(COLOR_BLACK));
                }
                wprintw(stats_win, "]\n");
            }
        }

        VISIBLE(network_if) {
            wprintw(stats_win, "\nNetwork Interface (");
            for(i = 0; i < ctx->interfaces.network_if_count; i++) {
                if(i == g_network_if_selected) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, " %s", ctx->interfaces.network_if[i]->name);
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wprintw(stats_win, " %s", ctx->interfaces.network_if[i]->name);
                }
            }
            wprintw(stats_win, " )\n  Tx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                network_if->stats.packets_tx, network_if->stats.rate_packets_tx.avg,
                network_if->stats.rate_bytes_tx.avg * 8 / 1000);
            wprintw(stats_win, "  Rx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                network_if->stats.packets_rx, network_if->stats.rate_packets_rx.avg,
                network_if->stats.rate_bytes_rx.avg * 8 / 1000);
            if(ctx->stats.stream_traffic_flows) {
                wprintw(stats_win, "  Tx Stream Packets         %10lu |%7lu PPS\n",
                    network_if->stats.stream_tx, network_if->stats.rate_stream_tx.avg);
                wprintw(stats_win, "  Rx Stream Packets         %10lu |%7lu PPS %10lu Loss\n",
                    network_if->stats.stream_rx, network_if->stats.rate_stream_rx.avg,
                    network_if->stats.stream_loss);
            }
            if(ctx->stats.session_traffic_flows) {
                wprintw(stats_win, "  Tx Session Packets        %10lu |%7lu PPS\n",
                    network_if->stats.session_ipv4_tx, network_if->stats.rate_session_ipv4_tx.avg);
                wprintw(stats_win, "  Rx Session Packets        %10lu |%7lu PPS %10lu Loss\n",
                    network_if->stats.session_ipv4_rx, network_if->stats.rate_session_ipv4_rx.avg,
                    network_if->stats.session_ipv4_loss);
                wprintw(stats_win, "  Tx Session Packets IPv6   %10lu |%7lu PPS\n",
                    network_if->stats.session_ipv6_tx, network_if->stats.rate_session_ipv6_tx.avg);
                wprintw(stats_win, "  Rx Session Packets IPv6   %10lu |%7lu PPS %10lu Loss\n",
                    network_if->stats.session_ipv6_rx, network_if->stats.rate_session_ipv6_rx.avg,
                    network_if->stats.session_ipv6_loss);
                wprintw(stats_win, "  Tx Session Packets IPv6PD %10lu |%7lu PPS\n",
                    network_if->stats.session_ipv6pd_tx, network_if->stats.rate_session_ipv6pd_tx.avg);
                wprintw(stats_win, "  Rx Session Packets IPv6PD %10lu |%7lu PPS %10lu Loss\n",
                    network_if->stats.session_ipv6pd_rx, network_if->stats.rate_session_ipv6pd_rx.avg,
                    network_if->stats.session_ipv6pd_loss);
            }
            wprintw(stats_win, "  Tx Multicast Packets      %10lu |%7lu PPS\n",
                network_if->stats.mc_tx, network_if->stats.rate_mc_tx.avg);
        }
        VISIBLE(a10nsp_if) {
            wprintw(stats_win, "\nA10NSP Interface (");
            for(i = 0; i < ctx->interfaces.a10nsp_if_count; i++) {
                if(i == g_a10nsp_if_selected) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, " %s", ctx->interfaces.a10nsp_if[i]->name);
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wprintw(stats_win, " %s", ctx->interfaces.a10nsp_if[i]->name);
                }
            }
            wprintw(stats_win, " )\n  Tx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                a10nsp_if->stats.packets_tx, a10nsp_if->stats.rate_packets_tx.avg,
                a10nsp_if->stats.rate_bytes_tx.avg * 8 / 1000);
            wprintw(stats_win, "  Rx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                a10nsp_if->stats.packets_rx, a10nsp_if->stats.rate_packets_rx.avg,
                a10nsp_if->stats.rate_bytes_rx.avg * 8 / 1000);
            if(ctx->stats.stream_traffic_flows) {
                wprintw(stats_win, "  Tx Stream Packets         %10lu |%7lu PPS\n",
                    a10nsp_if->stats.stream_tx, a10nsp_if->stats.rate_stream_tx.avg);
                wprintw(stats_win, "  Rx Stream Packets         %10lu |%7lu PPS %10lu Loss\n",
                    a10nsp_if->stats.stream_rx, a10nsp_if->stats.rate_stream_rx.avg,
                    a10nsp_if->stats.stream_loss);
            }
            if(ctx->stats.session_traffic_flows) {
                wprintw(stats_win, "  Tx Session Packets        %10lu |%7lu PPS\n",
                    a10nsp_if->stats.session_ipv4_tx, a10nsp_if->stats.rate_session_ipv4_tx.avg);
                wprintw(stats_win, "  Rx Session Packets        %10lu |%7lu PPS %10lu Loss\n",
                    a10nsp_if->stats.session_ipv4_rx, a10nsp_if->stats.rate_session_ipv4_rx.avg,
                    a10nsp_if->stats.session_ipv4_loss);
            }
        }
        VISIBLE(access_if) {
            wprintw(stats_win, "\nAccess Interface (");
            for(i = 0; i < ctx->interfaces.access_if_count; i++) {
                if(i == g_access_if_selected) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, " %s", ctx->interfaces.access_if[i]->name);
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wprintw(stats_win, " %s", ctx->interfaces.access_if[i]->name);
                }
            }
            wprintw(stats_win, " )\n  Tx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                access_if->stats.packets_tx, access_if->stats.rate_packets_tx.avg,
                access_if->stats.rate_bytes_tx.avg * 8 / 1000);
            wprintw(stats_win, "  Rx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                access_if->stats.packets_rx, access_if->stats.rate_packets_rx.avg,
                access_if->stats.rate_bytes_rx.avg * 8 / 1000);
            if(ctx->stats.stream_traffic_flows) {
                wprintw(stats_win, "  Tx Stream Packets         %10lu |%7lu PPS\n",
                    access_if->stats.stream_tx, access_if->stats.rate_stream_tx.avg);
                wprintw(stats_win, "  Rx Stream Packets         %10lu |%7lu PPS %10lu Loss\n",
                    access_if->stats.stream_rx, access_if->stats.rate_stream_rx.avg,
                    access_if->stats.stream_loss);
            }
            if(ctx->stats.session_traffic_flows) {
                wprintw(stats_win, "  Tx Session Packets        %10lu |%7lu PPS\n",
                    access_if->stats.session_ipv4_tx, access_if->stats.rate_session_ipv4_tx.avg);
                wprintw(stats_win, "  Rx Session Packets        %10lu |%7lu PPS %10lu Loss %lu Wrong Session\n",
                    access_if->stats.session_ipv4_rx, access_if->stats.rate_session_ipv4_rx.avg,
                    access_if->stats.session_ipv4_loss, access_if->stats.session_ipv4_wrong_session);
                wprintw(stats_win, "  Tx Session Packets IPv6   %10lu |%7lu PPS\n",
                    access_if->stats.session_ipv6_tx, access_if->stats.rate_session_ipv6_tx.avg);
                wprintw(stats_win, "  Rx Session Packets IPv6   %10lu |%7lu PPS %10lu Loss %lu Wrong Session\n",
                    access_if->stats.session_ipv6_rx, access_if->stats.rate_session_ipv6_rx.avg,
                    access_if->stats.session_ipv6_loss, access_if->stats.session_ipv6_wrong_session);
                wprintw(stats_win, "  Tx Session Packets IPv6PD %10lu |%7lu PPS\n",
                    access_if->stats.session_ipv6pd_tx, access_if->stats.rate_session_ipv6pd_tx.avg);
                wprintw(stats_win, "  Rx Session Packets IPv6PD %10lu |%7lu PPS %10lu Loss %lu Wrong Session\n",
                    access_if->stats.session_ipv6pd_rx, access_if->stats.rate_session_ipv6pd_rx.avg,
                    access_if->stats.session_ipv6pd_loss, access_if->stats.session_ipv6pd_wrong_session);
            }
            wprintw(stats_win, "  Rx Multicast Packets      %10lu |%7lu PPS %10lu Loss\n",
                access_if->stats.mc_rx, access_if->stats.rate_mc_rx.avg,
                access_if->stats.mc_loss);
        }
    } else if(g_view_selected == UI_VIEW_ACCESS_IF_STATS) {
        if(access_if) {
            wprintw(stats_win, "\nAccess Interface Protocol Stats (");
            for(i = 0; i < ctx->interfaces.access_if_count; i++) {
                if(i == g_access_if_selected) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, " %s", ctx->interfaces.access_if[i]->name);
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wprintw(stats_win, " %s", ctx->interfaces.access_if[i]->name);
                }
            }
            wprintw(stats_win, " )\n");
            wprintw(stats_win, "\nPacket Stats\n");
            wprintw(stats_win, "  ARP    TX: %10u RX: %10u\n", access_if->stats.arp_tx, access_if->stats.arp_rx);
            wprintw(stats_win, "  PADI   TX: %10u RX: %10u\n", access_if->stats.padi_tx, 0);
            wprintw(stats_win, "  PADO   TX: %10u RX: %10u\n", 0, access_if->stats.pado_rx);
            wprintw(stats_win, "  PADR   TX: %10u RX: %10u\n", access_if->stats.padr_tx, 0);
            wprintw(stats_win, "  PADS   TX: %10u RX: %10u\n", 0, access_if->stats.pads_rx);
            wprintw(stats_win, "  PADT   TX: %10u RX: %10u\n", access_if->stats.padt_tx, access_if->stats.padt_rx);
            wprintw(stats_win, "  LCP    TX: %10u RX: %10u\n", access_if->stats.lcp_tx, access_if->stats.lcp_rx);
            wprintw(stats_win, "  PAP    TX: %10u RX: %10u\n", access_if->stats.pap_tx, access_if->stats.pap_rx);
            wprintw(stats_win, "  CHAP   TX: %10u RX: %10u\n", access_if->stats.chap_tx, access_if->stats.chap_rx);
            wprintw(stats_win, "  IPCP   TX: %10u RX: %10u\n", access_if->stats.ipcp_tx, access_if->stats.ipcp_rx);
            wprintw(stats_win, "  IP6CP  TX: %10u RX: %10u\n", access_if->stats.ip6cp_tx, access_if->stats.ip6cp_rx);
            wprintw(stats_win, "  IGMP   TX: %10u RX: %10u\n", access_if->stats.igmp_tx, access_if->stats.igmp_rx);
            wprintw(stats_win, "  ICMP   TX: %10u RX: %10u\n", access_if->stats.icmp_tx, access_if->stats.icmp_rx);
            wprintw(stats_win, "  DHCP   TX: %10u RX: %10u\n", access_if->stats.dhcp_tx, access_if->stats.dhcp_rx);
            wprintw(stats_win, "  DHCPv6 TX: %10u RX: %10u\n", access_if->stats.dhcpv6_tx, access_if->stats.dhcpv6_rx);
            wprintw(stats_win, "  ICMPv6 TX: %10u RX: %10u\n", access_if->stats.icmpv6_tx, access_if->stats.icmpv6_rx);

            wprintw(stats_win, "\nTimeout Stats\n");
            wprintw(stats_win, "  LCP Echo Request: %10u\n", access_if->stats.lcp_echo_timeout);
            wprintw(stats_win, "  LCP Request:      %10u\n", access_if->stats.lcp_timeout);
            wprintw(stats_win, "  IPCP Request:     %10u\n", access_if->stats.ipcp_timeout);
            wprintw(stats_win, "  IP6CP Request:    %10u\n", access_if->stats.ip6cp_timeout);
            wprintw(stats_win, "  PAP:              %10u\n", access_if->stats.pap_timeout);
            wprintw(stats_win, "  CHAP:             %10u\n", access_if->stats.chap_timeout);
            wprintw(stats_win, "  DHCP Request:     %10u\n", access_if->stats.dhcp_timeout);
            wprintw(stats_win, "  DHCPv6 Request:   %10u\n", access_if->stats.dhcpv6_timeout);
            wprintw(stats_win, "  ICMPv6 RS:        %10u\n", access_if->stats.icmpv6_rs_timeout);
        } else {
            wprintw(stats_win, "\nAccess Interface Protocol Stats");
        }

    } else if(g_view_selected == UI_VIEW_SESSION) {
        wprintw(stats_win, "\nSession and Streams ( Session-Id: ", g_session_selected);
        wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
        wprintw(stats_win, "%u", g_session_selected);
        wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
        wprintw(stats_win, " )\n", g_session_selected);
        session = bbl_session_get(ctx, g_session_selected);
        if(session) {
            wprintw(stats_win, "\n     State: %s \n", session_state_string(session->session_state));
            if(session->username) {
                wprintw(stats_win, "  Username: %s \n", session->username);
            }
            if(session->agent_remote_id) {
                wprintw(stats_win, "       ARI: %s \n", session->agent_remote_id);
            }
            if(session->agent_remote_id) {
                wprintw(stats_win, "       ACI: %s \n", session->agent_circuit_id);
            }
            if(session->connections_status_message || session->reply_message) {
                wprintw(stats_win, "\n");
                if(session->reply_message) {
                    wprintw(stats_win, "  Reply-Message: %s \n", session->reply_message);
                }
                if(session->connections_status_message) {
                    wprintw(stats_win, "  Connection-Status-Message: %s \n", session->connections_status_message);
                }
            }
            wprintw(stats_win, "\n  Access Client Interface\n");
            wprintw(stats_win, "    Tx Packets %10lu | %7lu PPS | %10lu Kbps\n",
                session->stats.packets_tx, session->stats.rate_packets_tx.avg,
                session->stats.rate_bytes_tx.avg * 8 / 1000);
            wprintw(stats_win, "    Rx Packets %10lu | %7lu PPS | %10lu Kbps\n",
                session->stats.packets_rx, session->stats.rate_packets_rx.avg,
                session->stats.rate_bytes_rx.avg * 8 / 1000);

            if(session->stream) {
                wprintw(stats_win, "\n  Stream           | Direction | Tx PPS  | Tx Kbps    | Rx PPS  | Rx Kbps    | Loss\n");
                wprintw(stats_win, "  -------------------------------------------------------------------------------------\n");

                uint64_t tx_kbps;
                uint64_t rx_kbps;
                uint64_t stream_sum_up_tx_pps = 0;
                uint64_t stream_sum_up_tx_kbps = 0;
                uint64_t stream_sum_up_rx_pps = 0;
                uint64_t stream_sum_up_rx_kbps = 0;
                uint64_t stream_sum_up_loss = 0;
                uint64_t stream_sum_down_tx_pps = 0;
                uint64_t stream_sum_down_rx_pps = 0;
                uint64_t stream_sum_down_tx_kbps = 0;
                uint64_t stream_sum_down_rx_kbps = 0;
                uint64_t stream_sum_down_loss = 0;

                bbl_stream *stream = session->stream;
                i = 0;
                while(stream) {
                    tx_kbps = stream->rate_packets_tx.avg * stream->tx_len * 8 / 1000;
                    rx_kbps = stream->rate_packets_rx.avg * stream->rx_len * 8 / 1000;
                    if(i >= stats_win_postion && i < 16+stats_win_postion) {
                        wprintw(stats_win, "  %-16.16s | %-9.9s | %7lu | %10lu | %7lu | %10lu | %8lu\n", stream->config->name,
                                stream->direction == STREAM_DIRECTION_UP ? "up" : "down",
                                stream->rate_packets_tx.avg, tx_kbps, stream->rate_packets_rx.avg, rx_kbps, stream->loss);
                    } else if (i == 16+stats_win_postion) {   
                        wprintw(stats_win, "  ...\n");
                    }
                    i++;

                    if(stream->direction == STREAM_DIRECTION_UP) {
                        stream_sum_up_tx_pps += stream->rate_packets_tx.avg;
                        stream_sum_up_tx_kbps += tx_kbps;
                        stream_sum_up_rx_pps += stream->rate_packets_rx.avg;
                        stream_sum_up_rx_kbps += rx_kbps;
                        stream_sum_up_loss += stream->loss;
                    } else {
                        stream_sum_down_tx_pps += stream->rate_packets_tx.avg;
                        stream_sum_down_tx_kbps += tx_kbps;
                        stream_sum_down_rx_pps += stream->rate_packets_rx.avg;
                        stream_sum_down_rx_kbps += rx_kbps;
                        stream_sum_down_loss += stream->loss;
                    }
                    stream = stream->next;
                }
                wprintw(stats_win, "  =====================================================================================\n");
                wprintw(stats_win, "  SUM              | up        | %7lu | %10lu | %7lu | %10lu | %8lu\n",
                        stream_sum_up_tx_pps, stream_sum_up_tx_kbps, stream_sum_up_rx_pps, stream_sum_up_rx_kbps, stream_sum_up_loss);
                wprintw(stats_win, "                   | down      | %7lu | %10lu | %7lu | %10lu | %8lu\n",
                        stream_sum_down_tx_pps, stream_sum_down_tx_kbps, stream_sum_down_rx_pps, stream_sum_down_rx_kbps, stream_sum_down_loss);
            }
        }
    }
    wrefresh(stats_win);
}

/*
 * Curses init.
 */
void
bbl_init_curses (bbl_ctx_s *ctx)
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    /* Stats window */
    stats_win = newwin(LINES, STATS_WIN_SIZE, 0, 0);
    stats_win_postion = 0;

    /* Log window */
    log_win = newwin(LINES, COLS-STATS_WIN_SIZE, 0, STATS_WIN_SIZE);
    scrollok(log_win, TRUE);

    start_color();
    init_pair(1, COLOR_RED, COLOR_BLACK);
    init_pair(2, COLOR_GREEN, COLOR_BLACK);
    init_pair(3, COLOR_BLACK, COLOR_CYAN);
    init_pair(4, COLOR_BLACK, COLOR_BLUE);

    curs_set(0); /* cursor off */
    refresh();

    timeout(0);
    bbl_init_stats_win(ctx);
    wrefresh(stats_win);

    timer_add_periodic(&ctx->timer_root, &ctx->stats_timer, "Statistics Timer",
                       0, 100 * MSEC, ctx, &bbl_stats_job);
    timer_add_periodic(&ctx->timer_root, &ctx->keyboard_timer, "Keyboard Reader",
                       0, 100 * MSEC, ctx, &bbl_read_key_job);

    g_interactive = true;
}