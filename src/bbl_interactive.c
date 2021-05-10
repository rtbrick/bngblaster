/*
 * BNG Blaster (BBL) - Interactive Mode
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_stats.h"
#include "bbl_logging.h"
#include "bbl_session.h"
#include "bbl_stream.h"

#define PROGRESS_BAR_SIZE   60
#define STATS_WIN_SIZE      90

typedef enum {
    UI_VIEW_DEFAULT = 0,
    UI_VIEW_STREAMS,
    UI_VIEW_MAX,
} __attribute__ ((__packed__)) bbl_ui_view;


/* ncurses */
WINDOW *stats_win = NULL;
WINDOW *log_win = NULL;

extern volatile bool g_teardown;
extern volatile bool g_teardown_request;

/* This global variable is used to switch between access interfaces. */
uint8_t g_access_if_selected = 0;
/* This global variable is used to switch between views. */
bbl_ui_view g_view_selected = 0;
/* This global variable is used to switch vetween sessions in some views. */
uint32_t g_session_selected = 1; 

extern const char banner[];

void 
bbl_init_stats_win()
{
    wclear(stats_win);
    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
    wprintw(stats_win, "F1: Select View    F2: Select Session  F3: Select Interface\n");
    wprintw(stats_win, "F7: Start Traffic  F8: Stop Traffic    F9: Terminate Sessions\n");
    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
    wprintw(stats_win, "%s", banner);
}

static void
enable_disable_traffic(bbl_ctx_s *ctx, bool status)
{
    bbl_session_s *session;
    uint32_t i;

    /* Iterate over all sessions */
    for(i = 0; i < ctx->sessions; i++) {
        session = ctx->session_list[i];
        if(session) {
            session->session_traffic = status;
            session->stream_traffic = status;
        }
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
            g_view_selected++;
            if(g_view_selected >= UI_VIEW_MAX) {
                g_view_selected = UI_VIEW_DEFAULT;
            }
            bbl_init_stats_win();
            break;
        case KEY_F(2):
            g_session_selected++;
            if(g_session_selected > ctx->sessions) {
                g_session_selected = 1;
            }
            bbl_init_stats_win();
            break;
        case KEY_F(6):
            g_access_if_selected++;
            if(g_access_if_selected >= ctx->op.access_if_count) {
                g_access_if_selected = 0;
            }
            bbl_init_stats_win();
            break;
        case KEY_F(7):
            enable_disable_traffic(ctx, true);
            LOG(NORMAL, "Start traffic\n");
            break;
        case KEY_F(8):
            enable_disable_traffic(ctx, false);
            LOG(NORMAL, "Stop traffic\n");
            break;
        case KEY_F(9):
            g_teardown = true;
            g_teardown_request = true;
            LOG(NORMAL, "Teardown request\n");
            break;
        default:
	        break;
    }
}

/*
 * Format a progress bar.
 */
char *
bbl_format_progress (uint complete, uint current)
{
    static char buf[PROGRESS_BAR_SIZE+1];
    float percentage;
    uint idx;

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
    
    bbl_session_s *session;

    int max_x, max_y;
    int i; 

    access_if = ctx->op.access_if[g_access_if_selected];

    wmove(stats_win, 14, 0);
    getmaxyx(stats_win, max_y, max_x);

    (void)max_x;

    if(g_view_selected == UI_VIEW_DEFAULT) {

        if(ctx->sessions) {
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

            /* Session stats */
            wprintw(stats_win, "  Setup Time  %10lu ms\n", ctx->stats.setup_time);
            wprintw(stats_win, "  Setup Rate  %10.02lf CPS (MIN: %0.02lf AVG: %0.02lf MAX: %0.02lf)\n",
                    ctx->stats.cps, ctx->stats.cps_min, ctx->stats.cps_avg, ctx->stats.cps_max);
            wprintw(stats_win, "  Flapped     %10lu\n", ctx->sessions_flapped);

            /* DHCPv6 */
            if(ctx->config.dhcpv6_enable) {
                wprintw(stats_win, "\nDHCPv6\n");
                wprintw(stats_win, "  Sessions    %10lu\n", ctx->dhcpv6_requested);
                wprintw(stats_win, "  Established %10lu [", ctx->dhcpv6_established);
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
        }

        if (ctx->op.network_if) {
            if(dict_count(ctx->li_flow_dict)) {
                wprintw(stats_win, "\nLI Statistics\n");
                wprintw(stats_win, "  Flows                     %10lu\n", dict_count(ctx->li_flow_dict));
                wprintw(stats_win, "  Rx Packets                %10lu (%7lu PPS)\n",  
                    ctx->op.network_if->stats.li_rx, ctx->op.network_if->stats.rate_li_rx.avg);
            }
            if(ctx->config.l2tp_server) {
                wprintw(stats_win, "\nL2TP LNS Statistics\n");
                wprintw(stats_win, "  Tunnels     %10lu\n", ctx->l2tp_tunnels);
                wprintw(stats_win, "  Established %10lu\n", ctx->l2tp_tunnels_established);
                wprintw(stats_win, "  Sessions    %10lu\n", ctx->l2tp_sessions);
                wprintw(stats_win, "  Packets:\n");
                wprintw(stats_win, "    Tx Control              %10lu Retries: %lu\n", 
                    ctx->op.network_if->stats.l2tp_control_tx, ctx->op.network_if->stats.l2tp_control_retry);
                wprintw(stats_win, "    Rx Control              %10lu Duplicate: %lu Out-of-Order: %lu\n", 
                    ctx->op.network_if->stats.l2tp_control_rx, 
                    ctx->op.network_if->stats.l2tp_control_rx_dup, 
                    ctx->op.network_if->stats.l2tp_control_rx_ooo);
                wprintw(stats_win, "    Tx Data                 %10lu (%7lu PPS)\n", 
                    ctx->op.network_if->stats.l2tp_data_tx, ctx->op.network_if->stats.rate_l2tp_data_tx.avg);
                wprintw(stats_win, "    Rx Data                 %10lu (%7lu PPS)\n", 
                    ctx->op.network_if->stats.l2tp_data_rx, ctx->op.network_if->stats.rate_l2tp_data_tx.avg);
            }

            if(access_if && ctx->stats.session_traffic_flows) {
                wprintw(stats_win, "\nSession Traffic\n");
                wprintw(stats_win, "  Flows       %10lu\n", ctx->stats.session_traffic_flows);
                /* Progress bar session traffic flows */
                wprintw(stats_win, "  Verified    %10lu [", ctx->stats.session_traffic_flows_verified);
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
            wprintw(stats_win, "\nNetwork Interface (");
            wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
            wprintw(stats_win, " %s", ctx->op.network_if->name);
            wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
            wprintw(stats_win, " )\n  Tx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                ctx->op.network_if->stats.packets_tx, ctx->op.network_if->stats.rate_packets_tx.avg, 
                ctx->op.network_if->stats.rate_bytes_tx.avg * 8 / 1000);
            wprintw(stats_win, "  Rx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                ctx->op.network_if->stats.packets_rx, ctx->op.network_if->stats.rate_packets_rx.avg, 
                ctx->op.network_if->stats.rate_bytes_rx.avg * 8 / 1000);
            wprintw(stats_win, "  Tx Session Packets        %10lu |%7lu PPS\n",
                ctx->op.network_if->stats.session_ipv4_tx, ctx->op.network_if->stats.rate_session_ipv4_tx.avg);
            wprintw(stats_win, "  Rx Session Packets        %10lu |%7lu PPS %10lu Loss\n",
                ctx->op.network_if->stats.session_ipv4_rx, ctx->op.network_if->stats.rate_session_ipv4_rx.avg,
                ctx->op.network_if->stats.session_ipv4_loss);
            wprintw(stats_win, "  Tx Session Packets IPv6   %10lu |%7lu PPS\n",
                ctx->op.network_if->stats.session_ipv6_tx, ctx->op.network_if->stats.rate_session_ipv6_tx.avg);
            wprintw(stats_win, "  Rx Session Packets IPv6   %10lu |%7lu PPS %10lu Loss\n",
                ctx->op.network_if->stats.session_ipv6_rx, ctx->op.network_if->stats.rate_session_ipv6_rx.avg,
                ctx->op.network_if->stats.session_ipv6_loss);
            wprintw(stats_win, "  Tx Session Packets IPv6PD %10lu |%7lu PPS\n",
                ctx->op.network_if->stats.session_ipv6pd_tx, ctx->op.network_if->stats.rate_session_ipv6pd_tx.avg);
            wprintw(stats_win, "  Rx Session Packets IPv6PD %10lu |%7lu PPS %10lu Loss\n",
                ctx->op.network_if->stats.session_ipv6pd_rx, ctx->op.network_if->stats.rate_session_ipv6pd_rx.avg,
                ctx->op.network_if->stats.session_ipv6pd_loss);
            wprintw(stats_win, "  Tx Multicast Packets      %10lu |%7lu PPS\n",
                ctx->op.network_if->stats.mc_tx, ctx->op.network_if->stats.rate_mc_tx.avg);
        }

        if(access_if) {
            wprintw(stats_win, "\nAccess Interface (");
            for(i = 0; i < ctx->op.access_if_count; i++) {
                if(i == g_access_if_selected) {
                    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
                    wprintw(stats_win, " %s", ctx->op.access_if[i]->name);
                    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
                } else {
                    wprintw(stats_win, " %s", ctx->op.access_if[i]->name); 
                }
            }
            wprintw(stats_win, " )\n  Tx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                access_if->stats.packets_tx, access_if->stats.rate_packets_tx.avg, 
                access_if->stats.rate_bytes_tx.avg * 8 / 1000);
            wprintw(stats_win, "  Rx Packets                %10lu |%7lu PPS %10lu Kbps\n",
                access_if->stats.packets_rx, access_if->stats.rate_packets_rx.avg, 
                access_if->stats.rate_bytes_rx.avg * 8 / 1000);
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
            wprintw(stats_win, "  Rx Multicast Packets      %10lu |%7lu PPS %10lu Loss\n",
                access_if->stats.mc_rx, access_if->stats.rate_mc_rx.avg,
                access_if->stats.mc_loss);

            /* Protocol stats */
            if(max_y > 70) {
                wprintw(stats_win, "\nAccess Interface Protocol Packet Stats\n");
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
                wprintw(stats_win, "  ICMPv6 TX: %10u RX: %10u\n", access_if->stats.icmpv6_tx, access_if->stats.icmpv6_rx);
                wprintw(stats_win, "  DHCPv6 TX: %10u RX: %10u\n", access_if->stats.dhcpv6_tx, access_if->stats.dhcpv6_rx);
                wprintw(stats_win, "  DHCP   TX: %10u RX: %10u\n", access_if->stats.dhcp_tx, access_if->stats.dhcp_rx);
            }
            if(max_y > 80) {
                wprintw(stats_win, "\nAccess Interface Protocol Timeout Stats\n");
                wprintw(stats_win, "  LCP Echo Request: %10u\n", access_if->stats.lcp_echo_timeout);
                wprintw(stats_win, "  LCP Request:      %10u\n", access_if->stats.lcp_timeout);
                wprintw(stats_win, "  IPCP Request:     %10u\n", access_if->stats.ipcp_timeout);
                wprintw(stats_win, "  IP6CP Request:    %10u\n", access_if->stats.ip6cp_timeout);
                wprintw(stats_win, "  PAP:              %10u\n", access_if->stats.pap_timeout);
                wprintw(stats_win, "  CHAP:             %10u\n", access_if->stats.chap_timeout);
                wprintw(stats_win, "  ICMPv6 RS:        %10u\n", access_if->stats.dhcpv6_timeout);
                wprintw(stats_win, "  DHCPv6 Request:   %10u\n", access_if->stats.dhcpv6_timeout);
            }
        }
    } else if(g_view_selected == UI_VIEW_STREAMS) {
        wprintw(stats_win, "\nSession Stream Stats ( Session-Id: ", g_session_selected);
        wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
        wprintw(stats_win, "%u", g_session_selected);
        wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
        wprintw(stats_win, " )\n", g_session_selected);
        session = bbl_session_get(ctx, g_session_selected);
        if(session) {
            if(session->username) {
                wprintw(stats_win, "\n  Username: %s \n", session->username);
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
                while(stream) {
                    tx_kbps = stream->rate_packets_tx.avg * stream->tx_len * 8 / 1000;
                    rx_kbps = stream->rate_packets_rx.avg * stream->rx_len * 8 / 1000;
                    wprintw(stats_win, "  %-16.16s | %-9.9s | %7lu | %10lu | %7lu | %10lu | %8lu\n", stream->config->name, 
                            stream->direction == STREAM_DIRECTION_UP ? "up" : "down",
                            stream->rate_packets_tx.avg, tx_kbps, stream->rate_packets_rx.avg, rx_kbps, stream->loss);

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
    bbl_init_stats_win();
    wrefresh(stats_win);

    timer_add_periodic(&ctx->timer_root, &ctx->stats_timer, "Statistics Timer",
		               0, 100 * MSEC, ctx, &bbl_stats_job);
    timer_add_periodic(&ctx->timer_root, &ctx->keyboard_timer, "Keyboard Reader",
		               0, 100 * MSEC, ctx, &bbl_read_key_job);

    g_interactive = true;
}
