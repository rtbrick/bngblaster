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

#define PROGRESS_BAR_SIZE   60
#define STATS_WIN_SIZE      90

/* ncurses */
WINDOW *stats_win = NULL;
WINDOW *log_win = NULL;

extern volatile bool g_teardown;
extern volatile bool g_teardown_request;
extern uint8_t g_access_if_selected;

extern const char banner[];

static void
enable_disable_session_traffic(bbl_ctx_s *ctx, bool status)
{
    struct dict_itor *itor;
    bbl_session_s *session;

    /* Iterate over all sessions */
    itor = dict_itor_new(ctx->session_dict);
    dict_itor_first(itor);
    for (; dict_itor_valid(itor); dict_itor_next(itor)) {
        session = (bbl_session_s*)*dict_itor_datum(itor);
        if(session) {
            session->session_traffic = status;
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
        case KEY_F(6):
            g_access_if_selected++;
            if(g_access_if_selected >= ctx->op.access_if_count) {
                g_access_if_selected = 0;
            }
            break;
        case KEY_F(7):
            enable_disable_session_traffic(ctx, true);
            LOG(NORMAL, "Enable session traffic\n");
            break;
        case KEY_F(8):
            enable_disable_session_traffic(ctx, false);
            LOG(NORMAL, "Disable session traffic\n");
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
        goto exit;
    }

    percentage = (float)current / (float)complete;
    for (idx = 0; idx < sizeof(buf); idx++) {
        if (idx <= (percentage * PROGRESS_BAR_SIZE)) {
            buf[idx] = '#';
            continue;
        }
        buf[idx] = ' ';
    }

 exit:
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
    int max_x, max_y;
    int i; 

    access_if = ctx->op.access_if[g_access_if_selected];

    wmove(stats_win, 12, 0);
    getmaxyx(stats_win, max_y, max_x);

    (void)max_x;

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
        wprintw(stats_win, " )\n  Tx Packets                %10lu (%7lu PPS)\n",
            ctx->op.network_if->stats.packets_tx, ctx->op.network_if->stats.rate_packets_tx.avg);
        wprintw(stats_win, "  Rx Packets                %10lu (%7lu PPS)\n",
            ctx->op.network_if->stats.packets_rx, ctx->op.network_if->stats.rate_packets_rx.avg);
        wprintw(stats_win, "  Tx Session Packets        %10lu (%7lu PPS)\n",
            ctx->op.network_if->stats.session_ipv4_tx, ctx->op.network_if->stats.rate_session_ipv4_tx.avg);
        wprintw(stats_win, "  Rx Session Packets        %10lu (%7lu PPS) Loss: %lu\n",
            ctx->op.network_if->stats.session_ipv4_rx, ctx->op.network_if->stats.rate_session_ipv4_rx.avg,
            ctx->op.network_if->stats.session_ipv4_loss);
        wprintw(stats_win, "  Tx Session Packets IPv6   %10lu (%7lu PPS)\n",
            ctx->op.network_if->stats.session_ipv6_tx, ctx->op.network_if->stats.rate_session_ipv6_tx.avg);
        wprintw(stats_win, "  Rx Session Packets IPv6   %10lu (%7lu PPS) Loss: %lu\n",
            ctx->op.network_if->stats.session_ipv6_rx, ctx->op.network_if->stats.rate_session_ipv6_rx.avg,
            ctx->op.network_if->stats.session_ipv6_loss);
        wprintw(stats_win, "  Tx Session Packets IPv6PD %10lu (%7lu PPS)\n",
            ctx->op.network_if->stats.session_ipv6pd_tx, ctx->op.network_if->stats.rate_session_ipv6pd_tx.avg);
        wprintw(stats_win, "  Rx Session Packets IPv6PD %10lu (%7lu PPS) Loss: %lu\n",
            ctx->op.network_if->stats.session_ipv6pd_rx, ctx->op.network_if->stats.rate_session_ipv6pd_rx.avg,
            ctx->op.network_if->stats.session_ipv6pd_loss);
        wprintw(stats_win, "  Tx Multicast Packets      %10lu (%7lu PPS)\n",
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
        wprintw(stats_win, " )\n  Tx Packets                %10lu (%7lu PPS)\n",
            access_if->stats.packets_tx, access_if->stats.rate_packets_tx.avg);
        wprintw(stats_win, "  Rx Packets                %10lu (%7lu PPS)\n",
            access_if->stats.packets_rx, access_if->stats.rate_packets_rx.avg);
        wprintw(stats_win, "  Tx Session Packets        %10lu (%7lu PPS)\n",
            access_if->stats.session_ipv4_tx, access_if->stats.rate_session_ipv4_tx.avg);
        wprintw(stats_win, "  Rx Session Packets        %10lu (%7lu PPS) Loss: %lu Wrong Session: %lu\n",
            access_if->stats.session_ipv4_rx, access_if->stats.rate_session_ipv4_rx.avg,
            access_if->stats.session_ipv4_loss, access_if->stats.session_ipv4_wrong_session);
        wprintw(stats_win, "  Tx Session Packets IPv6   %10lu (%7lu PPS)\n",
            access_if->stats.session_ipv6_tx, access_if->stats.rate_session_ipv6_tx.avg);
        wprintw(stats_win, "  Rx Session Packets IPv6   %10lu (%7lu PPS) Loss: %lu Wrong Session: %lu\n",
            access_if->stats.session_ipv6_rx, access_if->stats.rate_session_ipv6_rx.avg,
            access_if->stats.session_ipv6_loss, access_if->stats.session_ipv6_wrong_session);
        wprintw(stats_win, "  Tx Session Packets IPv6PD %10lu (%7lu PPS)\n",
            access_if->stats.session_ipv6pd_tx, access_if->stats.rate_session_ipv6pd_tx.avg);
        wprintw(stats_win, "  Rx Session Packets IPv6PD %10lu (%7lu PPS) Loss: %lu Wrong Session: %lu\n",
            access_if->stats.session_ipv6pd_rx, access_if->stats.rate_session_ipv6pd_rx.avg,
            access_if->stats.session_ipv6pd_loss, access_if->stats.session_ipv6pd_wrong_session);
        wprintw(stats_win, "  Rx Multicast Packets      %10lu (%7lu PPS) Loss: %lu\n",
            access_if->stats.mc_rx, access_if->stats.rate_mc_rx.avg,
            access_if->stats.mc_loss);

        /* Protocol stats */
        if(max_y > 68) {
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
        }
        if(max_y > 78) {
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
    wattron(stats_win, COLOR_PAIR(COLOR_GREEN));
    wprintw(stats_win, "F6: Select Interface F7/F8: Start/Stop Traffic F9: Terminate Sessions\n");
    wattroff(stats_win, COLOR_PAIR(COLOR_GREEN));
    wprintw(stats_win, "%s", banner);
    wrefresh(stats_win);

    timer_add_periodic(&ctx->timer_root, &ctx->stats_timer, "Statistics Timer",
		               0, 100 * MSEC, ctx, bbl_stats_job);
    timer_add_periodic(&ctx->timer_root, &ctx->keyboard_timer, "Keyboard Reader",
		               0, 100 * MSEC, ctx, bbl_read_key_job);

    g_interactive = true;
}
