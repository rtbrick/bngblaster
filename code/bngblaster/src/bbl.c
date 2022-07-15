/*
 * BNG BLaster (BBL) - Main File
 *
 * The BNG Blaster is a test tool to simulate thousands
 * of PPPoE or IPoE subscribers including IPTV, L2TPv2,
 * traffic verification and convergence testing capabilities.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_pcap.h"
#include "bbl_interactive.h"
#include "bbl_ctrl.h"
#include "bbl_stream.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"

/* Global Variables */
bool g_interactive = false; /* interactive mode using ncurses */
bool g_init_phase = true;
bool g_traffic = true;
bool g_banner = true;
bool g_monkey = true;

extern char *g_log_file;
volatile bool g_teardown = false;
volatile bool g_teardown_request = false;
volatile uint8_t g_teardown_request_count = 0;

uint16_t g_teardown_countdown = 1;

const char banner[] = "\n"
"      ____   __   ____         _        __                                  ,/\n"
"     / __ \\ / /_ / __ ) _____ (_)_____ / /__                              ,'/\n"
"    / /_/ // __// __  |/ ___// // ___// //_/                            ,' /\n"
"   / _, _// /_ / /_/ // /   / // /__ / ,<                             ,'  /_____,    \n"
"  /_/ |_| \\__//_____//_/   /_/ \\___//_/|_|                          .'____    ,'   \n"
"      ____   _   _  ______   ____   _               _                    /  ,'\n"
"     / __ ) / | / // ____/  / __ ) / /____ _ _____ / /_ ___   ____      / ,'\n"
"    / __  |/  |/ // / __   / __  |/ // __ `// ___// __// _ \\ / ___/    /,'\n"
"   / /_/ // /|  // /_/ /  / /_/ // // /_/ /(__  )/ /_ /  __// /       / \n"
"  /_____//_/ |_/ \\____/  /_____//_/ \\__,_//____/ \\__/ \\___//_/\n\n";


void
teardown_handler(int sig)
{
    LOG(INFO, "Received signal %s (%d), initiating teardown\n", strsignal(sig), sig);
    g_teardown = true;
    g_teardown_request = true;
    g_teardown_request_count++;
}

void
enable_disable_traffic(bbl_ctx_s *ctx, bool status)
{
    bbl_session_s *session;
    uint32_t i;

    g_traffic = status;
    ctx->multicast_traffic = status;

    /* Iterate over all sessions */
    for(i = 0; i < ctx->sessions; i++) {
        session = ctx->session_list[i];
        if(session) {
            session->session_traffic = status;
            session->stream_traffic = status;
        }
    }
}

static bool
bbl_add_multicast_packets(bbl_ctx_s *ctx)
{
    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ip = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};
    uint8_t mac[ETH_ADDR_LEN] = {0};
    uint8_t *buf;

    uint32_t group;
    uint32_t source;

    int i;
    uint16_t len = 0;

    struct bbl_interface_ *interface;

    if(ctx->config.send_multicast_traffic && ctx->config.igmp_group_count) {
        interface = bbl_get_network_interface(ctx, ctx->config.multicast_traffic_network_interface);
        if(!interface) {
            return false;
        }

        interface->mc_packets = malloc(ctx->config.igmp_group_count * 2000);
        buf = interface->mc_packets;

        for(i = 0; i < ctx->config.igmp_group_count; i++) {
            len = 0;
            bbl.flow_id = ctx->flow_id++;

            group = be32toh(ctx->config.igmp_group) + i * be32toh(ctx->config.igmp_group_iter);
            if(ctx->config.igmp_source) {
                source = ctx->config.igmp_source;
            } else {
                source = interface->ip.address;
            }
            group = htobe32(group);
            /* Generate multicast destination MAC */
            ipv4_multicast_mac(group, mac);
            eth.src = interface->mac;
            eth.dst = mac;
            eth.vlan_outer = interface->vlan;
            eth.type = ETH_TYPE_IPV4;
            eth.next = &ip;
            ip.src = source;
            ip.dst = group;
            ip.ttl = 64;
            ip.tos = ctx->config.multicast_traffic_tos;
            ip.protocol = PROTOCOL_IPV4_UDP;
            ip.next = &udp;
            udp.src = BBL_UDP_PORT;
            udp.dst = BBL_UDP_PORT;
            udp.protocol = UDP_PROTOCOL_BBL;
            udp.next = &bbl;
            if(ctx->config.multicast_traffic_len > 76) {
                bbl.padding = ctx->config.multicast_traffic_len - 76;
            }
            bbl.type = BBL_TYPE_MULTICAST;
            bbl.direction = BBL_DIRECTION_DOWN;
            bbl.tos = ctx->config.multicast_traffic_tos;
            bbl.mc_source = ip.src;
            bbl.mc_group = group ;
            if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
                return false;
            }
            buf = buf + len;
        }
        interface->mc_packet_len = len;
    }
    return true;
}

/*
 * Command line options.
 */
const char *optstring = "vhC:T:l:L:u:p:P:j:J:c:g:s:r:z:S:Ibf";
static struct option long_options[] = {
    { "version",                no_argument,        NULL, 'v' },
    { "help",                   no_argument,        NULL, 'h' },
    { "config",                 required_argument,  NULL, 'C' },
    { "stream-config",          required_argument,  NULL, 'T' },
    { "logging",                required_argument,  NULL, 'l' },
    { "log-file",               required_argument,  NULL, 'L' },
    { "username",               required_argument,  NULL, 'u' },
    { "password",               required_argument,  NULL, 'p' },
    { "pcap-capture",           required_argument,  NULL, 'P' },
    { "json-report-content",    required_argument,  NULL, 'j' },
    { "json-report-file",       required_argument,  NULL, 'J' },
    { "session-count",          required_argument,  NULL, 'c' },
    { "mc-group",               required_argument,  NULL, 'g' },
    { "mc-source",              required_argument,  NULL, 's' },
    { "mc-group-count",         required_argument,  NULL, 'r' },
    { "mc-zapping-interval",    required_argument,  NULL, 'z' },
    { "control-socket",         required_argument,  NULL, 'S' },
    { "interactive",            no_argument,        NULL, 'I' },
    { "hide-banner",            no_argument,        NULL, 'b' },
    { "force",                  no_argument,        NULL, 'f' },
    { NULL,                     0,                  NULL,  0 }
};

struct keyval_ log_names[] = {
    { DEBUG,         "debug" },
    { ERROR,         "error" },
    { IGMP,          "igmp" },
    { IO,            "io" },
    { PPPOE,         "pppoe" },
    { INFO,          "info" },
    { PCAP,          "pcap" },
    { TIMER,         "timer" },
    { TIMER_DETAIL,  "timer-detail" },
    { IP,            "ip" },
    { LOSS,          "loss" },
    { L2TP,          "l2tp" },
    { DHCP,          "dhcp" },
    { ISIS,          "isis" },
    { BGP,           "bgp" },
    { TCP,           "tcp" },
    { 0, NULL}
};

static char *
bbl_print_usage_arg (struct option *option)
{
    if (option->has_arg == 1) {
        if (strcmp(option->name, "logging") == 0) {
            return log_usage();
        }
        if (strcmp(option->name, "json-report-content") == 0) {
            return " sessions|streams";
        }
        return " <args>";
    }
    return "";
}

static void
bbl_print_version (void)
{
    if(sizeof(BNGBLASTER_VERSION)-1) {
        printf("Version: %s\n", BNGBLASTER_VERSION);
    } else {
        printf("Version: DEV\n");
    }
    if(sizeof(COMPILER_ID)-1 + sizeof(COMPILER_VERSION)-1) {
        printf("Compiler: %s (%s)\n", COMPILER_ID, COMPILER_VERSION);
    }
    if(sizeof(GIT_REF)-1 + sizeof(GIT_SHA)-1) {
        printf("GIT:\n");
        printf("  REF: %s\n", GIT_REF);
        printf("  SHA: %s\n", GIT_SHA);
    }
    printf("IO Modes: packet_mmap_raw (default), packet_mmap, raw");
#ifdef BNGBLASTER_NETMAP
    printf(", netmap");
#endif
    printf("\n");
}

static void
bbl_print_usage (void)
{
    int idx;
    printf("%s", banner);
    printf("Usage: bngblaster [OPTIONS]\n\n");
    for (idx = 0; ; idx++) {
        if (long_options[idx].name == NULL) {
            break;
        }
        printf("  -%c --%s%s\n", long_options[idx].val, long_options[idx].name,
               bbl_print_usage_arg(&long_options[idx]));
    }
}

void
bbl_smear_job (timer_s *timer)
{
    bbl_ctx_s *ctx = timer->data;

    /* LCP Keepalive Interval */
    if(ctx->config.lcp_keepalive_interval) {
        timer_smear_bucket(&ctx->timer_root, ctx->config.lcp_keepalive_interval, 0);
    }
    if(ctx->config.lcp_keepalive_interval != 5) {
        /* Default Retry Interval */
        timer_smear_bucket(&ctx->timer_root, 5, 0);
    }
}

void
bbl_ctrl_job (timer_s *timer)
{
    bbl_ctx_s *ctx = timer->data;
    bbl_session_s *session;
    bbl_interface_s *interface;
    int rate = 0;
    uint32_t i;

    struct timespec timestamp;
    struct timespec time_diff;

    /* Setup phase ...
     * Wait for all network interfaces to be resolved. */
    if(g_init_phase && !g_teardown) {
        LOG_NOARG(INFO, "Resolve network interfaces\n");
        for(i = 0; i < ctx->interfaces.network_if_count; i++) {
            interface = ctx->interfaces.network_if[i];
            if(interface->gateway_resolve_wait == false) {
                continue;
            }
            if(ipv6_addr_not_zero(&interface->gateway6) && !interface->icmpv6_nd_resolved) {
                LOG(DEBUG, "Wait for %s IPv6 gateway %s to be resolved\n",
                    interface->name, format_ipv6_address(&interface->gateway6));
                return;
            }
            if(interface->gateway && !interface->arp_resolved) {
                LOG(DEBUG, "Wait for %s IPv4 gateway %s to be resolved\n",
                    interface->name, format_ipv4_address(&interface->gateway));
                return;
            }
        }
        g_init_phase = false;
        LOG_NOARG(INFO, "All network interfaces resolved\n");
        clock_gettime(CLOCK_MONOTONIC, &ctx->timestamp_resolved);
    }

    if(ctx->sessions_outstanding) ctx->sessions_outstanding--;

    if(g_teardown) {
        if(g_teardown_countdown) g_teardown_countdown--;
        if(ctx->l2tp_tunnels && ctx->sessions_terminated >= ctx->sessions) {
            bbl_l2tp_stop_all_tunnel(ctx);
        }
        /* Teardown phase ... */
        if(g_teardown_request) {
            /* Put all sessions on the teardown list. */
            for(i = 0; i < ctx->sessions; i++) {
                session = ctx->session_list[i];
                if(session) {
                    if(!CIRCLEQ_NEXT(session, session_teardown_qnode)) {
                        /* Add only if not already on teardown list. */
                        CIRCLEQ_INSERT_TAIL(&ctx->sessions_teardown_qhead, session, session_teardown_qnode);
                    }
                }
            }
            /* Teardown routing protocols. */
            isis_teardown(ctx);
            bgp_teardown(ctx);
            g_teardown_request = false;
        } else {
            /* Process teardown list in chunks. */
            rate = ctx->config.sessions_stop_rate;
            while (!CIRCLEQ_EMPTY(&ctx->sessions_teardown_qhead)) {
                session = CIRCLEQ_FIRST(&ctx->sessions_teardown_qhead);
                if(rate > 0) {
                    if(session->session_state != BBL_IDLE) rate--;
                    bbl_session_clear(ctx, session);
                    /* Remove from teardown queue. */
                    CIRCLEQ_REMOVE(&ctx->sessions_teardown_qhead, session, session_teardown_qnode);
                    CIRCLEQ_NEXT(session, session_teardown_qnode) = NULL;
                    CIRCLEQ_PREV(session, session_teardown_qnode) = NULL;
                } else {
                    break;
                }
            }
        }
    } else {
        /* Wait N seconds (default 0) before we start to setup sessions. */
        if(ctx->config.sessions_start_delay) {
            clock_gettime(CLOCK_MONOTONIC, &timestamp);
            timespec_sub(&time_diff, &timestamp, &ctx->timestamp_resolved);
            if(time_diff.tv_sec < ctx->config.sessions_start_delay) {
                return;
            }
        }
        /* Iterate over all idle session (list of pending sessions)
         * and start as much as permitted per interval based on max
         * outstanding and setup rate. Sessions started will be removed
         * from idle list. */
        bbl_stats_update_cps(ctx);
        rate = ctx->config.sessions_start_rate;
        while (!CIRCLEQ_EMPTY(&ctx->sessions_idle_qhead)) {
            session = CIRCLEQ_FIRST(&ctx->sessions_idle_qhead);
            if(rate > 0) {
                if(ctx->sessions_outstanding < ctx->config.sessions_max_outstanding) {
                    ctx->sessions_outstanding++;
                    /* Start session */
                    switch (session->access_type) {
                        case ACCESS_TYPE_PPPOE:
                            /* PPP over Ethernet (PPPoE) */
                            session->session_state = BBL_PPPOE_INIT;
                            session->send_requests = BBL_SEND_DISCOVERY;
                            break;
                        case ACCESS_TYPE_IPOE:
                            /* IP over Ethernet (IPoE) */
                            session->session_state = BBL_IPOE_SETUP;
                            session->send_requests = 0;
                            if(session->access_config->ipv4_enable) {
                                if(session->access_config->dhcp_enable) {
                                    /* Start IPoE session by sending DHCP discovery if enabled. */
                                    bbl_dhcp_start(session);
                                } else if (session->ip_address && session->peer_ip_address) {
                                    /* Start IPoE session by sending ARP request if local and
                                     * remote IP addresses are already provided. */
                                    session->send_requests |= BBL_SEND_ARP_REQUEST;
                                }
                            }
                            if(session->access_config->ipv6_enable) {
                                if(session->access_config->dhcpv6_enable) {
                                    /* Start IPoE session by sending DHCPv6 request if enabled. */
                                    bbl_dhcpv6_start(session);
                                } else {
                                    /* Start IPoE session by sending RS. */
                                    session->send_requests |= BBL_SEND_ICMPV6_RS;
                                }
                            }
                            break;
                    }
                    bbl_session_tx_qnode_insert(session);
                    /* Remove from idle queue */
                    CIRCLEQ_REMOVE(&ctx->sessions_idle_qhead, session, session_idle_qnode);
                    CIRCLEQ_NEXT(session, session_idle_qnode) = NULL;
                    CIRCLEQ_PREV(session, session_idle_qnode) = NULL;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
}

/**
 * @brief BNG BLASTER MAIN FUNCTION
 *
 * @param argc number of argument values
 * @param argv argument values
 * @return int return code
 */
int
main(int argc, char *argv[])
{
    bbl_ctx_s *ctx = NULL;
    int long_index = 0;
    int ch = 0;
    uint32_t ipv4;
    bbl_stats_t stats = {0};
    int exit_status = 1;

    const char *config_file = NULL;
    const char *config_streams_file = NULL;
    const char *username = NULL;
    const char *password = NULL;
    const char *sessions = NULL;
    const char *igmp_group = NULL;
    const char *igmp_source = NULL;
    const char *igmp_group_count = NULL;
    const char *igmp_zap_interval = NULL;
    bool  interactive = false;

    ctx = bbl_ctx_add();
    if (!ctx) {
        exit(2);
    }

    /* Clear logging global array. */
    memset(log_id, 0, sizeof(struct log_id_) * LOG_ID_MAX);
    log_id[INFO].enable = true;
    log_id[ERROR].enable = true;

    /* Seed pseudo random generator. */
    srand(time(0));

    /* Process config options. */
    while (true) {
        ch = getopt_long(argc, argv, optstring, long_options, &long_index);
        if (ch == -1) {
            break;
        }
        switch (ch) {
            case 'v':
                bbl_print_version();
                exit(0);
            case 'h':
                bbl_print_usage();
                exit(0);
            case 'P':
                ctx->pcap.filename = optarg;
                break;
            case 'j':
                if (strcmp("sessions", optarg) == 0) {
                    ctx->config.json_report_sessions = true;
                } else if (strcmp("streams", optarg) == 0) {
                    ctx->config.json_report_streams = true;
                }
                break;
            case 'J':
                ctx->config.json_report_filename = optarg;
                break;
            case 'C':
                config_file = optarg;
                break;
            case 'T':
                config_streams_file = optarg;
                break;
            case 'l':
                log_enable(optarg);
                break;
            case 'L':
                g_log_file = optarg;
                break;
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'c':
                sessions = optarg;
                break;
            case 'g':
                igmp_group = optarg;
                break;
            case 's':
                igmp_source = optarg;
                break;
            case 'r':
                igmp_group_count = optarg;
                break;
            case 'z':
                igmp_zap_interval = optarg;
                break;
            case 'I':
                interactive = true;
                break;
            case 'S':
                ctx->ctrl_socket_path = optarg;
                break;
            case 'f':
                ctx->config.interface_lock_force = true;
                break;
            case 'b':
                g_banner = false;
                break;
            default:
                bbl_print_usage();
                goto CLEANUP;
        }
    }

    if(!config_file) {
        fprintf(stderr, "Error: No configuration specified (-C / --config <file>)\n");
        goto CLEANUP;
    }

#if 0
    timer_test(ctx);
    exit(0);
#endif

    /* Init config. */
    bbl_config_init_defaults(ctx);
    if(!bbl_config_load_json(config_file, ctx)) {
        fprintf(stderr, "Error: Failed to load configuration file %s\n", config_file);
        goto CLEANUP;
    }
    if(config_streams_file) {
        if(!bbl_config_streams_load_json(config_streams_file, ctx)) {
            fprintf(stderr, "Error: Failed to load stream configuration file %s\n", config_streams_file);
            goto CLEANUP;
        }
    }
    g_monkey = ctx->config.monkey_autostart;

    if(username) ctx->config.username = username;
    if(password) ctx->config.password = password;
    if(sessions) ctx->config.sessions = atoi(sessions);
    if(igmp_group) {
        inet_pton(AF_INET, igmp_group, &ipv4);
        ctx->config.igmp_group = ipv4;
    }
    if(igmp_source) {
        inet_pton(AF_INET, igmp_source, &ipv4);
        ctx->config.igmp_source = ipv4;
    }
    if(igmp_group_count) ctx->config.igmp_group_count = atoi(igmp_group_count);
    if(igmp_zap_interval) ctx->config.igmp_zap_interval = atoi(igmp_zap_interval);

    /* Init IS-IS instances. */
    if(!isis_init(ctx)) {
        fprintf(stderr, "Error: Failed to init IS-IS\n");
        goto CLEANUP;
    }

    /* Add interfaces. */
    if(!bbl_add_interfaces(ctx)) {
        fprintf(stderr, "Error: Failed to add interfaces\n");
        goto CLEANUP;
    }

    /* Init TCP. */
    bbl_tcp_init(ctx);

    /* Init BGP sessions. */
    if(!bgp_init(ctx)) {
        fprintf(stderr, "Error: Failed to init BGP\n");
        goto CLEANUP;
    }

    /* Start curses. */
    if (interactive) {
        bbl_init_curses(ctx);
    }

    /* Add traffic. */
    if(!bbl_add_multicast_packets(ctx)) {
        if (interactive) endwin();
        fprintf(stderr, "Error: Failed to add multicast traffic\n");
        goto CLEANUP;
    }
    if(!bbl_stream_raw_add(ctx)) {
        if (interactive) endwin();
        fprintf(stderr, "Error: Failed to add RAW stream traffic\n");
        goto CLEANUP;
    }

    /* Setup resources in case PCAP dumping is desired. */
    pcapng_init(ctx);

    /* Setup test. */
    if(ctx->interfaces.access_if_count) {
        if(!bbl_sessions_init(ctx)) {
            if (interactive) endwin();
            fprintf(stderr, "Error: Failed to init sessions\n");
            goto CLEANUP;
        }
    }

    /* Setup control job. */
    timer_add_periodic(&ctx->timer_root, &ctx->control_timer, "Control Timer", 1, 0, ctx, &bbl_ctrl_job);

    /* Setup control socket and job */
    if(ctx->ctrl_socket_path) {
        if(!bbl_ctrl_socket_open(ctx)) {
            if (interactive) endwin();
            goto CLEANUP;
        }
    }

    /* Start smear job. Use a crazy nsec bucket '12345678',
     * such that we do not accidentally smear ourselves. */
    timer_add_periodic(&ctx->timer_root, &ctx->smear_timer, "Timer Smearing", 45, 12345678, ctx, &bbl_smear_job);

    /* Smear all buckets. */
    timer_smear_all_buckets(&ctx->timer_root);

    /* Prevent traffic from autostart. */
    if(ctx->config.traffic_autostart == false) {
        enable_disable_traffic(ctx, false);
    }

    /* Start threads. */
    bbl_stream_start_threads(ctx);

    /* Start event loop. */
    log_open();
    clock_gettime(CLOCK_MONOTONIC, &ctx->timestamp_start);
    signal(SIGINT, teardown_handler);
    while(g_teardown_request_count < 10) {
        if(!(ctx->l2tp_tunnels || ctx->routing_sessions)) {
            if(ctx->sessions) {
                /* With sessions, wait for all sessions
                 * to be terminated. */
                if(ctx->sessions_terminated >= ctx->sessions && ctx->l2tp_tunnels == 0) {
                    break;
                }
            } else {
                /* Without sessions, we can stop immediately
                 * as soon as teardown was requested. */
                if(g_teardown) {
                    break;
                }
            }
        }
        timer_walk(&ctx->timer_root);
    }
    clock_gettime(CLOCK_MONOTONIC, &ctx->timestamp_stop);

    /* Stop threads. */
    bbl_stream_stop_threads(ctx);

    /* Stop curses. Do this before the final reports. */
    if(g_interactive) {
        endwin();
        g_interactive = false;
    }

    /* Generate reports. */
    bbl_stats_generate(ctx, &stats);
    bbl_stats_stdout(ctx, &stats);
    bbl_stats_json(ctx, &stats);
    exit_status = 0;

    /* Cleanup resources. */
CLEANUP:
    bbl_interface_unlock_all(ctx);
    log_close();
    if(ctx->ctrl_socket_path) {
        bbl_ctrl_socket_close(ctx);
    }
    bbl_ctx_del(ctx);
    ctx = NULL;
    return exit_status;
}
