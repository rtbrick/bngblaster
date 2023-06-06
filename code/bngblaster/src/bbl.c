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
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_pcap.h"
#include "bbl_interactive.h"
#include "bbl_ctrl.h"
#include "bbl_stream.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"

/* Global Context */
bbl_ctx_s *g_ctx = NULL;

/* Global Variables */
bool g_interactive = false; /* interactive mode using ncurses */
bool g_init_phase = true;
bool g_traffic = true;
bool g_banner = true;
bool g_monkey = true;

uint8_t g_log_buf_cur = 0;
char *g_log_buf = NULL;

extern char *g_log_file;
volatile bool g_teardown = false;
volatile bool g_teardown_request = false;
volatile uint8_t g_teardown_request_count = 0;

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

const char*
test_state()
{
    if(g_teardown) {
        return "teardown";
    } else if(g_init_phase) {
        return "init";
    } else {
        return "active";
    }
}

time_t
test_duration()
{
    struct timespec now;
    struct timespec time_diff = {0};
    if(g_ctx) {
        if(g_ctx->timestamp_stop.tv_sec) {
            timespec_sub(&time_diff, 
                         &g_ctx->timestamp_stop, 
                         &g_ctx->timestamp_start);
        } else {
            clock_gettime(CLOCK_MONOTONIC, &now);
            timespec_sub(&time_diff, &now, 
                         &g_ctx->timestamp_start);
        }
    }
    return time_diff.tv_sec;
}

void
enable_disable_traffic(bool status)
{
    bbl_session_s *session;
    uint32_t i;

    g_traffic = status;

    /* Iterate over all sessions */
    for(i = 0; i < g_ctx->sessions; i++) {
        session = &g_ctx->session_list[i];
        if(session) {
            session->session_traffic.active = status;
            session->streams.active = status;
        }
    }
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
    { IP,            "ip" },
    { LOSS,          "loss" },
    { L2TP,          "l2tp" },
    { DHCP,          "dhcp" },
    { ISIS,          "isis" },
    { LDP,           "ldp" },
    { BGP,           "bgp" },
    { TCP,           "tcp" },
    { LAG,           "lag" },
    { DPDK,          "dpdk" },
    { PACKET,        "packet" },
    { HTTP,          "http" },
#ifdef BNGBLASTER_TIMER_LOGGING
    { TIMER,         "timer" },
    { TIMER_DETAIL,  "timer-detail" },
#endif
    { 0, NULL}
};

static char *
bbl_print_usage_arg(struct option *option)
{
    if(option->has_arg == 1) {
        if(strcmp(option->name, "logging") == 0) {
            return log_usage();
        }
        if(strcmp(option->name, "json-report-content") == 0) {
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
#ifdef BNGBLASTER_DPDK
    printf(", dpdk");
#endif
    printf("\n");
}

static void
bbl_print_usage(void)
{
    int idx;
    printf("%s", banner);
    printf("Usage: bngblaster [OPTIONS]\n\n");
     for(idx = 0; ; idx++) {
        if(long_options[idx].name == NULL) {
            break;
        }
        printf("  -%c --%s%s\n", long_options[idx].val, long_options[idx].name,
               bbl_print_usage_arg(&long_options[idx]));
    }
}

void
bbl_smear_job(timer_s *timer)
{
    UNUSED(timer);
    /* LCP Keepalive Interval */
    if(g_ctx->config.lcp_keepalive_interval) {
        /* Adding 1 nanoseconds to enforce a dedicated timer bucket. */
        timer_smear_bucket(&g_ctx->timer_root, g_ctx->config.lcp_keepalive_interval, 1);
    }
}

void
bbl_ctrl_job(timer_s *timer)
{
    UNUSED(timer);
    bbl_session_s *session;
    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;

    int rate = 0;
    uint32_t i;

    struct timespec timestamp;
    struct timespec time_diff;

    /* Setup phase ...
     * Wait for all network interfaces to be resolved. */
    if(g_init_phase && !g_teardown) {
        LOG_NOARG(INFO, "Resolve network interfaces\n");
        CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
            network_interface = interface->network;
            while(network_interface) {
                if(network_interface->gateway_resolve_wait) {
                    if(ipv6_addr_not_zero(&network_interface->gateway6) && !network_interface->icmpv6_nd_resolved) {
                        LOG(DEBUG, "Wait for %s IPv6 gateway %s to be resolved\n",
                            network_interface->name, format_ipv6_address(&network_interface->gateway6));
                        return;
                    }
                    if(network_interface->gateway && !network_interface->arp_resolved) {
                        LOG(DEBUG, "Wait for %s IPv4 gateway %s to be resolved\n",
                            network_interface->name, format_ipv4_address(&network_interface->gateway));
                        return;
                    }
                }
                network_interface = network_interface->next;
            }
        }
        g_init_phase = false;
        LOG_NOARG(INFO, "All network interfaces resolved\n");
        clock_gettime(CLOCK_MONOTONIC, &g_ctx->timestamp_resolved);
    }

    if(g_teardown) {
        if(g_ctx->l2tp_tunnels && g_ctx->sessions_terminated >= g_ctx->sessions) {
            bbl_l2tp_stop_all_tunnel();
        }
        /* Teardown phase ... */
        if(g_teardown_request) {
            /* Put all sessions on the teardown list. */
            for(i = 0; i < g_ctx->sessions; i++) {
                session = &g_ctx->session_list[i];
                if(session) {
                    if(!CIRCLEQ_NEXT(session, session_teardown_qnode)) {
                        /* Add only if not already on teardown list. */
                        CIRCLEQ_INSERT_TAIL(&g_ctx->sessions_teardown_qhead, session, session_teardown_qnode);
                    }
                }
            }
            /* Teardown routing protocols. */
            isis_teardown();
            ldp_teardown();
            bgp_teardown();
            g_teardown_request = false;
        } else {
            /* Process teardown list in chunks. */
            rate = g_ctx->config.sessions_stop_rate;
            while(!CIRCLEQ_EMPTY(&g_ctx->sessions_teardown_qhead)) {
                session = CIRCLEQ_FIRST(&g_ctx->sessions_teardown_qhead);
                if(rate > 0) {
                    if(session->session_state != BBL_IDLE) rate--;
                    bbl_session_clear(session);
                    /* Remove from teardown queue. */
                    CIRCLEQ_REMOVE(&g_ctx->sessions_teardown_qhead, session, session_teardown_qnode);
                    CIRCLEQ_NEXT(session, session_teardown_qnode) = NULL;
                    CIRCLEQ_PREV(session, session_teardown_qnode) = NULL;
                } else {
                    break;
                }
            }
        }
    } else {
        /* Wait N seconds (default 0) before we start to setup sessions. */
        if(g_ctx->config.sessions_start_delay) {
            clock_gettime(CLOCK_MONOTONIC, &timestamp);
            timespec_sub(&time_diff, &timestamp, &g_ctx->timestamp_resolved);
            if(time_diff.tv_sec < g_ctx->config.sessions_start_delay) {
                return;
            }
        }
        /* Iterate over all idle session (list of pending sessions)
         * and start as much as permitted per interval based on max
         * outstanding and setup rate. Sessions started will be removed
         * from idle list. */
        bbl_stats_update_cps();
        rate = g_ctx->config.sessions_start_rate;
        while(!CIRCLEQ_EMPTY(&g_ctx->sessions_idle_qhead)) {
            session = CIRCLEQ_FIRST(&g_ctx->sessions_idle_qhead);
            if(rate > 0) {
                if(g_ctx->sessions_outstanding < g_ctx->config.sessions_max_outstanding) {
                    g_ctx->sessions_outstanding++;
                    /* Start session */
                    if(session->cfm_cc) {
                        bbl_cfm_cc_start(session);
                    }
                    switch(session->access_type) {
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
                                if(session->dhcp_state > BBL_DHCP_DISABLED) {
                                    /* Start IPoE session by sending DHCP discovery if enabled. */
                                    bbl_dhcp_start(session);
                                } else if(session->ip_address && session->peer_ip_address) {
                                    /* Start IPoE session by sending ARP request if local and
                                     * remote IP addresses are already provided. */
                                    session->send_requests |= BBL_SEND_ARP_REQUEST;
                                }
                            }
                            if(session->access_config->ipv6_enable) {
                                if(session->dhcpv6_state > BBL_DHCP_DISABLED) {
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
                    CIRCLEQ_REMOVE(&g_ctx->sessions_idle_qhead, session, session_idle_qnode);
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
    int long_index = 0;
    int ch = 0;
    uint32_t ipv4;
    bbl_stats_s stats = {0};
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

    if(!bbl_ctx_add()) {
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
        if(ch == -1) {
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
                g_ctx->pcap.filename = optarg;
                break;
            case 'j':
                if(strcmp("sessions", optarg) == 0) {
                    g_ctx->config.json_report_sessions = true;
                } else if(strcmp("streams", optarg) == 0) {
                    g_ctx->config.json_report_streams = true;
                }
                break;
            case 'J':
                g_ctx->config.json_report_filename = optarg;
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
                bbl_interactive_log_buf_init();
                break;
            case 'S':
                g_ctx->ctrl_socket_path = optarg;
                break;
            case 'f':
                g_ctx->config.interface_lock_force = true;
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

    /* Open logfile. */
    log_open();

    /* Init config. */
    bbl_config_init_defaults();
    if(!bbl_config_load_json(config_file)) {
        fprintf(stderr, "Error: Failed to load configuration file %s\n", config_file);
        goto CLEANUP;
    }
    if(config_streams_file) {
        if(!bbl_config_streams_load_json(config_streams_file)) {
            fprintf(stderr, "Error: Failed to load stream configuration file %s\n", config_streams_file);
            goto CLEANUP;
        }
    }
    g_monkey = g_ctx->config.monkey_autostart;

    if(username) g_ctx->config.username = username;
    if(password) g_ctx->config.password = password;
    if(sessions) g_ctx->config.sessions = atoi(sessions);
    if(igmp_group) {
        inet_pton(AF_INET, igmp_group, &ipv4);
        g_ctx->config.igmp_group = ipv4;
    }
    if(igmp_source) {
        inet_pton(AF_INET, igmp_source, &ipv4);
        g_ctx->config.igmp_source = ipv4;
    }
    if(igmp_group_count) g_ctx->config.igmp_group_count = atoi(igmp_group_count);
    if(igmp_zap_interval) g_ctx->config.igmp_zap_interval = atoi(igmp_zap_interval);

#ifdef BNGBLASTER_DPDK
    /* Init DPDK. */
    if(!io_dpdk_init()) {
        fprintf(stderr, "Error: Failed to init DPDK\n");
        goto CLEANUP;
    }
#endif

    /* Init IS-IS instances. */
    if(!isis_init()) {
        fprintf(stderr, "Error: Failed to init IS-IS\n");
        goto CLEANUP;
    }

    /* Init LDP instances. */
    if(!ldp_init()) {
        fprintf(stderr, "Error: Failed to init LDP\n");
        goto CLEANUP;
    }

    /* Init interfaces. */
    if(!bbl_interface_init()) {
        fprintf(stderr, "Error: Failed to init interfaces\n");
        goto CLEANUP;
    }

    /* Init TCP. */
    bbl_tcp_init();

    /* Init BGP sessions. */
    if(!bgp_init()) {
        fprintf(stderr, "Error: Failed to init BGP\n");
        goto CLEANUP;
    }

    /* Init streams. */
    if(!bbl_stream_init()) {
        fprintf(stderr, "Error: Failed to add RAW stream traffic\n");
        goto CLEANUP;
    }

    /* Setup resources in case PCAP dumping is desired. */
    pcapng_init();

    /* Setup test. */
    if(bbl_access_interface_get(NULL)) {
        if(!bbl_sessions_init()) {
            fprintf(stderr, "Error: Failed to init sessions\n");
            goto CLEANUP;
        }
    }

    /* Setup control job. */
    timer_add_periodic(&g_ctx->timer_root, &g_ctx->control_timer, "Control Timer", 
                       1, 0, g_ctx, &bbl_ctrl_job);

    /* Setup control socket and job */
    if(g_ctx->ctrl_socket_path) {
        if(!bbl_ctrl_socket_init()) {
            goto CLEANUP;
        }
    }

    /* Init IO stream token buckets. */
    io_init_stream_token_bucket();

    /* Start smear job. Use a crazy nsec bucket '12345678',
     * such that we do not accidentally smear ourselves. */
    timer_add_periodic(&g_ctx->timer_root, &g_ctx->smear_timer, "Timer Smearing", 
                       45, 12345678, g_ctx, &bbl_smear_job);
    timer_no_smear(g_ctx->smear_timer);

    /* Prevent traffic from autostart. */
    if(g_ctx->config.multicast_traffic_autostart == false) {
        g_ctx->multicast_endpoint = ENDPOINT_ENABLED;
    }
    if(g_ctx->config.traffic_autostart == false) {
        enable_disable_traffic(false);
    }

    /* Start threads. */
    io_thread_start_all();

    /* Smear all buckets. */
    timer_smear_all_buckets(&g_ctx->timer_root);

    /* Start curses. */
    if(interactive) {
        bbl_interactive_init();
        bbl_interactive_start();
    }

    signal(SIGINT, teardown_handler);

    /* Start event loop ... */
    clock_gettime(CLOCK_MONOTONIC, &g_ctx->timestamp_start);
    while(g_teardown_request_count < 10) {
        if(g_teardown) {
            /* If teardown has requested, wait for all L2TP 
             * tunnels and routing sessions to be terminated. */
            if(g_ctx->l2tp_tunnels == 0 && g_ctx->routing_sessions == 0) {
                if(g_ctx->sessions) {
                    /* With sessions, wait for all sessions
                     * to be terminated. */
                    if(g_ctx->sessions_terminated >= g_ctx->sessions) {
                        break;
                    }
                } else {
                    /* Without sessions, we can stop immediately
                     * as soon as teardown was requested. */
                    break;
                }
            }
        }
        /* Continue with event loop ... */
        timer_walk(&g_ctx->timer_root);
    }
    clock_gettime(CLOCK_MONOTONIC, &g_ctx->timestamp_stop);

    /* Stop threads. */
    io_thread_stop_all();

    /* Stop curses. Do this before the final reports. */
    if(g_interactive) {
        endwin();
        g_interactive = false;
    }

    /* Generate reports. */
    bbl_stream_final();
    bbl_stats_generate(&stats);
    bbl_stats_stdout(&stats);
    bbl_stats_json(&stats);
    exit_status = 0;

    /* Cleanup resources. */
CLEANUP:
    bbl_interface_unlock_all();
    if(g_ctx->ctrl_socket_path) {
        bbl_ctrl_socket_close();
    }
    log_close();
    bbl_ctx_del();
    return exit_status;
}
