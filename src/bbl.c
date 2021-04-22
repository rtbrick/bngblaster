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
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_ctx.h"
#include "bbl_config.h"
#include "bbl_session.h"
#include "bbl_pcap.h"
#include "bbl_stats.h"
#include "bbl_interactive.h"
#include "bbl_ctrl.h"
#include "bbl_logging.h"
#include "bbl_io.h"
#include <sys/stat.h>

/* Global Variables */
bool g_interactive = false; // interactive mode using ncurses
char *g_log_file = NULL;

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
teardown_handler (int sig)
{
    LOG(NORMAL, "Received signal %s (%d), initiating teardown\n", strsignal(sig), sig);
    g_teardown = true;
    g_teardown_request = true;
    g_teardown_request_count++;
}

void
bbl_session_tx_qnode_insert (bbl_session_s *session)
{
    bbl_interface_s *interface = session->interface;
    if(CIRCLEQ_NEXT(session, session_tx_qnode)) {
        return;
    }
    CIRCLEQ_INSERT_TAIL(&interface->session_tx_qhead, session, session_tx_qnode);
}

void
bbl_session_tx_qnode_remove (bbl_session_s *session)
{
    bbl_interface_s *interface = session->interface;
    CIRCLEQ_REMOVE(&interface->session_tx_qhead, session, session_tx_qnode);
    CIRCLEQ_NEXT(session, session_tx_qnode) = NULL;
    CIRCLEQ_PREV(session, session_tx_qnode) = NULL;
}

void
bbl_session_network_tx_qnode_insert (bbl_session_s *session)
{
    bbl_interface_s *interface = session->interface->ctx->op.network_if;
    if(CIRCLEQ_NEXT(session, session_network_tx_qnode)) {
        return;
    }
    if(interface) {
        CIRCLEQ_INSERT_TAIL(&interface->session_tx_qhead, session, session_network_tx_qnode);
    }
}

void
bbl_session_network_tx_qnode_remove (bbl_session_s *session)
{
    bbl_interface_s *interface = session->interface->ctx->op.network_if;
    if(interface) {
        CIRCLEQ_REMOVE(&interface->session_tx_qhead, session, session_network_tx_qnode);
        CIRCLEQ_NEXT(session, session_network_tx_qnode) = NULL;
        CIRCLEQ_PREV(session, session_network_tx_qnode) = NULL;
    }
}

bool
bbl_add_multicast_packets (bbl_ctx_s *ctx, bbl_interface_s *interface)
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

    if(ctx->config.send_multicast_traffic && ctx->config.igmp_group_count) {
        interface->mc_packets = malloc(ctx->config.igmp_group_count * 2000);
        buf = interface->mc_packets;

        for(i = 0; i < ctx->config.igmp_group_count; i++) {
            len = 0;
            bbl.flow_id = ctx->flow_id++;

            group = be32toh(ctx->config.igmp_group) + i * be32toh(ctx->config.igmp_group_iter);
            if(ctx->config.igmp_source) {
                source = ctx->config.igmp_source;
            } else {
                source = interface->ip;
            }
            group = htobe32(group);
            /* Generate multicast destination MAC */
            *(uint32_t*)(&mac[2]) = group;
            mac[0] = 0x01;
            mac[2] = 0x5e;
            mac[3] &= 0x7f;
            eth.src = interface->mac;
            eth.dst = mac;
            eth.vlan_outer = ctx->config.network_vlan;
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
    }
    interface->mc_packet_len = len;
    return true;
}

bool
bbl_interface_lock(bbl_ctx_s *ctx, char *interface_name) {

    FILE *lock_file;
    char  lock_path[128];
    int   lock_pid;
    char  proc_pid_path[32];

    struct stat sts;
    pid_t pid = getpid();

    snprintf(lock_path, 128, "/tmp/bngblaster_%s.lock", interface_name);
    lock_file = fopen(lock_path, "r");
    if(lock_file) {
        // lock file exists
        if(fscanf(lock_file,"%d", &lock_pid) == 1 && lock_pid > 1) {
            snprintf(proc_pid_path, 32, "/proc/%d", lock_pid);
            if (!(stat(proc_pid_path, &sts) == -1 && errno == ENOENT)) {
                LOG(ERROR, "Interface %s in use by process %d (%s)\n", interface_name, lock_pid, lock_path);
                if(!ctx->config.interface_lock_force) return false;
            }
        } else {
            LOG(ERROR, "Invalid interface lock file %s\n", lock_path);
            if(!ctx->config.interface_lock_force) return false;
        }
        fclose(lock_file);
    }
    /* crate lock file */
    lock_pid = pid;
    lock_file = fopen(lock_path, "w");
    if(!lock_file) {
        LOG(ERROR, "Failed to open interface lock file %s\n", lock_path);
        return false;
    }
    fprintf(lock_file, "%d", lock_pid);
    fclose(lock_file);
    return true;
}

void
bbl_interface_unlock_all(bbl_ctx_s *ctx) {
    char  lock_path[128];
    bbl_interface_s *interface;
    int i;

    if(ctx->op.network_if) {
        interface = ctx->op.network_if;
        snprintf(lock_path, 128, "/tmp/bngblaster_%s.lock", interface->name);
        remove(lock_path);
    }
    for(i = 0; i < ctx->op.access_if_count; i++) {
        interface = ctx->op.access_if[i];
        if(interface) {
            snprintf(lock_path, 128, "/tmp/bngblaster_%s.lock", interface->name);
            remove(lock_path);
        }
    }
}

/** 
 * bbl_add_interface 
 *
 * @param ctx global context
 * @param interface interface.
 */
bbl_interface_s *
bbl_add_interface (bbl_ctx_s *ctx, char *interface_name)
{
    bbl_interface_s *interface;
    struct ifreq ifr;

    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if(!bbl_interface_lock(ctx, interface_name)) {
        return NULL;
    }

    interface = calloc(1, sizeof(bbl_interface_s));
    if (!interface) {
        LOG(ERROR, "No memory for interface %s\n", interface_name);
        return NULL;
    }

    interface->name = strdup(interface_name);
    interface->ctx = ctx;
    CIRCLEQ_INSERT_TAIL(&ctx->interface_qhead, interface, interface_qnode);

    interface->pcap_index = ctx->pcap.index;
    ctx->pcap.index++;

    /*
     * List for sessions who want to transmit.
     */
    CIRCLEQ_INIT(&interface->session_tx_qhead);
    CIRCLEQ_INIT(&interface->l2tp_tx_qhead);

    /*
     * Obtain the interface MAC address.
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface_name);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        LOG(ERROR, "Getting MAC address error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        return NULL;
    }
    memcpy(&interface->mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);

    /*
     * Obtain the interface index.
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        LOG(ERROR, "Get interface index error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        return NULL;
    }
    interface->ifindex = ifr.ifr_ifindex;

    /* The BNG Blaster supports multiple IO modes where packet_mmap is
     * selected per default. */
    if(!bbl_io_add_interface(ctx, interface)) {
        LOG(ERROR, "Failed to add interface %s\n", interface->name);
        return NULL;     
    }

    /*
     * Timer to compute periodic rates.
     */
    timer_add_periodic(&ctx->timer_root, &interface->rate_job, "Rate Computation", 1, 0, interface,
		               &bbl_compute_interface_rate_job);

    return interface;
}

/** 
 * bbl_add_access_interfaces 
 *
 * @param ctx global context
 */
bool
bbl_add_access_interfaces (bbl_ctx_s *ctx) {
    bbl_access_config_s *access_config = ctx->config.access_config;
    struct bbl_interface_ *access_if;
    int i;

    while(access_config) {
        for(i = 0; i < ctx->op.access_if_count; i++) {
            if(ctx->op.access_if[i]->name) {
                if (strcmp(ctx->op.access_if[i]->name, access_config->interface) == 0) {
                    /* Interface already added! */
                    access_config->access_if = ctx->op.access_if[i];
                    goto NEXT;
                }
            }
        }
        access_if = bbl_add_interface(ctx, access_config->interface);
        if (!access_if) {
            LOG(ERROR, "Failed to add access interface %s\n", access_config->interface);
            return false;
        }
        access_if->access = true;
        access_config->access_if = access_if;
        ctx->op.access_if[ctx->op.access_if_count++] = access_if;
NEXT:
        access_config = access_config->next;
    }
    return true;
}

/*
 * Command line options.
 */
const char *optstring = "vhC:l:L:u:p:P:J:c:g:s:r:z:S:If";
static struct option long_options[] = {
    { "version",                no_argument,        NULL, 'v' },
    { "help",                   no_argument,        NULL, 'h' },
    { "config",                 required_argument,  NULL, 'C' },
    { "logging",                required_argument,  NULL, 'l' },
    { "log-file",               required_argument,  NULL, 'L' },
    { "username",               required_argument,  NULL, 'u' },
    { "password",               required_argument,  NULL, 'p' },
    { "pcap-capture",           required_argument,  NULL, 'P' },
    { "json-report",            required_argument,  NULL, 'J' },
    { "session-count",          required_argument,  NULL, 'c' },
    { "mc-group",               required_argument,  NULL, 'g' },
    { "mc-source",              required_argument,  NULL, 's' },
    { "mc-group-count",         required_argument,  NULL, 'r' },
    { "mc-zapping-interval",    required_argument,  NULL, 'z' },
    { "control-socket",         required_argument,  NULL, 'S' },
    { "interactive",            no_argument,        NULL, 'I' },
    { "force",                  no_argument,        NULL, 'f' },
    { NULL,                     0,                  NULL,  0 }
};

char *
bbl_print_usage_arg (struct option *option)
{
    if (option->has_arg == 1) {
        if (strcmp(option->name, "logging") == 0) {
            return log_usage();
        }

        return " <args>";
    }
    return "";
}

void
bbl_print_version (void)
{
    if(sizeof(BNGBLASTER_VERSION)-1) {
        printf("Version: %s\n", BNGBLASTER_VERSION);
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

void
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
    int rate = 0;
    uint32_t i;

    if(ctx->sessions_outstanding) ctx->sessions_outstanding--;

    if(ctx->sessions) { 
        if(ctx->sessions_terminated >= ctx->sessions) {
            /* Now close all L2TP tunnels ... */
            if(ctx->l2tp_tunnels == 0) {
                /* Stop event loop to close application! */
                CIRCLEQ_INIT(&ctx->timer_root.timer_bucket_qhead);
            } else {
                bbl_l2tp_stop_all_tunnel(ctx);
            }
            return;
        }
    } else {
        /* Network interface only... */
        if(g_teardown) {
            if(ctx->l2tp_tunnels == 0) {
                /* Stop event loop to close application! */
                CIRCLEQ_INIT(&ctx->timer_root.timer_bucket_qhead);
            } else {
                bbl_l2tp_stop_all_tunnel(ctx);
            }
            return;
        }
        return;
    }

    if(g_teardown) {
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
        /* Setup phase ... 
         * Iterate over all idle session (list of pending sessions)
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
                                    session->send_requests |= BBL_SEND_DHCPREQUEST;
                                } else if (session->ip_address && session->peer_ip_address) {
                                    /* Start IPoE session by sending ARP request if local and 
                                     * remote IP addresses are already provided. */
                                    session->send_requests |= BBL_SEND_ARP_REQUEST;
                                }
                            }
                            if(session->access_config->ipv6_enable) {
                                /* Start IPoE session by sending RS. */
                                session->send_requests |= BBL_SEND_ICMPV6_RS;
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

int
main (int argc, char *argv[])
{
    bbl_ctx_s *ctx = NULL;
    int long_index = 0;
    int ch = 0;
    uint32_t ipv4;
    bbl_stats_t stats = {0};

    char *config_file = NULL;
    char *username = NULL;
    char *password = NULL;
    char *sessions = NULL;
    char *igmp_group = NULL;
    char *igmp_source = NULL;
    char *igmp_group_count = NULL;
    char *igmp_zap_interval = NULL;
    bool  interactive = false;

    ctx = bbl_ctx_add();
    if (!ctx) {
        exit(1);
    }

    /*
     * Clear logging global array.
     */
    memset(log_id, 0, sizeof(struct log_id_) * LOG_ID_MAX);
    log_id[NORMAL].enable = true;
    log_id[ERROR].enable = true;

    /*
     * Seed pseudo random generator.
     */
    srand(time(0));

    /*
     * Process config options.
     */
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
            case 'J':
		        ctx->config.json_report_filename = optarg;
                break;
            case 'C':
                config_file = optarg;
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
            default:
                bbl_print_usage();
                exit(1);
        }
    }
    if (geteuid() != 0) {
        fprintf(stderr, "Error: Must be run with root privileges\n");
	    exit(1);
    }

    if(!config_file) {
        fprintf(stderr, "Error: No configuration specified (-C / --config <file>)\n");
        exit(1);
    }

#if 0
    timer_test(ctx);
    exit(0);
#endif

    /*
     * Init config.
     */
    bbl_config_init_defaults(ctx);
    if(!bbl_config_load_json(config_file, ctx)) {
        fprintf(stderr, "Error: Failed to load configuration file %s\n", config_file);
        exit(1);
    }
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

    /*
     * Start curses.
     */
    if (interactive) {
        bbl_init_curses(ctx);
    }

    /*
     * Add access interfaces.
     */
    if(!bbl_add_access_interfaces(ctx)) {
        if (interactive) endwin();
        fprintf(stderr, "Error: Failed to add access interfaces\n");
        exit(1);
    }

    /*
     * Add network interface.
     */
    if (strlen(ctx->config.network_if)) {
        ctx->op.network_if = bbl_add_interface(ctx, ctx->config.network_if);
        if (!ctx->op.network_if) {
            if (interactive) endwin();
            fprintf(stderr, "Error: Failed to add network interface\n");
            exit(1);
        }
        ctx->op.network_if->access = false;
        if(ctx->config.network_ip && ctx->config.network_gateway) {
            if(ctx->config.network_ip && ctx->config.network_gateway) {
                ctx->op.network_if->ip = ctx->config.network_ip;
                ctx->op.network_if->gateway = ctx->config.network_gateway;
                /* Send initial ARP request */
                ctx->op.network_if->send_requests |= BBL_IF_SEND_ARP_REQUEST;
            }
            /* Add Multicast traffic */
            if(!bbl_add_multicast_packets(ctx, ctx->op.network_if)) {
                if (interactive) endwin();
                fprintf(stderr, "Error: Failed to add multicast traffic\n");
                exit(1);
            }
            ctx->multicast_traffic = true;
            ctx->op.network_if->mc_packet_seq = 1;
        }
        if(ctx->config.network_ip6.len && ctx->config.network_gateway6.len) {
            memcpy(&ctx->op.network_if->ip6, &ctx->config.network_ip6, sizeof(ipv6_prefix));
            memcpy(&ctx->op.network_if->gateway6, &ctx->config.network_gateway6, sizeof(ipv6_prefix));
            /* Send initial ICMPv6 NS */
            ctx->op.network_if->send_requests |= BBL_IF_SEND_ICMPV6_NS;
        }
    }

    /*
     * Setup resources in case PCAP dumping is desired.
     */
    pcapng_init(ctx);

    /*
     * Setup test.
     */
    if(ctx->op.access_if_count) {
        if(!bbl_sessions_init(ctx)) {
            if (interactive) endwin();
            fprintf(stderr, "Error: Failed to init sessions\n");
            exit(1);
        };
    }

    /*
     * Setup control job.
     */
    timer_add_periodic(&ctx->timer_root, &ctx->control_timer, "Control Timer", 1, 0, ctx, &bbl_ctrl_job);

    /*
     * Setup control socket and job
     */
    if(ctx->ctrl_socket_path) {
        if(!bbl_ctrl_socket_open(ctx)) {
            if (interactive) endwin();
            exit(1);
        }
    }
    
    /*
     * Start smear job. Use a crazy nsec bucket '12345678', such that we do not accidentally smear ourselves.
     */
    timer_add_periodic(&ctx->timer_root, &ctx->smear_timer, "Timer Smearing", 45, 12345678, ctx, &bbl_smear_job);

    /*
     * Start event loop.
     */
    log_open();
    clock_gettime(CLOCK_MONOTONIC, &ctx->timestamp_start);
    signal(SIGINT, teardown_handler);
    timer_walk(&ctx->timer_root);
    while(ctx->sessions_terminated < ctx->sessions && g_teardown_request_count < 10) {
        timer_walk(&ctx->timer_root);
    }
    clock_gettime(CLOCK_MONOTONIC, &ctx->timestamp_stop);

    /*
     * Stop curses. Do this before the final reports.
     */
    if(g_interactive) {
        endwin();
    }

    /*
     * Generate reports.
     */
    bbl_stats_generate(ctx, &stats);
    bbl_stats_stdout(ctx, &stats);
    bbl_stats_json(ctx, &stats);

    /*
     * Cleanup ressources.
     */
    bbl_interface_unlock_all(ctx);
    log_close();
    if(ctx->ctrl_socket_path) {
        bbl_ctrl_socket_close(ctx);
    }
    bbl_ctx_del(ctx);
    ctx = NULL;
}
