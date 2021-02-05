/*
 * BNG BLaster (BBL), a tool for scale testing the control plane of BNG and BRAS devices.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_config.h"
#include "bbl_pcap.h"
#include "bbl_stats.h"
#include "bbl_interactive.h"
#include "bbl_ctrl.h"

#include "bbl_logging.h"

/* Global Variables */
bool g_interactive = false; // interactive mode using ncurses
char *g_log_file = NULL;

volatile bool g_teardown = false;
volatile bool g_teardown_request = false;
volatile uint8_t g_teardown_request_count = 0;

/* This variable is used to switch between access
 * interfaces in interactive mode (ncurses). */
uint8_t g_access_if_selected = 0; 

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

void
bbl_session_update_state(bbl_ctx_s *ctx, bbl_session_s *session, session_state_t state)
{
    if(session->session_state != state) {
        /* State has changed ... */
        if(session->session_state == BBL_ESTABLISHED && ctx->sessions_established) {
            /* Decrement sessions established if old state is established. */
            ctx->sessions_established--;
            if(session->dhcpv6_received) {
                ctx->dhcpv6_established--;
            }
            if(session->dhcpv6_requested) {
                ctx->dhcpv6_requested--;
            }
        } else if(state == BBL_ESTABLISHED) {
            /* Increment sessions established and decrement outstanding
             * if new state is established. */
            ctx->sessions_established++;
            if(ctx->sessions_established > ctx->sessions_established_max) ctx->sessions_established_max = ctx->sessions_established;
            if(ctx->sessions_outstanding) ctx->sessions_outstanding--;
        }
        if(state == BBL_PPP_TERMINATING) {
            session->ipcp_state = BBL_PPP_CLOSED;
            session->ip6cp_state = BBL_PPP_CLOSED;
        }
        if(state == BBL_TERMINATED) {
            /* Stop all session tiemrs */
            timer_del(session->timer_arp);
            timer_del(session->timer_padi);
            timer_del(session->timer_padr);
            timer_del(session->timer_lcp);
            timer_del(session->timer_lcp_echo);
            timer_del(session->timer_auth);
            timer_del(session->timer_ipcp);
            timer_del(session->timer_ip6cp);
            timer_del(session->timer_dhcpv6);
            timer_del(session->timer_igmp);
            timer_del(session->timer_zapping);
            timer_del(session->timer_icmpv6);
            timer_del(session->timer_session);
            timer_del(session->timer_session_traffic_ipv4);
            timer_del(session->timer_session_traffic_ipv6);
            timer_del(session->timer_session_traffic_ipv6pd);

            /* Reset all states */
            session->lcp_state = BBL_PPP_CLOSED;
            session->ipcp_state = BBL_PPP_CLOSED;
            session->ip6cp_state = BBL_PPP_CLOSED;

            /* Increment sessions terminated if new state is terminated. */
            if(g_teardown) {
                ctx->sessions_terminated++;
            } else {
                if(session->access_type == ACCESS_TYPE_PPPOE) {
                    if(ctx->config.pppoe_reconnect) {
                        state = BBL_IDLE;
                        CIRCLEQ_INSERT_TAIL(&ctx->sessions_idle_qhead, session, session_idle_qnode);
                        memset(&session->server_mac, 0xff, ETH_ADDR_LEN); // init with broadcast MAC
                        session->pppoe_session_id = 0;
                        session->pppoe_ac_cookie_len = 0;
                        session->ip_address = 0;
                        session->peer_ip_address = 0;
                        session->dns1 = 0;
                        session->dns2 = 0;
                        session->ipv6_prefix.len = 0;
                        session->delegated_ipv6_prefix.len = 0;
                        session->icmpv6_ra_received = false;
                        session->dhcpv6_requested = false;
                        session->dhcpv6_received = false;
                        session->dhcpv6_type = DHCPV6_MESSAGE_SOLICIT;
                        session->dhcpv6_ia_pd_option_len = 0;
                        session->zapping_joined_group = NULL;
                        session->zapping_leaved_group = NULL;
                        session->zapping_count = 0;
                        session->zapping_view_start_time.tv_sec = 0;
                        session->zapping_view_start_time.tv_nsec = 0;
                        session->stats.flapped++;
                        ctx->sessions_flapped++;
                    } else {
                        ctx->sessions_terminated++;
                    }
                } else {
                    /* IPoE */
                    ctx->sessions_terminated++;
                }
            }
        }
        session->session_state = state;
    }
}

bool
bbl_add_multicast_packets (bbl_ctx_s *ctx, bbl_interface_s *interface)
{
    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ip = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};
    uint8_t mac[ETH_ADDR_LEN] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x00 };
    uint8_t *buf;

    uint32_t group;
    uint32_t source;

    int i;
    uint len = 0;

    if(ctx->config.send_multicast_traffic && ctx->config.igmp_group_count) {
        interface->mc_packets = malloc(ctx->config.igmp_group_count * 1500);
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
            /* Generate destination MAC */
            *(uint32_t*)&mac[2] = group & 0x7FDDDF; mac[2] = 0x5e;

            eth.src = interface->mac;
            eth.dst = mac;
            eth.vlan_outer = ctx->config.network_vlan;
            eth.type = ETH_TYPE_IPV4;
            eth.next = &ip;
            ip.src = source;
            ip.dst = htobe32(group);
            ip.ttl = 64;
            ip.protocol = PROTOCOL_IPV4_UDP;
            ip.next = &udp;
            udp.src = BBL_UDP_PORT;
            udp.dst = BBL_UDP_PORT;
            udp.protocol = UDP_PROTOCOL_BBL;
            udp.next = &bbl;
            bbl.type = BBL_TYPE_MULTICAST;
            bbl.direction = BBL_DIRECTION_DOWN;
            bbl.mc_source = ip.src;
            bbl.mc_group = ip.dst ;
            if(encode_ethernet(buf, &len, &eth) != PROTOCOL_SUCCESS) {
                return false;
            }
            buf = buf + len;
        }
    }
    interface->mc_packet_len = len;
    return true;
}

/*
 * Allocate an interface and setup Tx and Rx rings.
 */
bbl_interface_s *
bbl_add_interface (bbl_ctx_s *ctx, char *interface_name, int slots)
{
    bbl_interface_s *interface;
    char timer_name[16];
    struct ifreq ifr;
    size_t ring_size;
    int version, qdisc_bypass;

    interface = calloc(1, sizeof(bbl_interface_s));
    if (!interface) {
        LOG(ERROR, "No memory for interface %s\n", interface_name);
        return NULL;
    }

    interface->name = strdup(interface_name);

    /*
     * Open RAW socket for all Ethertypes.
     * https://man7.org/linux/man-pages/man7/packet.7.html
     */
    interface->fd_tx = socket(AF_PACKET, SOCK_RAW, htobe16(ETH_P_ALL));
    if (interface->fd_tx == -1) {
        LOG(ERROR, "socket() TX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return NULL;
    }

    interface->fd_rx = socket(AF_PACKET, SOCK_RAW, htobe16(ETH_P_ALL));
    if (interface->fd_rx == -1) {
        LOG(ERROR, "socket() RX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return NULL;
    }

    /*
     * Use API version 2 which is good enough for what we're doing.
     */
    version = TPACKET_V2;
    if ((setsockopt(interface->fd_tx, SOL_PACKET, PACKET_VERSION, &version, sizeof(version))) == -1) {
        LOG(ERROR, "setsockopt() TX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return NULL;
    }

    if ((setsockopt(interface->fd_rx, SOL_PACKET, PACKET_VERSION, &version, sizeof(version))) == -1) {
        LOG(ERROR, "setsockopt() RX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return NULL;
    }

    /*
     * Limit packet capture to a given interface.
     * Obtain the interface index and bind the socket to the interface.
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface_name);
    if (ioctl(interface->fd_tx, SIOCGIFINDEX, &ifr) == -1) {
        LOG(ERROR, "Get interface index error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return NULL;
    }

    interface->addr.sll_family = AF_PACKET;
    interface->addr.sll_ifindex = ifr.ifr_ifindex;
    interface->addr.sll_protocol = htobe16(ETH_P_ALL);
    if (bind(interface->fd_tx, (struct sockaddr*)&interface->addr, sizeof(interface->addr)) == -1) {
        LOG(ERROR, "bind() TX error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return NULL;
    }

    if (bind(interface->fd_rx, (struct sockaddr*)&interface->addr, sizeof(interface->addr)) == -1) {
        LOG(ERROR, "bind() RX error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return NULL;
    }

    /*
     * Obtain the interface MAC address.
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface_name);
    if (ioctl(interface->fd_rx, SIOCGIFHWADDR, &ifr) == -1) {
        LOG(ERROR, "Getting MAC address error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return NULL;
    }
    memcpy(&interface->mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
    LOG(NORMAL, "Getting MAC address %02x:%02x:%02x:%02x:%02x:%02x for interface %s\n",
	interface->mac[0], interface->mac[1], interface->mac[2],
	interface->mac[3], interface->mac[4], interface->mac[5], interface->name);

    /*
     * Set the interface to promiscuous mode. Only for the RX FD.
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface_name);
    if (ioctl(interface->fd_rx, SIOCGIFFLAGS, &ifr) == -1) {
        LOG(ERROR, "Getting socket flags error %s (%d) when setting promiscuous mode for interface %s\n",
        strerror(errno), errno, interface->name);
        return NULL;
    }

    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(interface->fd_rx, SIOCSIFFLAGS, ifr) == -1){
        LOG(ERROR, "Setting socket flags error %s (%d) when setting promiscuous mode for interface %s\n",
        strerror(errno), errno, interface->name);
        return NULL;
    }

    /*
     *   Bypass TC_QDISC, such that the kernel is hammered 30% less with processing packets. Only for the TX FD.
     *
     *   PACKET_QDISC_BYPASS (since Linux 3.14)
     *          By default, packets sent through packet sockets pass through
     *          the kernel's qdisc (traffic control) layer, which is fine for
     *          the vast majority of use cases.  For traffic generator appli‐
     *          ances using packet sockets that intend to brute-force flood
     *          the network—for example, to test devices under load in a simi‐
     *          lar fashion to pktgen—this layer can be bypassed by setting
     *          this integer option to 1.  A side effect is that packet
     *          buffering in the qdisc layer is avoided, which will lead to
     *          increased drops when network device transmit queues are busy;
     *          therefore, use at your own risk.
     */
    qdisc_bypass = 1;
    if (setsockopt(interface->fd_tx, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass)) == -1) {
        LOG(ERROR, "Setting qdisc bypass error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return NULL;
    }

    /*
     * Setup TX ringbuffer.
     */
    memset(&interface->req_tx, 0, sizeof(interface->req_tx));
    interface->req_tx.tp_block_size = sysconf(_SC_PAGESIZE); /* 4096 */
    interface->req_tx.tp_frame_size = interface->req_tx.tp_block_size/2; /* 2048 */
    interface->req_tx.tp_block_nr = slots/2;
    interface->req_tx.tp_frame_nr = slots;
    if (setsockopt(interface->fd_tx, SOL_PACKET, PACKET_TX_RING, &interface->req_tx, sizeof(interface->req_tx)) == -1) {
        LOG(ERROR, "Allocating TX ringbuffer error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return NULL;
    }

    /*
     * Open the shared memory TX window between kernel and userspace.
     */
    ring_size = interface->req_tx.tp_block_nr * interface->req_tx.tp_block_size;
    interface->ring_tx = mmap(0, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, interface->fd_tx, 0);

    /*
     * Setup RX ringbuffer. Double the slots, such that we do not miss any packets.
     */
    slots <<= 1;
    memset(&interface->req_rx, 0, sizeof(interface->req_rx));
    interface->req_rx.tp_block_size = sysconf(_SC_PAGESIZE); /* 4096 */
    interface->req_rx.tp_frame_size = interface->req_rx.tp_block_size/2; /* 2048 */
    interface->req_rx.tp_block_nr = slots/2;
    interface->req_rx.tp_frame_nr = slots;
    if (setsockopt(interface->fd_rx, SOL_PACKET, PACKET_RX_RING, &interface->req_rx, sizeof(interface->req_rx)) == -1) {
        LOG(ERROR, "Allocating RX ringbuffer error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return NULL;
    }

    /*
     * Open the shared memory RX window between kernel and userspace.
     */
    ring_size = interface->req_rx.tp_block_nr * interface->req_rx.tp_block_size;
    interface->ring_rx = mmap(0, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, interface->fd_rx, 0);

    LOG(NORMAL, "Add interface %s\n", interface->name);

    /*
     * Add an periodic timer for polling I/O.
     */
    snprintf(timer_name, sizeof(timer_name), "%s TX", interface_name);
    timer_add_periodic(&ctx->timer_root, &interface->tx_job, timer_name, 0, ctx->config.tx_interval * MSEC, interface, bbl_tx_job);
    snprintf(timer_name, sizeof(timer_name), "%s RX", interface_name);
    timer_add_periodic(&ctx->timer_root, &interface->rx_job, timer_name, 0, ctx->config.rx_interval * MSEC, interface, bbl_rx_job);

    /*
     * Timer to compute periodic rates.
     */
    timer_add_periodic(&ctx->timer_root, &interface->rate_job, "Rate Computation", 1, 0, interface,
		               bbl_compute_interface_rate_job);

    /*
     * Add to context interface list.
     */
    interface->ctx = ctx;
    CIRCLEQ_INSERT_TAIL(&ctx->interface_qhead, interface, interface_qnode);

    interface->pcap_index = ctx->pcap.index;
    ctx->pcap.index++;

    /*
     * List for sessions who want to transmit.
     */
    CIRCLEQ_INIT(&interface->session_tx_qhead);

    return interface;
}

bool
bbl_add_access_interfaces (bbl_ctx_s *ctx) {
    bbl_access_config_s *access_config = ctx->config.access_config;
    struct bbl_interface_ *access_if;
    int i;

    while(access_config) {
        for(i = 0; i < ctx->op.access_if_count; i++) {
            if(ctx->op.access_if[i]->name) {
                if (strncmp(ctx->op.access_if[i]->name, access_config->interface, IFNAMSIZ) == 0) {
                    /* Interface already added! */
                    access_config->access_if = ctx->op.access_if[i];
                    goto Next;
                }
            }
        }
        access_if = bbl_add_interface(ctx, access_config->interface, 1024);
        if (!access_if) {
            LOG(ERROR, "Failed to add access interface %s\n", access_config->interface);
            return false;
        }
        access_if->access = true;
        access_config->access_if = access_if;
        ctx->op.access_if[ctx->op.access_if_count++] = access_if;
Next:
        access_config = access_config->next;
    }
    return true;
}

/*
 * Command line options.
 */
const char *optstring = "vhC:l:L:a:n:u:p:P:J:c:g:s:r:z:S:I";
static struct option long_options[] = {
    { "version",                no_argument,        NULL, 'v' },
    { "help",                   no_argument,        NULL, 'h' },
    { "config",                 required_argument,  NULL, 'C' },
    { "logging",                required_argument,  NULL, 'l' },
    { "log-file",               required_argument,  NULL, 'L' },
    { "access-interface",       required_argument,  NULL, 'a' },
    { "network-interface",      required_argument,  NULL, 'n' },
    { "username",               required_argument,  NULL, 'u' },
    { "password",               required_argument,  NULL, 'p' },
    { "pcap-capture",           required_argument,  NULL, 'P' },
    { "json-report",            required_argument,  NULL, 'J' },
    { "pppoe-session-count",    required_argument,  NULL, 'c' },
    { "mc-group",               required_argument,  NULL, 'g' },
    { "mc-source",              required_argument,  NULL, 's' },
    { "mc-group-count",         required_argument,  NULL, 'r' },
    { "mc-zapping-interval",    required_argument,  NULL, 'z' },
    { "control socket (UDS)",   required_argument,  NULL, 'S' },
    { "interactive (ncurses)",  no_argument,        NULL, 'I' },
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
    if(strlen(BNGBLASTER_VERSION)) {
        printf("Version: %s\n", BNGBLASTER_VERSION);
    }
    if(strlen(GIT_REF) + strlen(GIT_SHA)) {
        printf("GIT:\n");
        printf("  REF: %s\n", GIT_REF);
        printf("  SHA: %s\n", GIT_SHA);
    }
}

void
bbl_print_usage (void)
{
    u_int idx;
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

#if 0
/*
 * Called by hashtable destructor.
 */
void
bbl_free_session (void *key __attribute__((unused)), void *s)
{
    bbl_session_s *session = s; 
    if(session->access_ipv4_tx_packet_template) {
        free(session->access_ipv4_tx_packet_template);
    }
    if(session->network_ipv4_tx_packet_template) {
        free(session->network_ipv4_tx_packet_template);
    }
    if(session->access_ipv6_tx_packet_template) {
        free(session->access_ipv6_tx_packet_template);
    }
    if(session->network_ipv6_tx_packet_template) {
        free(session->network_ipv6_tx_packet_template);
    }
    if(session->access_ipv6pd_tx_packet_template) {
        free(session->access_ipv6pd_tx_packet_template);
    }
    if(session->network_ipv6pd_tx_packet_template) {
        free(session->network_ipv6pd_tx_packet_template);
    }
    free(session);
}
#endif

/*
 * A session key fits in 64-Bits. Lets do this instead of a memcmp()
 */
int
bbl_compare_session (void *key1, void *key2)
{
    const uint64_t a = *(const uint64_t*)key1;
    const uint64_t b = *(const uint64_t*)key2;
    return (a > b) - (a < b);
}

uint
bbl_session_hash (const void* k)
{
    uint hash = 2166136261U;

    hash ^= *(uint32_t *)k;
    hash ^= *(uint16_t *)(k+4) << 12;
    hash ^= *(uint16_t *)(k+6);

    return hash;
}

/*
 * Allocate a context which is our top-level data structure.
 */
bbl_ctx_s *
bbl_add_ctx (void)
{
    bbl_ctx_s *ctx;

    ctx = calloc(1, sizeof(bbl_ctx_s));
        if (!ctx) {
        return NULL;
    }

    /* Allocate scratchpad memory. */
    ctx->sp_rx = malloc(SCRATCHPAD_LEN);
    ctx->sp_tx = malloc(SCRATCHPAD_LEN);

    /*
     * Initialize Timer root.
     */
    timer_init_root(&ctx->timer_root);

    CIRCLEQ_INIT(&ctx->sessions_idle_qhead);
    CIRCLEQ_INIT(&ctx->sessions_teardown_qhead);
    CIRCLEQ_INIT(&ctx->interface_qhead);

    ctx->flow_id = 1;
    /*
     * Initialize session DB.
     */
    ctx->session_dict = hashtable2_dict_new((dict_compare_func)bbl_compare_session,
                                            bbl_session_hash,
                                            BBL_SESSION_HASHTABLE_SIZE);

    return ctx;
}

void
bbl_del_ctx (bbl_ctx_s *ctx) {
    bbl_access_config_s *access_config = ctx->config.access_config;
    void *p = NULL;

    /* Free access configuration memory. */
    while(access_config) {
        p = access_config;
        access_config = access_config->next;
        free(p);
    }

    if(ctx->sp_rx) {
        free(ctx->sp_rx);
    }
    if(ctx->sp_tx) {
        free(ctx->sp_tx);
    }

    pcapng_free(ctx);
    timer_flush_root(&ctx->timer_root);
    free(ctx);
    return;
}

bbl_session_s *
bbl_add_session (bbl_ctx_s *ctx, bbl_interface_s *interface, bbl_session_s *session_template, bbl_access_config_s *access_config)
{
    bbl_session_s *session;
    dict_insert_result result;

    session = calloc(1, sizeof(bbl_session_s));
    if (!session) {
        return NULL;
    }

    /*
     * Copy key data.
     */
    memcpy(&session->key, &session_template->key, sizeof(session->key));

    /*
     * Copy non-key data.
     */
    session->access_type = session_template->access_type;
    session->access_third_vlan = access_config->access_third_vlan;
    session->access_config = access_config;
    memcpy(session->server_mac, session_template->server_mac, ETH_ADDR_LEN);
    memcpy(session->client_mac, session_template->client_mac, ETH_ADDR_LEN);
    session->mru = session_template->mru;
    session->magic_number = session_template->magic_number;
    snprintf(session->username, USERNAME_LEN, "%s", session_template->username);
    snprintf(session->password, PASSWORD_LEN, "%s", session_template->password);
    snprintf(session->agent_circuit_id, ACI_LEN, "%s", session_template->agent_circuit_id);
    snprintf(session->agent_remote_id, ARI_LEN, "%s", session_template->agent_remote_id);
    session->rate_up = session_template->rate_up;
    session->rate_down = session_template->rate_down;
    session->duid[1] = 3;
    session->duid[3] = 1;
    memcpy(&session->duid[4], session_template->client_mac, ETH_ADDR_LEN);
    session->igmp_autostart = access_config->igmp_autostart;
    session->igmp_version = access_config->igmp_version;
    session->igmp_robustness = 2; /* init robustness with 2 */
    session->zapping_group_max = be32toh(ctx->config.igmp_group) + ((ctx->config.igmp_group_count - 1) * be32toh(ctx->config.igmp_group_iter));
    session->session_traffic = access_config->session_traffic_autostart;
    if(session->access_type == ACCESS_TYPE_IPOE) {
        if(access_config->static_ip && access_config->static_gateway) {
            session->ip_address = access_config->static_ip;
            session->peer_ip_address = access_config->static_gateway;
            access_config->static_ip = htobe32(be32toh(access_config->static_ip) + be32toh(access_config->static_ip_iter));
            access_config->static_gateway = htobe32(be32toh(access_config->static_gateway) + be32toh(access_config->static_gateway_iter));
        }
    }

    /*
     * Insert session into session dictionary hanging off a context.
     */
    result = dict_insert(ctx->session_dict, &session->key);
    if (!result.inserted) {
        free(session);
        return NULL;
    }
    *result.datum_ptr = session;

    /*
     * Store parent.
     */
    session->interface = interface;
    session->session_state = BBL_IDLE;
    CIRCLEQ_INSERT_TAIL(&ctx->sessions_idle_qhead, session, session_idle_qnode);
    ctx->sessions++;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        ctx->sessions_pppoe++;
    } else {
        ctx->sessions_ipoe++;
    }
    return session;
}

bool
bbl_init_sessions (bbl_ctx_s *ctx)
{
    bbl_session_s session_template;
    bbl_access_config_s *access_config;
        
    uint32_t i = 1;
    char *s;
    char snum1[32];
    char snum2[32];

    /* The variable t counts how many sessions are created in one 
     * loop over all access configurations and is reset to zero
     * every time we start from first access profile. If the variable 
     * is still zero after processing last access profile means 
     * that all VLAN ranges are exhausted. */
    int t = 0;
    
    access_config = ctx->config.access_config;

    /* For equal distribution of sessions over access configurations 
     * and outer VLAN's, we loop first over all configurations,
     * second over all outer VLAN's and last over all inner VLAN's. */
    while(i <= ctx->config.sessions) {
        if(access_config->exhausted) goto Next;
        if(access_config->access_outer_vlan == 0) {
            /* The outer VLAN is initial 0 */
            access_config->access_outer_vlan = access_config->access_outer_vlan_min;
            access_config->access_inner_vlan = access_config->access_inner_vlan_min;
        } else {
            access_config->access_outer_vlan++;
            if(access_config->access_outer_vlan > access_config->access_outer_vlan_max) {
                access_config->access_outer_vlan = access_config->access_outer_vlan_min;
                if(access_config->access_inner_vlan <= access_config->access_inner_vlan_max) {
                    access_config->access_inner_vlan++;
                }
            }
        }
        if(access_config->access_inner_vlan > access_config->access_inner_vlan_max) {
            /* VLAN range exhausted */
            access_config->exhausted = true;
            goto Next;
        }
        t++;
        access_config->sessions++;
        memset(&session_template, 0, sizeof(session_template));
        memset(&session_template.server_mac, 0xff, ETH_ADDR_LEN); // init with broadcast MAC
        session_template.key.outer_vlan_id= access_config->access_outer_vlan;
        session_template.key.inner_vlan_id = access_config->access_inner_vlan;
        session_template.key.ifindex = access_config->access_if->addr.sll_ifindex;
        session_template.client_mac[0] = 0x02; //
        session_template.client_mac[1] = 0x00; // set client OUI ro locally administered
        session_template.client_mac[2] = 0x00; //
        session_template.mru = ctx->config.ppp_mru;
        session_template.access_type = access_config->access_type;
        session_template.client_mac[3] = i>>16;
        session_template.client_mac[4] = i>>8;
        session_template.client_mac[5] = i;
        session_template.magic_number = i;
        /* Populate session identifiaction attributes */
        snprintf(snum1, 6, "%d", i);
        snprintf(snum2, 6, "%d", access_config->sessions);
        /* Update username */
        s = replace_substring(access_config->username, "{session-global}", snum1);
        snprintf(session_template.username, USERNAME_LEN, "%s", s);
        s = replace_substring(session_template.username, "{session}", snum2);
        snprintf(session_template.username, USERNAME_LEN, "%s", s);
        /* Update password */
        s = replace_substring(access_config->password, "{session-global}", snum1);
        snprintf(session_template.password, PASSWORD_LEN, "%s", s);
        s = replace_substring(session_template.password, "{session}", snum2);
        snprintf(session_template.password, PASSWORD_LEN, "%s", s);
        /* Update ACI */
        s = replace_substring(access_config->agent_circuit_id, "{session-global}", snum1);
        snprintf(session_template.agent_circuit_id, ACI_LEN, "%s", s);
        s = replace_substring(session_template.agent_circuit_id, "{session}", snum2);
        snprintf(session_template.agent_circuit_id, ACI_LEN, "%s", s);
        /* Update ARI */
        s = replace_substring(access_config->agent_remote_id, "{session-global}", snum1);
        snprintf(session_template.agent_remote_id, ARI_LEN, "%s", s);
        s = replace_substring(session_template.agent_remote_id, "{session}", snum2);
        snprintf(session_template.agent_remote_id, ARI_LEN, "%s", s);
        /* Update rates ... */
        session_template.rate_up = access_config->rate_up;
        session_template.rate_down = access_config->rate_down;
        if(bbl_add_session(ctx, access_config->access_if, &session_template, access_config) == NULL) {
            LOG(ERROR, "Failed to create session (%s Q-in-Q %u:%u)\n", access_config->interface, access_config->access_outer_vlan, access_config->access_inner_vlan);
            return false;
        }
        i++;
Next:
        if(access_config->next) {
            access_config = access_config->next;
        } else {
            if (t) {
                t = 0;
                access_config = ctx->config.access_config;
            } else {
                LOG(ERROR, "Failed to create sessions because VLAN ranges exhausted!\n");
                return false;
            }

        }
    }
    return true;
}

/*
 * performance test code
 */
#if 0
void
bbl_test_lookup_session(bbl_ctx_s *ctx)
{
    session_key_t key;
    uint ifindex, outer_vlan_id, inner_vlan_id, session_found;
    void **search;

    session_found = 0;
    for (ifindex = 0; ifindex < 10; ifindex++) {
        for (outer_vlan_id = 1; outer_vlan_id < 200; outer_vlan_id++) {
            for (inner_vlan_id = 1; inner_vlan_id < 200; inner_vlan_id++) {
                key.ifindex = ifindex;
                key.outer_vlan_id = outer_vlan_id;
                key.inner_vlan_id = inner_vlan_id;
                search = dict_search(ctx->session_dict, &key);
                if (search) {
                    session_found++;
                }
            }
        }
    }
}
#endif

void
bbl_session_clear(bbl_ctx_s *ctx, bbl_session_s *session)
{
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        switch(session->session_state) {
            case BBL_IDLE:
                bbl_session_update_state(ctx, session, BBL_TERMINATED);
                break;
            case BBL_PPPOE_INIT:
            case BBL_PPPOE_REQUEST:
            case BBL_PPP_LINK:
                bbl_session_update_state(ctx, session, BBL_TERMINATING);
                session->send_requests = BBL_SEND_DISCOVERY;
                bbl_session_tx_qnode_insert(session);
                break;
            case BBL_PPP_AUTH:
            case BBL_PPP_NETWORK:
            case BBL_ESTABLISHED:
            case BBL_PPP_TERMINATING:
                bbl_session_update_state(ctx, session, BBL_PPP_TERMINATING);
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->lcp_options_len = 0;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
            default:
                break;
        }
    } else {
        bbl_session_update_state(ctx, session, BBL_TERMINATED);
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
    struct dict_itor *itor;
    int rate = 0;

    if(ctx->sessions_outstanding) ctx->sessions_outstanding--;

    if(ctx->sessions) { 
        if(ctx->sessions_terminated >= ctx->sessions) {
            CIRCLEQ_INIT(&ctx->timer_root.timer_bucket_qhead);
            return;
        }
    } else {
        /* Network interface only... */
        if(g_teardown) {
            CIRCLEQ_INIT(&ctx->timer_root.timer_bucket_qhead);
            return;
        }
        return;
    }

    if(g_teardown) {
        /* Teardown phase ... */
        if(g_teardown_request) {
            /* Put all sessions on the teardown list. */
            itor = dict_itor_new(ctx->session_dict);
            dict_itor_first(itor);
            for (; dict_itor_valid(itor); dict_itor_next(itor)) {
                session = (bbl_session_s*)*dict_itor_datum(itor);
                if(!CIRCLEQ_NEXT(session, session_teardown_qnode)) {
                    /* Add only if not already on teardown list. */
                    CIRCLEQ_INSERT_TAIL(&ctx->sessions_teardown_qhead, session, session_teardown_qnode);
                }
            }
            dict_itor_free(itor);
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

    ctx = bbl_add_ctx();
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
    if(username) snprintf(ctx->config.username, USERNAME_LEN, "%s", username);
    if(password) snprintf(ctx->config.password, PASSWORD_LEN, "%s", password);
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
        ctx->op.network_if = bbl_add_interface(ctx, ctx->config.network_if, 1024);
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
        if(!bbl_init_sessions(ctx)) {
            if (interactive) endwin();
            fprintf(stderr, "Error: Failed to init sessions\n");
            exit(1);
        };
    }

    /*
     * Setup control job.
     */
    timer_add_periodic(&ctx->timer_root, &ctx->control_timer, "Control Timer", 1, 0, ctx, bbl_ctrl_job);

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
    timer_add_periodic(&ctx->timer_root, &ctx->smear_timer, "Timer Smearing", 45, 12345678, ctx, bbl_smear_job);

    /*
     * Start event loop.
     */
    log_open();
    clock_gettime(CLOCK_REALTIME, &ctx->timestamp_start);
    signal(SIGINT, teardown_handler);
    timer_walk(&ctx->timer_root);
    while(ctx->sessions_terminated < ctx->sessions && g_teardown_request_count < 10) {
        timer_walk(&ctx->timer_root);
    }
    clock_gettime(CLOCK_REALTIME, &ctx->timestamp_stop);

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
    log_close();
    if(ctx->ctrl_socket_path) {
        bbl_ctrl_socket_close(ctx);
    }
    bbl_del_ctx(ctx);
    ctx = NULL;
}
