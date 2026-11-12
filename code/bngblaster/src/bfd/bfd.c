/*
 * BNG Blaster (BBL) - BFD Main
 *
 * Bidirectional Forwarding Detection in asynchronous
 * mode without echo function and demand mode for
 * single-hop (RFC 5881) and multi-hop (RFC 5883).
 *
 * BFD runs in the main thread, the TX timer of each session
 * is restarted with jitter after each packet and the detection
 * timer after each valid packet received.
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bfd.h"

/* The jitter is quantized to limit the number of timer buckets. */
#define BFD_JITTER_STEPS 16

static bfd_profile_config_s g_bfd_default_profile = {
    .id = 0,
    .tx_interval = BFD_DEFAULT_TX_INTERVAL_MS * 1000,
    .rx_interval = BFD_DEFAULT_RX_INTERVAL_MS * 1000,
    .multiplier = BFD_DEFAULT_MULTIPLIER,
};

static void
bfd_tx_job(timer_s *timer);

static void
bfd_tx_schedule(bfd_session_s *session);

static void
bfd_detect_job(timer_s *timer);

static int
bfd_discr_compare(void *a, void *b)
{
    uint32_t da = *(uint32_t*)a;
    uint32_t db = *(uint32_t*)b;
    return (da > db) - (da < db);
}

static int
bfd_key_compare(void *a, void *b)
{
    return memcmp(a, b, sizeof(bfd_key_s));
}

/**
 * bfd_profile_get
 *
 * @param id profile identifier (0 for defaults)
 * @return profile or NULL if not found
 */
bfd_profile_config_s *
bfd_profile_get(uint16_t id)
{
    bfd_profile_config_s *profile = g_ctx->config.bfd_profile_config;
    if(id == 0) {
        return &g_bfd_default_profile;
    }
    while(profile) {
        if(profile->id == id) return profile;
        profile = profile->next;
    }
    return NULL;
}

bfd_session_s *
bfd_session_by_id(uint32_t id)
{
    bfd_session_s *session = g_ctx->bfd.sessions;
    while(session) {
        if(session->id == id) return session;
        session = session->next;
    }
    return NULL;
}

static const char *
bfd_session_name(bfd_session_s *session)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "%u %s%s%s -> %s", session->id,
             session->interface ? session->interface->name : "",
             session->interface ? " " : "",
             session->local_str, session->peer_str);
    return buf;
}

static void
bfd_key_init(bfd_key_s *key, bbl_network_interface_s *interface, bool multihop,
             uint8_t af, void *local, void *peer)
{
    memset(key, 0x0, sizeof(bfd_key_s));
    key->interface = multihop ? NULL : interface;
    key->af = af;
    key->multihop = multihop;
    if(af == AF_INET) {
        memcpy(key->local, local, IPV4_ADDR_LEN);
        memcpy(key->peer, peer, IPV4_ADDR_LEN);
    } else {
        memcpy(key->local, local, IPV6_ADDR_LEN);
        memcpy(key->peer, peer, IPV6_ADDR_LEN);
    }
}

static uint32_t
bfd_discr_alloc()
{
    uint32_t discr;
    do {
        discr = g_ctx->bfd.next_discr++;
    } while(discr == 0 || hb_tree_search(g_ctx->bfd.discr_db, &discr));
    return discr;
}

static inline uint32_t
bfd_max(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}

/* Recompute negotiated TX interval and detection time (RFC 5880 6.8.2-6.8.4). */
static void
bfd_session_timers_update(bfd_session_s *session)
{
    uint32_t tx_interval = session->tx_interval;
    uint32_t remote_min_tx = session->remote_min_tx ? session->remote_min_tx : 1;
    uint64_t detect_time;

    session->tx_interval = bfd_max(session->active_min_tx, session->remote_min_rx);
    detect_time = (uint64_t)session->remote_multiplier * bfd_max(session->active_min_rx, remote_min_tx);
    session->detect_time = detect_time > UINT32_MAX ? UINT32_MAX : detect_time;
    if(session->tx_interval < tx_interval && session->tx_timer) {
        /* Do not wait for the previous (longer) interval. */
        bfd_tx_schedule(session);
    }
}

/* Set advertised and active intervals while not Up (slow start). */
static void
bfd_session_slow(bfd_session_s *session)
{
    session->desired_min_tx = bfd_max(session->config_tx_interval, BFD_SLOW_TX_INTERVAL_US);
    session->required_min_rx = session->config_rx_interval;
    session->active_min_tx = session->desired_min_tx;
    session->active_min_rx = session->required_min_rx;
    session->poll = false;
}

/* Change advertised intervals while Up, which starts a poll
 * sequence. A shorter TX interval and longer RX interval are
 * applied immediately, all others after the poll sequence. */
static void
bfd_session_poll_start(bfd_session_s *session, uint32_t desired_min_tx, uint32_t required_min_rx)
{
    session->desired_min_tx = desired_min_tx;
    session->required_min_rx = required_min_rx;
    if(desired_min_tx < session->active_min_tx) {
        session->active_min_tx = desired_min_tx;
    }
    if(required_min_rx > session->active_min_rx) {
        session->active_min_rx = required_min_rx;
    }
    session->poll = true;
    bfd_session_timers_update(session);
}

static void
bfd_session_poll_stop(bfd_session_s *session)
{
    session->poll = false;
    session->active_min_tx = session->desired_min_tx;
    session->active_min_rx = session->required_min_rx;
    session->stats.poll++;
    bfd_session_timers_update(session);
}

static uint8_t *
bfd_session_dst_mac(bfd_session_s *session)
{
    bbl_network_interface_s *interface = session->interface;
    if(session->peer_mac_learned) {
        return session->peer_mac;
    }
    return session->ipv6 ? interface->gateway6_mac : interface->gateway_mac;
}

/**
 * bfd_session_send
 *
 * Send BFD control packet.
 *
 * @param session BFD session
 * @param final send final (F) instead of poll (P)
 */
static void
bfd_session_send(bfd_session_s *session, bool final)
{
    bbl_network_interface_s *interface = session->interface;
    bfd_profile_config_s *profile = session->profile;

    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_udp_s udp = {0};
    bbl_bfd_s bfd = {0};
    uint8_t pdu[BFD_MAX_LEN];
    uint8_t *dst_mac;

    dst_mac = bfd_session_dst_mac(session);
    if(!*(uint32_t*)dst_mac && !*(uint16_t*)(dst_mac+4)) {
        /* Next hop not resolved. */
        session->stats.tx_error++;
        return;
    }

    bfd.diag = session->local_diag;
    bfd.state = session->state;
    if(final) {
        bfd.flags = BFD_FLAG_FINAL;
    } else if(session->poll) {
        bfd.flags = BFD_FLAG_POLL;
    }
    bfd.detect_mult = session->multiplier;
    bfd.my_discr = session->local_discr;
    bfd.your_discr = session->remote_discr;
    bfd.desired_min_tx = session->desired_min_tx;
    bfd.required_min_rx = session->required_min_rx;
    bfd.required_min_echo_rx = 0;
    bfd.auth_type = session->auth_type;
    bfd.auth_key_id = profile->auth_key_id;
    if(session->auth_type && session->auth_type != BFD_AUTH_SIMPLE) {
        session->xmit_auth_seq++;
    }
    bfd.pdu = pdu;
    bfd.pdu_len = bfd_packet_encode(pdu, &bfd, session->xmit_auth_seq,
                                    profile->auth_key, profile->auth_key_len);

    eth.dst = dst_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.vlan_inner = interface->inner_vlan;
    eth.qinq = interface->qinq;
    if(interface->tx_label.label) {
        eth.mpls = &interface->tx_label;
    }
    udp.src = session->src_port;
    udp.dst = session->multihop ? BFD_UDP_PORT_MULTI_HOP : BFD_UDP_PORT_SINGLE_HOP;
    udp.protocol = UDP_PROTOCOL_BFD;
    udp.next = &bfd;
    if(session->ipv6) {
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
        ipv6.src = session->local_ipv6;
        ipv6.dst = session->peer_ipv6;
        ipv6.ttl = BFD_TTL;
        ipv6.tos = 0xc0; /* CS6 (network control) */
        ipv6.protocol = IPV6_NEXT_HEADER_UDP;
        ipv6.next = &udp;
    } else {
        eth.type = ETH_TYPE_IPV4;
        eth.next = &ipv4;
        ipv4.src = session->local_ipv4;
        ipv4.dst = session->peer_ipv4;
        ipv4.ttl = BFD_TTL;
        ipv4.tos = 0xc0; /* CS6 (network control) */
        ipv4.offset = IPV4_DF;
        ipv4.protocol = PROTOCOL_IPV4_UDP;
        ipv4.next = &udp;
    }
    if(bbl_txq_to_buffer(interface->txq, &eth) == BBL_TXQ_OK) {
        session->stats.tx++;
        g_ctx->bfd.stats.tx++;
    } else {
        session->stats.tx_error++;
    }
}

static bool
bfd_session_tx_allowed(bfd_session_s *session)
{
    if(session->passive && !session->remote_discr) {
        /* Passive role (RFC 5880 section 6.1). */
        return false;
    }
    /* No periodic packets if the remote system does
     * not want to receive any (RFC 5880 6.8.3). */
    return session->remote_min_rx != 0;
}

static void
bfd_tx_schedule(bfd_session_s *session)
{
    uint32_t interval = session->tx_interval;
    uint64_t nsec;
    uint32_t step;

    /* Jitter of 0-25 % or 10-25 % if the detect
     * multiplier is 1 (RFC 5880 6.8.7). */
    step = rand() % BFD_JITTER_STEPS;
    if(session->multiplier == 1) {
        nsec = (uint64_t)interval * (750 + (150 * step) / BFD_JITTER_STEPS);
    } else {
        nsec = (uint64_t)interval * (750 + (250 * step) / BFD_JITTER_STEPS);
    }
    if(nsec < MSEC) nsec = MSEC;
    timer_add(&g_ctx->timer_root, &session->tx_timer, "BFD TX",
              nsec / SEC, nsec % SEC, session, &bfd_tx_job);
}

static void
bfd_tx_job(timer_s *timer)
{
    bfd_session_s *session = timer->data;
    if(bfd_session_tx_allowed(session)) {
        bfd_session_send(session, false);
    }
    bfd_tx_schedule(session);
}

static void
bfd_detect_start(bfd_session_s *session)
{
    uint64_t nsec = (uint64_t)session->detect_time * 1000;
    if(!nsec) return;
    timer_add(&g_ctx->timer_root, &session->detect_timer, "BFD DETECT",
              nsec / SEC, nsec % SEC, session, &bfd_detect_job);
}

static void
bfd_session_free(bfd_session_s *session)
{
    bfd_client_s *client;

    hb_tree_remove(g_ctx->bfd.discr_db, &session->local_discr);
    hb_tree_remove(g_ctx->bfd.key_db, &session->key);
    if(session->prev) {
        session->prev->next = session->next;
    } else {
        g_ctx->bfd.sessions = session->next;
    }
    if(session->next) {
        session->next->prev = session->prev;
    } else {
        g_ctx->bfd.sessions_tail = session->prev;
    }
    if(session->state == BFD_STATE_UP && g_ctx->bfd.sessions_up) {
        g_ctx->bfd.sessions_up--;
    }
    g_ctx->bfd.sessions_count--;
    timer_del(session->tx_timer);
    timer_del(session->detect_timer);
    while(session->clients) {
        client = session->clients;
        session->clients = client->next;
        free(client);
    }
    free(session->name);
    free(session->local_str);
    free(session->peer_str);
    free(session);
}

/* Clients may remove themselves or other clients of the
 * session in the callback, therefore the list is searched
 * again from the beginning after each callback. */
static void
bfd_session_notify(bfd_session_s *session, bfd_event_t event)
{
    bfd_client_s *client;

    for(client = session->clients; client; client = client->next) {
        client->notified = false;
    }
    session->notify = true;
    client = session->clients;
    while(client) {
        if(client->notified) {
            client = client->next;
            continue;
        }
        client->notified = true;
        if(client->cb) {
            client->cb(client->client, session, event);
        }
        client = session->clients;
    }
    session->notify = false;
}

/**
 * bfd_session_state_change
 *
 * @param session BFD session
 * @param state new state
 * @param diag local diagnostic code
 * @param notify notify clients if the session goes down
 */
static void
bfd_session_state_change(bfd_session_s *session, bfd_state_t state, uint8_t diag, bool notify)
{
    bfd_state_t old = session->state;

    if(old == state) return;

    LOG(BFD, "BFD (%s) state %s -> %s (%s)\n",
        bfd_session_name(session), bfd_state_string(old),
        bfd_state_string(state), bfd_diag_string(diag));

    session->state = state;
    session->local_diag = diag;
    clock_gettime(CLOCK_MONOTONIC, &session->state_timestamp);

    if(state == BFD_STATE_UP) {
        session->stats.up++;
        g_ctx->bfd.stats.up++;
        g_ctx->bfd.sessions_up++;
        if(session->desired_min_tx != session->config_tx_interval ||
           session->required_min_rx != session->config_rx_interval) {
            bfd_session_poll_start(session, session->config_tx_interval, session->config_rx_interval);
        }
    } else if(old == BFD_STATE_UP) {
        session->stats.down++;
        g_ctx->bfd.stats.down++;
        if(g_ctx->bfd.sessions_up) g_ctx->bfd.sessions_up--;
    }
    if(state < BFD_STATE_INIT) {
        bfd_session_slow(session);
        bfd_session_timers_update(session);
        timer_del(session->detect_timer);
    }

    /* Signal the state change immediately. */
    if(bfd_session_tx_allowed(session)) {
        bfd_session_send(session, false);
    }

    if(state == BFD_STATE_UP) {
        bfd_session_notify(session, BFD_EVENT_UP);
    } else if(old == BFD_STATE_UP && notify) {
        bfd_session_notify(session, BFD_EVENT_DOWN);
    }
}

static void
bfd_detect_job(timer_s *timer)
{
    bfd_session_s *session = timer->data;

    session->remote_discr = 0;
    session->remote_state = BFD_STATE_DOWN;
    session->remote_min_rx = 1;
    if(session->state == BFD_STATE_INIT || session->state == BFD_STATE_UP) {
        LOG(BFD, "BFD (%s) detection time expired\n", bfd_session_name(session));
        session->stats.timeout++;
        g_ctx->bfd.stats.timeout++;
        bfd_session_state_change(session, BFD_STATE_DOWN, BFD_DIAG_DETECTION_TIME_EXPIRED, true);
        if(session->deleted) {
            /* Deleted by a client during notification. */
            bfd_session_free(session);
        }
    }
}

static bfd_session_s *
bfd_session_add(bbl_network_interface_s *interface, bfd_profile_config_s *profile,
                bool multihop, uint8_t af, void *local, void *peer)
{
    bfd_session_s *session;
    dict_insert_result result;

    session = calloc(1, sizeof(bfd_session_s));
    if(!session) return NULL;

    session->id = ++g_ctx->bfd.next_id;
    session->interface = interface;
    session->profile = profile;
    session->multihop = multihop;
    session->ipv6 = af == AF_INET6;
    if(session->ipv6) {
        memcpy(session->local_ipv6, local, IPV6_ADDR_LEN);
        memcpy(session->peer_ipv6, peer, IPV6_ADDR_LEN);
        session->local_str = strdup(format_ipv6_address(&session->local_ipv6));
        session->peer_str = strdup(format_ipv6_address(&session->peer_ipv6));
    } else {
        session->local_ipv4 = *(uint32_t*)local;
        session->peer_ipv4 = *(uint32_t*)peer;
        session->local_str = strdup(format_ipv4_address(&session->local_ipv4));
        session->peer_str = strdup(format_ipv4_address(&session->peer_ipv4));
    }
    bfd_key_init(&session->key, interface, multihop, af, local, peer);

    session->src_port = BFD_SRC_PORT_MIN + ((session->id - 1) % BFD_SRC_PORT_RANGE);
    if(multihop) {
        session->min_ttl = profile->min_ttl_set ? profile->min_ttl : BFD_DEFAULT_MULTIHOP_MIN_TTL;
    } else {
        session->min_ttl = BFD_TTL;
    }
    session->passive = profile->passive;
    session->auth_type = profile->auth_type;
    session->xmit_auth_seq = rand();
    session->config_tx_interval = profile->tx_interval;
    session->config_rx_interval = profile->rx_interval;
    session->multiplier = profile->multiplier;

    session->state = BFD_STATE_DOWN;
    session->remote_state = BFD_STATE_DOWN;
    session->remote_min_rx = 1;
    session->local_discr = bfd_discr_alloc();
    bfd_session_slow(session);
    bfd_session_timers_update(session);
    clock_gettime(CLOCK_MONOTONIC, &session->state_timestamp);

    result = hb_tree_insert(g_ctx->bfd.discr_db, &session->local_discr);
    if(!result.inserted) {
        free(session);
        return NULL;
    }
    *result.datum_ptr = session;
    result = hb_tree_insert(g_ctx->bfd.key_db, &session->key);
    if(!result.inserted) {
        hb_tree_remove(g_ctx->bfd.discr_db, &session->local_discr);
        free(session);
        return NULL;
    }
    *result.datum_ptr = session;

    if(g_ctx->bfd.sessions_tail) {
        g_ctx->bfd.sessions_tail->next = session;
        session->prev = g_ctx->bfd.sessions_tail;
    } else {
        g_ctx->bfd.sessions = session;
    }
    g_ctx->bfd.sessions_tail = session;
    g_ctx->bfd.sessions_count++;

    LOG(BFD, "BFD (%s) add %s session (profile %u)\n",
        bfd_session_name(session), multihop ? "multi-hop" : "single-hop", profile->id);

    if(g_ctx->bfd.teardown) {
        session->state = BFD_STATE_ADMIN_DOWN;
        session->local_diag = BFD_DIAG_ADMIN_DOWN;
    }
    /* First packet with random delay to spread the TX load. */
    timer_add(&g_ctx->timer_root, &session->tx_timer, "BFD TX",
              0, (long)(rand() % 1000) * MSEC, session, &bfd_tx_job);
    return session;
}

static bool
bfd_ipv6_link_local(void *address)
{
    uint8_t *a = address;
    return a[0] == 0xfe && (a[1] & 0xc0) == 0x80;
}

/**
 * bfd_session_get
 *
 * Get existing session or add a new session.
 *
 * @param interface network interface
 * @param profile_id profile identifier (0 for defaults)
 * @param multihop multi-hop session (RFC 5883)
 * @param af address family (AF_INET or AF_INET6)
 * @param local local address (NULL for interface address)
 * @param peer peer address
 * @return session or NULL
 */
bfd_session_s *
bfd_session_get(bbl_network_interface_s *interface, uint16_t profile_id, bool multihop,
                uint8_t af, void *local, void *peer)
{
    bfd_profile_config_s *profile;
    bfd_key_s key;
    void **search;

    if(!interface || !peer) return NULL;
    if(!local) {
        if(af == AF_INET) {
            local = &interface->ip.address;
        } else if(bfd_ipv6_link_local(peer) || !ipv6_addr_not_zero(&interface->ip6.address)) {
            local = &interface->ip6_ll;
        } else {
            local = &interface->ip6.address;
        }
    }
    bfd_key_init(&key, interface, multihop, af, local, peer);
    search = hb_tree_search(g_ctx->bfd.key_db, &key);
    if(search) {
        return *search;
    }
    profile = bfd_profile_get(profile_id);
    if(!profile) {
        LOG(ERROR, "BFD profile %u not found\n", profile_id);
        return NULL;
    }
    return bfd_session_add(interface, profile, multihop, af, local, peer);
}

/**
 * bfd_session_client_add
 *
 * Add a client (e.g. routing protocol) to an existing
 * or new session. The profile of the first client is used.
 *
 * @return session or NULL
 */
bfd_session_s *
bfd_session_client_add(bbl_network_interface_s *interface, uint16_t profile_id, bool multihop,
                       uint8_t af, void *local, void *peer,
                       uint8_t type, void *client, bfd_client_cb cb)
{
    bfd_session_s *session;
    bfd_client_s *c;

    session = bfd_session_get(interface, profile_id, multihop, af, local, peer);
    if(!session) return NULL;

    c = session->clients;
    while(c) {
        if(c->client == client) return session;
        c = c->next;
    }
    c = calloc(1, sizeof(bfd_client_s));
    if(!c) return NULL;
    c->type = type;
    c->notified = session->notify; /* not notified about the current event */
    c->client = client;
    c->cb = cb;
    c->next = session->clients;
    session->clients = c;
    session->client_types |= type;
    session->deleted = false;
    LOG(BFD, "BFD (%s) add client %p (type %u)\n", bfd_session_name(session), client, type);
    return session;
}

/**
 * bfd_session_client_del
 *
 * Remove client from session, the session is deleted
 * with the last client (except static sessions).
 */
void
bfd_session_client_del(bfd_session_s *session, void *client)
{
    bfd_client_s *c, *prev = NULL;

    if(!session) return;
    c = session->clients;
    while(c) {
        if(c->client == client) {
            if(prev) {
                prev->next = c->next;
            } else {
                session->clients = c->next;
            }
            free(c);
            break;
        }
        prev = c;
        c = c->next;
    }
    session->client_types &= BFD_CLIENT_STATIC;
    for(c = session->clients; c; c = c->next) {
        session->client_types |= c->type;
    }
    if(session->clients || session->client_types & BFD_CLIENT_STATIC || session->deleted) {
        return;
    }

    LOG(BFD, "BFD (%s) delete session\n", bfd_session_name(session));
    if(session->state == BFD_STATE_UP || session->state == BFD_STATE_INIT) {
        /* Signal that the session is going away. */
        if(session->state == BFD_STATE_UP && g_ctx->bfd.sessions_up) {
            g_ctx->bfd.sessions_up--;
        }
        session->state = BFD_STATE_ADMIN_DOWN;
        session->local_diag = BFD_DIAG_ADMIN_DOWN;
        if(bfd_session_tx_allowed(session)) {
            bfd_session_send(session, false);
        }
    }
    session->deleted = true;
    if(!session->notify) {
        bfd_session_free(session);
    }
}

/**
 * bfd_session_enable
 *
 * Enable or disable (AdminDown) session.
 */
void
bfd_session_enable(bfd_session_s *session, bool enable)
{
    if(enable) {
        if(!session->admin_disabled) return;
        session->admin_disabled = false;
        bfd_session_state_change(session, BFD_STATE_DOWN, BFD_DIAG_NONE, false);
    } else {
        if(session->admin_disabled) return;
        session->admin_disabled = true;
        bfd_session_state_change(session, BFD_STATE_ADMIN_DOWN, BFD_DIAG_ADMIN_DOWN, false);
    }
}

/**
 * bfd_session_update
 *
 * Change session parameters, which starts a
 * poll sequence if the session is Up.
 *
 * @param tx_interval desired min TX interval in us (0 to keep)
 * @param rx_interval required min RX interval in us (0 to keep)
 * @param multiplier detect multiplier (0 to keep)
 */
void
bfd_session_update(bfd_session_s *session, uint32_t tx_interval, uint32_t rx_interval, uint8_t multiplier)
{
    if(tx_interval) session->config_tx_interval = tx_interval;
    if(rx_interval) session->config_rx_interval = rx_interval;
    if(multiplier) session->multiplier = multiplier;

    LOG(BFD, "BFD (%s) update tx-interval %ums rx-interval %ums multiplier %u\n",
        bfd_session_name(session), session->config_tx_interval/1000,
        session->config_rx_interval/1000, session->multiplier);

    if(session->state == BFD_STATE_UP) {
        bfd_session_poll_start(session, session->config_tx_interval, session->config_rx_interval);
        /* Start poll sequence immediately. */
        if(bfd_session_tx_allowed(session)) {
            bfd_session_send(session, false);
        }
    } else {
        bfd_session_slow(session);
        bfd_session_timers_update(session);
    }
}

static bfd_session_s *
bfd_session_lookup(bbl_network_interface_s *interface, bbl_bfd_s *bfd, bool multihop,
                   uint8_t af, void *local, void *peer)
{
    bfd_key_s key;
    void **search;

    if(bfd->your_discr) {
        search = hb_tree_search(g_ctx->bfd.discr_db, &bfd->your_discr);
    } else {
        /* Demultiplex by addresses (RFC 5880 6.3). */
        if(bfd->state != BFD_STATE_DOWN && bfd->state != BFD_STATE_ADMIN_DOWN) {
            return NULL;
        }
        bfd_key_init(&key, interface, multihop, af, local, peer);
        search = hb_tree_search(g_ctx->bfd.key_db, &key);
    }
    if(search) {
        return *search;
    }
    return NULL;
}

/**
 * bfd_rx
 *
 * Process BFD control packet (RFC 5880 6.8.6).
 */
void
bfd_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth,
       bbl_ipv4_s *ipv4, bbl_ipv6_s *ipv6, bbl_udp_s *udp)
{
    bbl_bfd_s *bfd = (bbl_bfd_s*)udp->next;
    bfd_session_s *session;
    bfd_profile_config_s *profile;
    bool multihop = udp->dst == BFD_UDP_PORT_MULTI_HOP;
    uint8_t ttl;
    uint8_t af;
    void *local;
    void *peer;
    uint32_t seq = 0;
    bfd_state_t state;
    struct timespec now = {0};
    struct timespec diff;

    g_ctx->bfd.stats.rx++;
    if(ipv6) {
        af = AF_INET6;
        ttl = ipv6->ttl;
        local = ipv6->dst;
        peer = ipv6->src;
    } else {
        af = AF_INET;
        ttl = ipv4->ttl;
        local = &ipv4->dst;
        peer = &ipv4->src;
    }

    if(!bfd_packet_valid(bfd) || (!multihop && ttl != BFD_TTL)) {
        g_ctx->bfd.stats.rx_error++;
        return;
    }

    session = bfd_session_lookup(interface, bfd, multihop, af, local, peer);
    if(!session) {
        g_ctx->bfd.stats.rx_no_session++;
        return;
    }
    if(session->deleted || session->multihop != multihop ||
       session->ipv6 != (af == AF_INET6) ||
       (!multihop && session->interface != interface) ||
       memcmp(session->key.peer, peer, af == AF_INET ? IPV4_ADDR_LEN : IPV6_ADDR_LEN) != 0 ||
       memcmp(session->key.local, local, af == AF_INET ? IPV4_ADDR_LEN : IPV6_ADDR_LEN) != 0 ||
       ttl < session->min_ttl) {
        session->stats.rx_error++;
        g_ctx->bfd.stats.rx_error++;
        return;
    }

    /* Authentication (RFC 5880 6.7) */
    profile = session->profile;
    if(session->auth_type) {
        if(session->auth_type != BFD_AUTH_SIMPLE) {
            clock_gettime(CLOCK_MONOTONIC, &now);
        }
        if(session->rcv_auth_seq_known && session->auth_type != BFD_AUTH_SIMPLE) {
            /* Forget the sequence number after two detection
             * times without valid packets (RFC 5880 6.8.1). */
            timespec_sub(&diff, &now, &session->rcv_auth_timestamp);
            if((uint64_t)diff.tv_sec * 1000000 + diff.tv_nsec / 1000 > 2ULL * session->detect_time) {
                session->rcv_auth_seq_known = false;
            }
        }
        if(!bfd_packet_auth_verify(bfd, session->auth_type, profile->auth_key_id,
                                   profile->auth_key, profile->auth_key_len, &seq) ||
           !bfd_auth_seq_check(session->auth_type, session->rcv_auth_seq_known,
                               session->rcv_auth_seq, seq, bfd->detect_mult)) {
            session->stats.rx_auth_error++;
            g_ctx->bfd.stats.rx_error++;
            return;
        }
        if(session->auth_type != BFD_AUTH_SIMPLE) {
            session->rcv_auth_seq = seq;
            session->rcv_auth_seq_known = true;
            session->rcv_auth_timestamp = now;
        }
    } else if(bfd->flags & BFD_FLAG_AUTH) {
        session->stats.rx_auth_error++;
        g_ctx->bfd.stats.rx_error++;
        return;
    }

    session->stats.rx++;
    if(!multihop) {
        memcpy(session->peer_mac, eth->src, ETH_ADDR_LEN);
        session->peer_mac_learned = true;
    }

    session->remote_discr = bfd->my_discr;
    session->remote_state = bfd->state;
    session->remote_diag = bfd->diag;
    session->remote_demand = bfd->flags & BFD_FLAG_DEMAND;
    session->remote_min_tx = bfd->desired_min_tx;
    session->remote_min_rx = bfd->required_min_rx;
    session->remote_multiplier = bfd->detect_mult;

    if(bfd->flags & BFD_FLAG_FINAL && session->poll) {
        bfd_session_poll_stop(session);
    } else {
        bfd_session_timers_update(session);
    }

    if(session->state == BFD_STATE_ADMIN_DOWN) {
        return;
    }
    bfd_detect_start(session);

    state = session->state;
    if(bfd->state == BFD_STATE_ADMIN_DOWN) {
        if(state != BFD_STATE_DOWN) {
            /* Peer AdminDown must not bring clients down (RFC 5882 3.2). */
            bfd_session_state_change(session, BFD_STATE_DOWN, BFD_DIAG_NEIGHBOR_DOWN, false);
        }
    } else if(state == BFD_STATE_DOWN) {
        if(bfd->state == BFD_STATE_DOWN) {
            bfd_session_state_change(session, BFD_STATE_INIT, BFD_DIAG_NONE, false);
        } else if(bfd->state == BFD_STATE_INIT) {
            bfd_session_state_change(session, BFD_STATE_UP, BFD_DIAG_NONE, false);
        }
    } else if(state == BFD_STATE_INIT) {
        if(bfd->state == BFD_STATE_INIT || bfd->state == BFD_STATE_UP) {
            bfd_session_state_change(session, BFD_STATE_UP, BFD_DIAG_NONE, false);
        }
    } else if(bfd->state == BFD_STATE_DOWN) {
        bfd_session_state_change(session, BFD_STATE_DOWN, BFD_DIAG_NEIGHBOR_DOWN, true);
    }

    if(session->deleted) {
        /* Deleted by a client during notification. */
        bfd_session_free(session);
        return;
    }
    if(bfd->flags & BFD_FLAG_POLL && bfd_session_tx_allowed(session)) {
        bfd_session_send(session, true);
    }
}

/**
 * bfd_init
 *
 * Init BFD and add all static sessions.
 */
bool
bfd_init()
{
    bfd_session_config_s *config = g_ctx->config.bfd_session_config;
    bbl_network_interface_s *interface;
    bfd_session_s *session;

    g_ctx->bfd.discr_db = hb_tree_new((dict_compare_func)bfd_discr_compare);
    g_ctx->bfd.key_db = hb_tree_new((dict_compare_func)bfd_key_compare);
    if(!(g_ctx->bfd.discr_db && g_ctx->bfd.key_db)) {
        return false;
    }
    /* Instances started in the same second use the same random seed. */
    g_ctx->bfd.next_discr = ((uint32_t)rand() << 8) ^ ((uint32_t)getpid() << 16) ^ 1;

    while(config) {
        interface = bbl_network_interface_get(config->network_interface);
        if(!interface) {
            LOG(ERROR, "Failed to add BFD session (network interface %s not found)\n",
                config->network_interface ? config->network_interface : "");
            return false;
        }
        if(config->ipv6) {
            session = bfd_session_get(interface, config->profile_id, config->multihop, AF_INET6,
                                      ipv6_addr_not_zero(&config->local_ipv6) ? &config->local_ipv6 : NULL,
                                      &config->peer_ipv6);
        } else {
            if(!config->local_ipv4 && !interface->ip.address) {
                LOG(ERROR, "Failed to add BFD session (no IPv4 address on network interface %s)\n",
                    interface->name);
                return false;
            }
            session = bfd_session_get(interface, config->profile_id, config->multihop, AF_INET,
                                      config->local_ipv4 ? &config->local_ipv4 : NULL,
                                      &config->peer_ipv4);
        }
        if(!session) {
            LOG_NOARG(ERROR, "Failed to add BFD session\n");
            return false;
        }
        if(session->client_types & BFD_CLIENT_STATIC) {
            LOG(ERROR, "Failed to add BFD session (duplicate %s)\n", bfd_session_name(session));
            return false;
        }
        session->client_types |= BFD_CLIENT_STATIC;
        if(config->name) {
            session->name = strdup(config->name);
        }
        config = config->next;
    }
    return true;
}

static void
bfd_teardown_job(timer_s *timer)
{
    bfd_session_s *session = g_ctx->bfd.sessions;
    UNUSED(timer);

    /* Repeat AdminDown in case the first packet was lost. */
    while(session) {
        if(session->state == BFD_STATE_ADMIN_DOWN && bfd_session_tx_allowed(session)) {
            bfd_session_send(session, false);
        }
        session = session->next;
    }
    if(g_ctx->routing_sessions) g_ctx->routing_sessions--;
}

/**
 * bfd_teardown
 *
 * Signal AdminDown for all sessions, the teardown
 * is delayed shortly to send the packets.
 */
void
bfd_teardown()
{
    bfd_session_s *session = g_ctx->bfd.sessions;

    if(g_ctx->bfd.teardown) return;
    g_ctx->bfd.teardown = true;
    if(session) {
        g_ctx->routing_sessions++;
        timer_add(&g_ctx->timer_root, &g_ctx->bfd.teardown_timer, "BFD TEARDOWN",
                  0, 200 * MSEC, NULL, &bfd_teardown_job);
    }
    while(session) {
        if(session->state != BFD_STATE_ADMIN_DOWN) {
            session->admin_disabled = true;
            bfd_session_state_change(session, BFD_STATE_ADMIN_DOWN, BFD_DIAG_ADMIN_DOWN, false);
        }
        session = session->next;
    }
}

static json_t *
bfd_clients_json(bfd_session_s *session)
{
    json_t *clients = json_array();
    if(session->client_types & BFD_CLIENT_STATIC) json_array_append_new(clients, json_string("static"));
    if(session->client_types & BFD_CLIENT_ISIS) json_array_append_new(clients, json_string("isis"));
    if(session->client_types & BFD_CLIENT_OSPFV2) json_array_append_new(clients, json_string("ospfv2"));
    if(session->client_types & BFD_CLIENT_OSPFV3) json_array_append_new(clients, json_string("ospfv3"));
    if(session->client_types & BFD_CLIENT_BGP) json_array_append_new(clients, json_string("bgp"));
    if(session->client_types & BFD_CLIENT_LDP) json_array_append_new(clients, json_string("ldp"));
    return clients;
}

json_t *
bfd_session_json(bfd_session_s *session)
{
    struct timespec now, diff;
    json_t *root;

    clock_gettime(CLOCK_MONOTONIC, &now);
    timespec_sub(&diff, &now, &session->state_timestamp);

    root = json_pack("{si ss* ss* ss ss sb ss ss ss sI sI ss ss si si sI sI sI sI sI sI si si sb sb ss so"
                     " s{sI sI sI sI sI si si si si}}",
                     "bfd-session-id", session->id,
                     "name", session->name,
                     "network-interface", session->interface ? session->interface->name : NULL,
                     "local-address", session->local_str,
                     "peer-address", session->peer_str,
                     "multihop", session->multihop,
                     "state", bfd_state_string(session->state),
                     "remote-state", bfd_state_string(session->remote_state),
                     "local-diagnostic", bfd_diag_string(session->local_diag),
                     "local-discriminator", (json_int_t)session->local_discr,
                     "remote-discriminator", (json_int_t)session->remote_discr,
                     "remote-diagnostic", bfd_diag_string(session->remote_diag),
                     "authentication-type", bfd_auth_type_string(session->auth_type),
                     "multiplier", session->multiplier,
                     "remote-multiplier", session->remote_multiplier,
                     "desired-min-tx-interval-us", (json_int_t)session->desired_min_tx,
                     "required-min-rx-interval-us", (json_int_t)session->required_min_rx,
                     "remote-desired-min-tx-interval-us", (json_int_t)session->remote_min_tx,
                     "remote-required-min-rx-interval-us", (json_int_t)session->remote_min_rx,
                     "tx-interval-us", (json_int_t)session->tx_interval,
                     "detection-time-us", (json_int_t)session->detect_time,
                     "state-seconds", (int)diff.tv_sec,
                     "min-ttl", session->min_ttl,
                     "passive", session->passive,
                     "poll", session->poll,
                     "admin-state", session->admin_disabled ? "disabled" : "enabled",
                     "clients", bfd_clients_json(session),
                     "stats",
                     "tx-packets", (json_int_t)session->stats.tx,
                     "tx-errors", (json_int_t)session->stats.tx_error,
                     "rx-packets", (json_int_t)session->stats.rx,
                     "rx-errors", (json_int_t)session->stats.rx_error,
                     "rx-auth-errors", (json_int_t)session->stats.rx_auth_error,
                     "up", session->stats.up,
                     "down", session->stats.down,
                     "timeout", session->stats.timeout,
                     "poll-sequences", session->stats.poll);
    return root;
}
