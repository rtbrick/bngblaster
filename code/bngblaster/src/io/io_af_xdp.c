/*
 * BNG Blaster (BBL) - IO AF_XDP Functions (EXPERIMENTAL/WIP)
 *
 * AF_XDP is a Linux kernel socket family that allows userspace to receive
 * and send raw Ethernet frames directly from/to a NIC driver queue via a
 * shared memory region (UMEM) and lock-free ring buffers, bypassing most
 * of the regular network stack. Unlike DPDK it works with the unmodified
 * kernel driver of the NIC and leaves the interface attached to the Linux
 * network stack, which makes it a good alternative for setups where DPDK
 * (dedicated driver binding, hugepages, ...) is not an option.
 *
 * This implementation uses libbpf (bpf/xsk.h) which takes care of loading
 * the default XDP program redirecting packets into the AF_XDP socket of
 * the matching queue.
 *
 * RX and TX each get their own disjoint range of NIC queue indices - e.g.
 * with rx-threads 5 and tx-threads 1, RX uses queues 0-4 and TX uses queue
 * 5, never sharing a queue between the two directions. This is deliberate:
 * a "combined" queue (RX ring and TX ring on the same socket/queue index)
 * would have RX and TX processing for that queue share a single NAPI/IRQ
 * context, so heavy TX load can delay that same queue's own RX servicing
 * (and vice versa) - showing up as RX drops unrelated to actual RX
 * capacity. Each queue gets its own independent UMEM (no XDP_SHARED_UMEM
 * is needed for this) and its own RX-only or TX-only io_af_xdp_queue_s.
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

#ifdef BNGBLASTER_AF_XDP

#include <bpf/xsk.h>
#include <linux/if_link.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define AF_XDP_BURST 256

extern bool g_init_phase;
extern bool g_traffic;

typedef enum {
    AF_XDP_Q_COMBINED, /* RX and TX both bound to this queue */
    AF_XDP_Q_RX_ONLY,
    AF_XDP_Q_TX_ONLY,
} io_af_xdp_qmode_t;

typedef struct io_af_xdp_queue_ {
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    void *umem_area;
    uint64_t umem_size;

    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;

    uint32_t frame_size;
    uint32_t rx_frames; /* fill/rx ring capacity, also number of RX frames */
    uint32_t tx_frames; /* comp/tx ring capacity, also number of TX frames */

    /* Stack of free TX frame addresses (upper half of the UMEM). */
    uint64_t *tx_free;
    uint32_t tx_free_count;

    int fd;
    uint32_t queue_id;
} io_af_xdp_queue_s;

/* Conservative worst-case per-packet overhead (double VLAN tag, ...) added
 * on top of the interface MTU when checking it against the AF_XDP frame
 * size. AF_XDP has no multi-buffer support here, so a single UMEM frame
 * must be able to hold an entire received frame or the driver will refuse
 * to attach (native mode) or frames will be dropped (generic mode). */
#define AF_XDP_MTU_OVERHEAD 128

static uint32_t
next_pow2(uint32_t v)
{
    uint32_t p = 2;
    if(v <= 2) {
        return 2;
    }
    while(p < v) {
        p <<= 1;
    }
    return p;
}

/**
 * AF_XDP has no multi-buffer support here, so the interface MTU must fit
 * within a single UMEM frame (XSK_UMEM__DEFAULT_FRAME_SIZE, 4096 byte).
 * Interfaces are commonly left at a larger (e.g. jumbo) MTU for other
 * purposes even though BNG Blaster itself never sends packets that large
 * unless jumbo-frames is enabled (which is already rejected for AF_XDP),
 * so check this explicitly and fail with a clear, actionable message
 * instead of a confusing low-level bind/attach error.
 */
static bool
io_af_xdp_check_mtu(bbl_interface_s *interface)
{
    struct ifreq ifr = {0};
    int fd;
    int mtu;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        return true; /* best effort, do not block on this check */
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if(ioctl(fd, SIOCGIFMTU, &ifr) == -1) {
        close(fd);
        return true;
    }
    close(fd);
    mtu = ifr.ifr_mtu;

    if((uint32_t)mtu + AF_XDP_MTU_OVERHEAD > XSK_UMEM__DEFAULT_FRAME_SIZE) {
        LOG(ERROR, "AF_XDP: interface %s has MTU %d which does not fit into the "
            "%u byte AF_XDP frame size, please lower the interface MTU "
            "(e.g. 'ip link set %s mtu 1500')\n",
            interface->name, mtu, XSK_UMEM__DEFAULT_FRAME_SIZE, interface->name);
        return false;
    }
    return true;
}

/**
 * AF_XDP binds sockets to specific queue indices (0..queues-1), and the
 * NIC's RSS engine hashes every flow to one fixed hardware queue out of
 * however many are currently configured on the interface. If the NIC has
 * more queues configured than bngblaster binds AF_XDP sockets to, flows
 * that hash to one of the unbound queues are simply XDP_PASS-ed to the
 * normal kernel stack instead of being redirected to us - which looks
 * like silent, deterministic RX loss for the affected flows and is very
 * hard to diagnose after the fact. So configure the interface to exactly
 * as many combined queues as we need, the same way the DPDK backend pins
 * the exact queue count via rte_eth_dev_configure().
 */
static bool
io_af_xdp_set_channels(bbl_interface_s *interface, uint32_t queues)
{
    struct ifreq ifr = {0};
    struct ethtool_channels ch = {0};
    int fd;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        return true; /* best effort, do not block on this check */
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);

    ch.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void*)&ch;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        /* Driver does not support ethtool channel queries (e.g. some
         * virtual interfaces) - nothing we can/need to do. */
        close(fd);
        return true;
    }

    if(ch.max_combined) {
        uint32_t old_combined = ch.combined_count;
        if(old_combined == queues) {
            close(fd);
            return true;
        }
        if(queues > ch.max_combined) {
            LOG(ERROR, "AF_XDP: interface %s only supports up to %u combined queues, "
                "but %u are required by rx-threads/tx-threads\n",
                interface->name, ch.max_combined, queues);
            close(fd);
            return false;
        }
        ch.cmd = ETHTOOL_SCHANNELS;
        ch.combined_count = queues;
        if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
            LOG(ERROR, "AF_XDP: failed to reconfigure interface %s to %u combined "
                "queue%s (%s), please configure it manually "
                "(e.g. 'ethtool -L %s combined %u')\n",
                interface->name, queues, queues == 1 ? "" : "s", strerror(errno),
                interface->name, queues);
            close(fd);
            return false;
        }
        LOG(AFXDP, "AF_XDP: interface %s reconfigured to %u combined queue%s "
            "(was %u)\n", interface->name, queues, queues == 1 ? "" : "s",
            old_combined);
    } else if(ch.max_rx && ch.max_tx) {
        if(ch.rx_count == queues && ch.tx_count == queues) {
            close(fd);
            return true;
        }
        if(queues > ch.max_rx || queues > ch.max_tx) {
            LOG(ERROR, "AF_XDP: interface %s only supports up to %u RX / %u TX queues, "
                "but %u are required by rx-threads/tx-threads\n",
                interface->name, ch.max_rx, ch.max_tx, queues);
            close(fd);
            return false;
        }
        ch.cmd = ETHTOOL_SCHANNELS;
        ch.rx_count = queues;
        ch.tx_count = queues;
        if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
            LOG(ERROR, "AF_XDP: failed to reconfigure interface %s to %u RX/TX "
                "queues (%s), please configure it manually "
                "(e.g. 'ethtool -L %s rx %u tx %u')\n",
                interface->name, queues, strerror(errno), interface->name, queues, queues);
            close(fd);
            return false;
        }
        LOG(AFXDP, "AF_XDP: interface %s reconfigured to %u RX/TX queues\n",
            interface->name, queues);
    }
    close(fd);
    return true;
}

/**
 * ethtool -L (channel count) only controls how many hardware queues exist;
 * it does not stop RSS from distributing incoming traffic across ALL of
 * them, including the TX-only queues bngblaster deliberately does not bind
 * an RX ring to. Without further constraint, any flow that happens to hash
 * to a TX-only queue is XDP_PASS-ed to the normal kernel stack instead of
 * being redirected to bngblaster - i.e. invisible RX loss, up to and
 * including 100% loss for a single-flow test unlucky enough to land there.
 * The RSS indirection table (ethtool -X) is what actually controls which
 * queues RSS is allowed to target, so remap every entry pointing at a
 * TX-only queue (index >= rx_queues) back into the RX range.
 */
static bool
io_af_xdp_constrain_rss(bbl_interface_s *interface, uint32_t rx_queues, uint32_t total_queues)
{
    struct ifreq ifr = {0};
    struct ethtool_rxfh size_probe = {0};
    struct ethtool_rxfh *rxfh;
    uint32_t *indir;
    uint8_t *buf;
    size_t buf_len;
    int fd;
    uint32_t i;
    bool changed = false;

    if(rx_queues >= total_queues) {
        /* No TX-only queue exists, nothing for RSS to avoid. */
        return true;
    }

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        return true; /* best effort */
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);

    size_probe.cmd = ETHTOOL_GRSSH;
    ifr.ifr_data = (void*)&size_probe;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        /* Driver exposes multiple queues but not the RSS indirection
         * table - we cannot verify TX-only queues are excluded from RSS,
         * so fail loudly instead of risking silent per-flow RX loss. */
        LOG(ERROR, "AF_XDP: interface %s does not support querying the RSS "
            "indirection table (%s), cannot guarantee that TX-only queue%s "
            "%u-%u are excluded from RX traffic distribution\n",
            interface->name, strerror(errno), total_queues - rx_queues == 1 ? "" : "s",
            rx_queues, total_queues - 1);
        close(fd);
        return false;
    }
    if(size_probe.indir_size == 0) {
        /* No indirection table on this driver/NIC - nothing to constrain. */
        close(fd);
        return true;
    }

    buf_len = sizeof(struct ethtool_rxfh) + (size_t)size_probe.indir_size * sizeof(uint32_t)
              + size_probe.key_size;
    buf = calloc(1, buf_len);
    if(!buf) {
        close(fd);
        return true; /* best effort */
    }
    rxfh = (struct ethtool_rxfh*)buf;
    rxfh->cmd = ETHTOOL_GRSSH;
    rxfh->indir_size = size_probe.indir_size;
    rxfh->key_size = size_probe.key_size;

    ifr.ifr_data = (void*)rxfh;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        LOG(ERROR, "AF_XDP: interface %s failed to read the RSS indirection table (%s)\n",
            interface->name, strerror(errno));
        free(buf);
        close(fd);
        return false;
    }

    /* rss_config holds indir_size u32 indirection entries, followed by
     * key_size byte of hash key (left untouched below). */
    indir = rxfh->rss_config;
    for(i = 0; i < rxfh->indir_size; i++) {
        if(indir[i] >= rx_queues) {
            indir[i] = indir[i] % rx_queues;
            changed = true;
        }
    }
    if(!changed) {
        free(buf);
        close(fd);
        return true;
    }

    rxfh->cmd = ETHTOOL_SRSSH;
    rxfh->rss_context = 0;
    ifr.ifr_data = (void*)rxfh;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to constrain the RSS indirection table on interface %s "
            "to the first %u queue%s (%s), please configure it manually "
            "(e.g. 'ethtool -X %s equal %u')\n",
            interface->name, rx_queues, rx_queues == 1 ? "" : "s", strerror(errno),
            interface->name, rx_queues);
        free(buf);
        close(fd);
        return false;
    }

    LOG(AFXDP, "AF_XDP: interface %s RSS indirection table constrained to queue%s 0-%u "
        "(queue%s %u-%u reserved for TX only, excluded from RX distribution)\n",
        interface->name, rx_queues == 1 ? "" : "s", rx_queues - 1,
        total_queues - rx_queues == 1 ? "" : "s", rx_queues, total_queues - 1);

    free(buf);
    close(fd);
    return true;
}

static void
io_af_xdp_queue_destroy(io_af_xdp_queue_s *q)
{
    if(!q) return;
    if(q->xsk) xsk_socket__delete(q->xsk);
    if(q->umem) xsk_umem__delete(q->umem);
    free(q->tx_free);
    free(q->umem_area);
    free(q);
}

/**
 * Seed the fill ring with every RX frame address so the kernel has buffers
 * to receive into. This must happen before the socket is bound (i.e.
 * before xsk_socket__create()), since binding is what makes the kernel
 * start steering packets to this socket - seeding it afterwards leaves a
 * window where inbound packets find an empty fill ring and get dropped
 * (visible as non-zero rx_fill_ring_empty_descs even though nothing was
 * ever handed to bngblaster).
 */
static bool
io_af_xdp_seed_fill(io_af_xdp_queue_s *q)
{
    uint32_t idx = 0;
    uint32_t i;

    if(xsk_ring_prod__reserve(&q->fill, q->rx_frames, &idx) != q->rx_frames) {
        return false;
    }
    for(i = 0; i < q->rx_frames; i++) {
        *xsk_ring_prod__fill_addr(&q->fill, idx + i) = (uint64_t)i * q->frame_size;
    }
    xsk_ring_prod__submit(&q->fill, q->rx_frames);
    return true;
}

static bool
io_af_xdp_queue_create(bbl_interface_s *interface, uint32_t queue_id, io_af_xdp_qmode_t qmode,
                        io_af_xdp_queue_s **queue_out)
{
    bbl_link_config_s *config = interface->config;
    io_af_xdp_queue_s *q;
    struct xsk_umem_config umem_cfg = {0};
    struct xsk_socket_config sock_cfg = {0};
    struct xsk_ring_cons *rx_ring;
    struct xsk_ring_prod *tx_ring;
    uint32_t page_size = getpagesize();
    bool want_rx = (qmode != AF_XDP_Q_TX_ONLY);
    bool want_tx = (qmode != AF_XDP_Q_RX_ONLY);
    uint32_t i;
    int ret;

    q = calloc(1, sizeof(io_af_xdp_queue_s));
    if(!q) {
        return false;
    }

    q->frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
    /* The UMEM always reserves space for both a fill and a completion
     * ring (they belong to the UMEM, not to a socket's RX/TX bind), but
     * a direction this queue does not use only needs the kernel-enforced
     * minimum ring size instead of the full configured slot count. */
    q->rx_frames = want_rx ? next_pow2(config->io_slots_rx) : 2;
    q->tx_frames = want_tx ? next_pow2(config->io_slots_tx) : 2;
    q->queue_id = queue_id;

    q->umem_size = (uint64_t)(q->rx_frames + q->tx_frames) * q->frame_size;
    if(posix_memalign(&q->umem_area, page_size, q->umem_size) != 0 || !q->umem_area) {
        LOG(ERROR, "AF_XDP: failed to allocate %lu byte UMEM for interface %s queue %u\n",
            (unsigned long)q->umem_size, interface->name, queue_id);
        io_af_xdp_queue_destroy(q);
        return false;
    }

    if(want_tx) {
        /* Seed the TX free-frame stack with every TX frame address. TX
         * frames occupy the upper half of the UMEM, RX frames the lower
         * half (or all of it, if this queue is TX-only). */
        q->tx_free = malloc(q->tx_frames * sizeof(uint64_t));
        if(!q->tx_free) {
            io_af_xdp_queue_destroy(q);
            return false;
        }
        for(i = 0; i < q->tx_frames; i++) {
            q->tx_free[i] = (uint64_t)(q->rx_frames + i) * q->frame_size;
        }
        q->tx_free_count = q->tx_frames;
    }

    umem_cfg.fill_size = q->rx_frames;
    umem_cfg.comp_size = q->tx_frames;
    umem_cfg.frame_size = q->frame_size;
    umem_cfg.frame_headroom = 0;
    umem_cfg.flags = 0;

    ret = xsk_umem__create(&q->umem, q->umem_area, q->umem_size, &q->fill, &q->comp, &umem_cfg);
    if(ret) {
        LOG(ERROR, "AF_XDP: failed to create UMEM for interface %s queue %u (error %d)\n",
            interface->name, queue_id, ret);
        io_af_xdp_queue_destroy(q);
        return false;
    }
    if(want_rx && !io_af_xdp_seed_fill(q)) {
        LOG(ERROR, "AF_XDP: failed to seed fill ring for interface %s queue %u\n",
            interface->name, queue_id);
        io_af_xdp_queue_destroy(q);
        return false;
    }

    /* A NULL ring pointer (with the matching *_size left at 0) tells
     * libbpf to not set up that direction at all, giving us an RX-only
     * or TX-only socket as needed - each queue still gets its own
     * independent UMEM, no XDP_SHARED_UMEM is required for this. */
    rx_ring = want_rx ? &q->rx : NULL;
    tx_ring = want_tx ? &q->tx : NULL;
    sock_cfg.rx_size = want_rx ? q->rx_frames : 0;
    sock_cfg.tx_size = want_tx ? q->tx_frames : 0;
    sock_cfg.libbpf_flags = 0;
    sock_cfg.bind_flags = XDP_USE_NEED_WAKEUP;

    /* Prefer native (driver) mode for the best performance and fall back
     * to generic (SKB) mode transparently, e.g. for virtual interfaces
     * (veth, ...) or drivers without native XDP support. A failed native
     * attempt can leave the UMEM/xsk in a state some libbpf versions do
     * not fully unwind, so the fallback attempt is done against a freshly
     * created UMEM rather than reusing the one from the failed attempt. */
    sock_cfg.xdp_flags = XDP_FLAGS_DRV_MODE;
    ret = xsk_socket__create(&q->xsk, interface->name, queue_id, q->umem, rx_ring, tx_ring, &sock_cfg);
    if(ret) {
        LOG(DEBUG, "AF_XDP: native mode not available for interface %s queue %u (error %d), "
            "falling back to generic (SKB) mode\n", interface->name, queue_id, ret);

        q->xsk = NULL;
        xsk_umem__delete(q->umem);
        q->umem = NULL;
        memset(&q->fill, 0, sizeof(q->fill));
        memset(&q->comp, 0, sizeof(q->comp));
        memset(&q->rx, 0, sizeof(q->rx));
        memset(&q->tx, 0, sizeof(q->tx));

        ret = xsk_umem__create(&q->umem, q->umem_area, q->umem_size, &q->fill, &q->comp, &umem_cfg);
        if(ret) {
            LOG(ERROR, "AF_XDP: failed to re-create UMEM for interface %s queue %u (error %d)\n",
                interface->name, queue_id, ret);
            io_af_xdp_queue_destroy(q);
            return false;
        }
        if(want_rx && !io_af_xdp_seed_fill(q)) {
            LOG(ERROR, "AF_XDP: failed to seed fill ring for interface %s queue %u\n",
                interface->name, queue_id);
            io_af_xdp_queue_destroy(q);
            return false;
        }

        sock_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        ret = xsk_socket__create(&q->xsk, interface->name, queue_id, q->umem, rx_ring, tx_ring, &sock_cfg);
    }
    if(ret) {
        LOG(ERROR, "AF_XDP: failed to create socket for interface %s queue %u (error %d) - "
            "possible causes: not enough RX/TX queues on the interface, an XDP "
            "program already attached to it, or missing CAP_NET_RAW/CAP_BPF privileges\n",
            interface->name, queue_id, ret);
        io_af_xdp_queue_destroy(q);
        return false;
    }
    q->fd = xsk_socket__fd(q->xsk);

    {
        /* Zero-copy is what makes native mode actually fast - if the
         * driver silently fell back to copy mode (e.g. because of a
         * feature/queue-config mismatch) every packet pays a memcpy on
         * top of the regular native-mode path, which can turn into real
         * loss at line rate on a fast link. Surface it so this is visible
         * instead of only showing up as an unexplained drop rate. */
        struct xdp_options opts = {0};
        socklen_t optlen = sizeof(opts);
        const char *copy_mode = "unknown";
        if(getsockopt(q->fd, SOL_XDP, XDP_OPTIONS, &opts, &optlen) == 0) {
            copy_mode = (opts.flags & XDP_OPTIONS_ZEROCOPY) ? "zero-copy" : "copy";
        }
        LOG(AFXDP, "AF_XDP: interface %s queue %u bound (%s mode, %s, %s, %u RX / %u TX frames of %u byte)\n",
            interface->name, queue_id, sock_cfg.xdp_flags == XDP_FLAGS_SKB_MODE ? "generic" : "native",
            copy_mode,
            qmode == AF_XDP_Q_COMBINED ? "RX+TX" : (qmode == AF_XDP_Q_RX_ONLY ? "RX only" : "TX only"),
            want_rx ? q->rx_frames : 0, want_tx ? q->tx_frames : 0, q->frame_size);
    }

    *queue_out = q;
    return true;
}

static void
io_af_xdp_refill(io_af_xdp_queue_s *q, uint64_t *addrs, uint32_t n)
{
    uint32_t idx = 0;
    uint32_t i;

    if(!n) return;

    /* The fill ring has exactly as many slots as there are RX frames, and
     * we only ever refill as many frames as we just consumed from the RX
     * ring, so this reservation cannot fail in practice. */
    if(xsk_ring_prod__reserve(&q->fill, n, &idx) != n) {
        return;
    }
    for(i = 0; i < n; i++) {
        *xsk_ring_prod__fill_addr(&q->fill, idx + i) = addrs[i];
    }
    xsk_ring_prod__submit(&q->fill, n);
    if(xsk_ring_prod__needs_wakeup(&q->fill)) {
        /* The driver may be sleeping waiting for fill ring entries. */
        recvfrom(q->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    }
}

static void
io_af_xdp_reap(io_af_xdp_queue_s *q)
{
    const __u64 *addr;
    uint32_t idx = 0;
    uint32_t n;
    uint32_t i;

    n = xsk_ring_cons__peek(&q->comp, q->tx_frames, &idx);
    if(!n) return;
    for(i = 0; i < n; i++) {
        addr = xsk_ring_cons__comp_addr(&q->comp, idx + i);
        q->tx_free[q->tx_free_count++] = *addr;
    }
    xsk_ring_cons__release(&q->comp, n);
}

/**
 * This job is for AF_XDP RX in main thread!
 */
void
io_af_xdp_rx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;
    io_af_xdp_queue_s *q = io->af_xdp_queue;

    bbl_ethernet_header_s *eth;
    const struct xdp_desc *desc;
    uint64_t addrs[AF_XDP_BURST];
    uint32_t idx_rx = 0;
    uint32_t rcvd;
    uint32_t i;

    protocol_error_t decode_result;
    bool pcap = false;

    assert(io->mode == IO_MODE_AF_XDP);
    assert(io->direction == IO_INGRESS);
    assert(io->thread == NULL);

    /* Get RX timestamp */
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;

    while((rcvd = xsk_ring_cons__peek(&q->rx, AF_XDP_BURST, &idx_rx))) {
        for(i = 0; i < rcvd; i++) {
            desc = xsk_ring_cons__rx_desc(&q->rx, idx_rx + i);
            addrs[i] = desc->addr;
            io->buf = xsk_umem__get_data(q->umem_area, desc->addr);
            io->buf_len = desc->len;
            io->stats.packets++;
            io->stats.bytes += io->buf_len;
            decode_result = decode_ethernet(io->buf, io->buf_len, g_ctx->sp, SCRATCHPAD_LEN, &eth);
            if(decode_result == PROTOCOL_SUCCESS) {
                /* Copy RX timestamp */
                eth->timestamp.tv_sec = io->timestamp.tv_sec;
                eth->timestamp.tv_nsec = io->timestamp.tv_nsec;
                /* Dump the packet into pcap file */
                if(g_ctx->pcap.write_buf && (!eth->bbl || g_ctx->pcap.include_streams)) {
                    pcap = true;
                    pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                              interface->ifindex, PCAPNG_EPB_FLAGS_INBOUND);
                }
                bbl_rx_handler(interface, eth);
            } else {
                /* Dump the packet into pcap file */
                if(g_ctx->pcap.write_buf) {
                    pcap = true;
                    pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                              interface->ifindex, PCAPNG_EPB_FLAGS_INBOUND);
                }
                if(decode_result == UNKNOWN_PROTOCOL) {
                    io->stats.unknown++;
                } else {
                    io->stats.protocol_errors++;
                }
            }
        }
        xsk_ring_cons__release(&q->rx, rcvd);
        io_af_xdp_refill(q, addrs, rcvd);
    }
    if(pcap) {
        pcapng_fflush();
    }
}

/**
 * This job is for AF_XDP TX in main thread!
 */
void
io_af_xdp_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;
    io_af_xdp_queue_s *q = io->af_xdp_queue;

    bbl_stream_s *stream = NULL;
    struct xdp_desc *desc;
    uint16_t burst = interface->config->io_burst;
    uint64_t now;
    uint64_t addr;
    uint32_t tidx = 0;

    bool ctrl = true;
    bool pcap = false;

    assert(io->mode == IO_MODE_AF_XDP);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    if(io->update_streams) {
        io_stream_update_pps(io);
    }

    io_af_xdp_reap(q);

    /* Get TX timestamp */
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;
    now = timespec_to_nsec(timer->timestamp);

    while(burst) {
        if(!q->tx_free_count) {
            io->stats.no_buffer++;
            break;
        }
        /* Peek (without popping) the next free TX frame so we have a
         * buffer to build the packet into. It is only actually consumed
         * once we know we have a packet to send. */
        addr = q->tx_free[q->tx_free_count - 1];
        io->buf = xsk_umem__get_data(q->umem_area, addr);

        if(unlikely(ctrl)) {
            /* First send all control traffic which has higher priority. */
            if(bbl_tx(interface, io->buf, &io->buf_len) != PROTOCOL_SUCCESS) {
                ctrl = false;
                continue;
            }
        } else {
            if(!(g_traffic && g_init_phase == false && interface->state == INTERFACE_UP)) {
                bbl_stream_io_stop(io);
                break;
            }
            stream = bbl_stream_io_send_iter(io, now);
            if(unlikely(stream == NULL)) {
                break;
            }
            memcpy(io->buf, stream->tx_buf, stream->tx_len);
            io->buf_len = stream->tx_len;
        }

        if(unlikely(xsk_ring_prod__reserve(&q->tx, 1, &tidx) != 1)) {
            /* Cannot happen in practice since the TX ring has exactly as
             * many slots as there are TX frames tracked by tx_free. Stream
             * counters are only touched below, once the packet is actually
             * queued, so no flow_seq is burned for a packet that never
             * made it onto the ring. */
            io->stats.no_buffer++;
            break;
        }
        q->tx_free_count--;
        desc = xsk_ring_prod__tx_desc(&q->tx, tidx);
        desc->addr = addr;
        desc->len = io->buf_len;
        desc->options = 0;
        xsk_ring_prod__submit(&q->tx, 1);

        if(!ctrl && stream) {
            stream->tx_packets++;
            stream->flow_seq++;
        }
        io->queued++;
        io->stats.packets++;
        io->stats.bytes += io->buf_len;
        burst--;

        /* Dump the packet into pcap file. */
        if(g_ctx->pcap.write_buf && (ctrl || g_ctx->pcap.include_streams)) {
            pcap = true;
            pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                      interface->ifindex, PCAPNG_EPB_FLAGS_OUTBOUND);
        }
    }

    if(io->queued) {
        if(xsk_ring_prod__needs_wakeup(&q->tx)) {
            sendto(q->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
        io->queued = 0;
    }
    if(pcap) {
        pcapng_fflush();
    }
}

void
io_af_xdp_thread_rx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;
    io_af_xdp_queue_s *q = io->af_xdp_queue;

    const struct xdp_desc *desc;
    uint64_t addrs[AF_XDP_BURST];
    uint32_t idx_rx = 0;
    uint32_t rcvd;
    uint32_t i;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 10000; /* 0.01ms */

    /* See io_packet_mmap_thread_rx_run_fn() for the rationale behind only
     * backing off after many consecutive empty rounds. */
    uint32_t idle_rounds = 0;
    const uint32_t idle_spin_rounds = 10000;

    assert(io->mode == IO_MODE_AF_XDP);
    assert(io->direction == IO_INGRESS);
    assert(io->thread);

    while(thread->active) {
        rcvd = xsk_ring_cons__peek(&q->rx, AF_XDP_BURST, &idx_rx);
        if(!rcvd) {
            if(++idle_rounds >= idle_spin_rounds) {
                nanosleep(&sleep, &rem);
                idle_rounds = 0;
            }
            continue;
        }
        idle_rounds = 0;

        /* Get RX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        for(i = 0; i < rcvd; i++) {
            desc = xsk_ring_cons__rx_desc(&q->rx, idx_rx + i);
            addrs[i] = desc->addr;
            io->buf = xsk_umem__get_data(q->umem_area, desc->addr);
            io->buf_len = desc->len;
            io->vlan_tci = 0;
            /* Process packet */
            io_thread_rx_handler(thread, io);
        }
        xsk_ring_cons__release(&q->rx, rcvd);
        io_af_xdp_refill(q, addrs, rcvd);
    }
}

void
io_af_xdp_thread_tx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;
    bbl_interface_s *interface = io->interface;
    io_af_xdp_queue_s *q = io->af_xdp_queue;

    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *slot;

    bbl_stream_s *stream = NULL;
    struct xdp_desc *desc;
    uint16_t io_burst = interface->config->io_burst;
    uint16_t burst = 0;
    uint64_t now;
    uint64_t addr;
    uint32_t tidx = 0;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 10000; /* 0.01ms */

    /* See io_packet_mmap_thread_tx_run_fn() for the rationale behind only
     * backing off after many consecutive empty rounds. */
    uint32_t idle_rounds = 0;
    const uint32_t idle_spin_rounds = 10000;

    assert(io->mode == IO_MODE_AF_XDP);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    while(thread->active) {
        if(io->update_streams) {
            io_stream_update_pps(io);
        }

        io_af_xdp_reap(q);

        burst = io_burst;

        /* First send all control traffic which has higher priority. */
        while(burst && (slot = bbl_txq_read_slot(txq))) {
            if(!q->tx_free_count) {
                io->stats.no_buffer++;
                break;
            }
            addr = q->tx_free[q->tx_free_count - 1];
            io->buf = xsk_umem__get_data(q->umem_area, addr);
            memcpy(io->buf, slot->packet, slot->packet_len);

            if(unlikely(xsk_ring_prod__reserve(&q->tx, 1, &tidx) != 1)) {
                io->stats.no_buffer++;
                break;
            }
            q->tx_free_count--;
            desc = xsk_ring_prod__tx_desc(&q->tx, tidx);
            desc->addr = addr;
            desc->len = slot->packet_len;
            desc->options = 0;
            xsk_ring_prod__submit(&q->tx, 1);

            io->stats.packets++;
            io->stats.bytes += slot->packet_len;
            io->queued++;
            bbl_txq_read_next(txq);
            burst--;
        }

        /* Get TX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);

        if(g_traffic && g_init_phase == false && interface->state == INTERFACE_UP) {
            now = timespec_to_nsec(&io->timestamp);
            while(burst) {
                if(!q->tx_free_count) {
                    io->stats.no_buffer++;
                    break;
                }
                /* Send traffic streams up to allowed burst. */
                stream = bbl_stream_io_send_iter(io, now);
                if(unlikely(stream == NULL)) {
                    break;
                }
                addr = q->tx_free[q->tx_free_count - 1];
                io->buf = xsk_umem__get_data(q->umem_area, addr);
                memcpy(io->buf, stream->tx_buf, stream->tx_len);

                if(unlikely(xsk_ring_prod__reserve(&q->tx, 1, &tidx) != 1)) {
                    io->stats.dropped++;
                    break;
                }
                q->tx_free_count--;
                desc = xsk_ring_prod__tx_desc(&q->tx, tidx);
                desc->addr = addr;
                desc->len = stream->tx_len;
                desc->options = 0;
                xsk_ring_prod__submit(&q->tx, 1);

                stream->tx_packets++;
                stream->flow_seq++;
                io->stats.packets++;
                io->stats.bytes += stream->tx_len;
                io->queued++;
                burst--;
            }
        } else {
            bbl_stream_io_stop(io);
        }

        if(io->queued) {
            idle_rounds = 0;
            if(xsk_ring_prod__needs_wakeup(&q->tx)) {
                sendto(q->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
            }
            io->queued = 0;
        } else if(++idle_rounds >= idle_spin_rounds) {
            nanosleep(&sleep, &rem);
            idle_rounds = 0;
        }
    }
}

bool
io_af_xdp_interface_init(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;

    uint16_t rx_threads = config->rx_threads;
    uint16_t tx_threads = config->tx_threads;
    /* RX and TX each get their own disjoint range of NIC queue indices -
     * queue N is never shared between the two directions. A "combined"
     * queue would have RX and TX processing for that queue share a single
     * NAPI/IRQ context, so a busy TX queue can delay servicing of that
     * same queue's own RX ring (and vice versa) - visible as RX drops
     * that have nothing to do with actual RX capacity. Keeping them fully
     * separate avoids that contention at the cost of using rx_queues +
     * tx_queues NIC queues instead of max(rx_queues, tx_queues). */
    uint16_t rx_queues = rx_threads ? rx_threads : 1;
    uint16_t tx_queues = tx_threads ? tx_threads : 1;
    uint16_t total_queues = rx_queues + tx_queues;
    uint16_t queue;
    uint32_t nic_queue_id;

    io_af_xdp_queue_s *q;
    io_handle_s *rx_io;
    io_handle_s *tx_io;

    if(g_ctx->config.jumbo_frames) {
        LOG(ERROR, "AF_XDP: jumbo frames are not supported by interface %s, "
            "the max AF_XDP frame size is %u byte\n", interface->name, XSK_UMEM__DEFAULT_FRAME_SIZE);
        return false;
    }

    if(!io_af_xdp_check_mtu(interface)) {
        return false;
    }

    if(!io_af_xdp_set_channels(interface, total_queues)) {
        return false;
    }

    if(!io_af_xdp_constrain_rss(interface, rx_queues, total_queues)) {
        return false;
    }

    for(queue = 0; queue < rx_queues; queue++) {
        if(!io_af_xdp_queue_create(interface, queue, AF_XDP_Q_RX_ONLY, &q)) {
            return false;
        }

        rx_io = calloc(1, sizeof(io_handle_s));
        if(!rx_io) return false;
        rx_io->id = queue;
        rx_io->mode = IO_MODE_AF_XDP;
        rx_io->direction = IO_INGRESS;
        rx_io->interface = interface;
        rx_io->fd = q->fd;
        rx_io->af_xdp_queue = q;
        rx_io->af_xdp_queue_id = queue;
        rx_io->next = interface->io.rx;
        interface->io.rx = rx_io;

        if(rx_threads) {
            if(!io_thread_init(rx_io)) {
                return false;
            }
            rx_io->thread->run_fn = io_af_xdp_thread_rx_run_fn;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.rx_job, "RX", 0,
                               config->rx_interval, rx_io, &io_af_xdp_rx_job);
        }
    }

    for(queue = 0; queue < tx_queues; queue++) {
        nic_queue_id = rx_queues + queue;
        if(!io_af_xdp_queue_create(interface, nic_queue_id, AF_XDP_Q_TX_ONLY, &q)) {
            return false;
        }

        tx_io = calloc(1, sizeof(io_handle_s));
        if(!tx_io) return false;
        tx_io->id = queue;
        tx_io->mode = IO_MODE_AF_XDP;
        tx_io->direction = IO_EGRESS;
        tx_io->interface = interface;
        tx_io->fd = q->fd;
        tx_io->af_xdp_queue = q;
        tx_io->af_xdp_queue_id = nic_queue_id;
        tx_io->next = interface->io.tx;
        interface->io.tx = tx_io;

        if(tx_threads) {
            if(!io_thread_init(tx_io)) {
                return false;
            }
            tx_io->thread->run_fn = io_af_xdp_thread_tx_run_fn;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.tx_job, "TX", 0,
                               config->tx_interval, tx_io, &io_af_xdp_tx_job);
        }
    }
    return true;
}

void
io_af_xdp_set_max_stream_len()
{
    uint16_t len = XSK_UMEM__DEFAULT_FRAME_SIZE - BBL_MAX_STREAM_OVERHEAD;
    if(len < g_ctx->config.io_max_stream_len) {
        LOG(DEBUG, "Set max allowed stream length to %u because of AF_XDP frame size limitations\n", len);
        g_ctx->config.io_max_stream_len = len;
    }
}

#endif
