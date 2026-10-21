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
 * This implementation uses the xsk API of libxdp (xdp/xsk.h) or of libbpf
 * < 1.0 (bpf/xsk.h), which takes care of loading the default XDP program
 * redirecting packets into the AF_XDP socket of the matching queue. With
 * libxdp, this program is attached via the libxdp dispatcher (multi-prog),
 * which requires the libxdp BPF object files (xsk_def_xdp_prog*.o) to
 * be installed.
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

#ifdef BNGBLASTER_LIBXDP
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#else
#include <bpf/xsk.h>
#include <bpf/libbpf.h>
#endif
#include <linux/if_link.h>
#include <sys/sysinfo.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define AF_XDP_BURST 256

/* In zero-copy mode, a TX kick (sendto) only wakes up the driver, which
 * then sends all descriptors in the TX ring. Kicking for every round,
 * often with only a few new packets, costs a syscall per round. Kick
 * only if enough descriptors are pending or after a short interval. */
#define AF_XDP_TX_KICK_BATCH        64
#define AF_XDP_TX_KICK_INTERVAL_NS  10000

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
    bool copy_mode; /* copy (not zero-copy) mode, TX requires sendto() kick */

    uint32_t tx_kick_pending; /* TX descriptors submitted since last kick */
    uint64_t tx_kick_last; /* timestamp of last kick (nsec) */
} io_af_xdp_queue_s;

/* NIC configuration found before the AF_XDP initialization changed it,
 * restored by io_af_xdp_cleanup(). A setting with cmd 0 could not be read
 * and is not restored. */
typedef struct io_af_xdp_state_ {
    struct ethtool_channels channels;
    struct ethtool_ringparam ring;
    struct ethtool_value flags;
    uint32_t *rss_indir; /* RSS indirection table */
    uint32_t rss_indir_size;
    bool rss_default; /* table was the driver default (entry i -> i % RX queues) */
    bool rss_changed; /* table was written by io_af_xdp_clamp_rss_indir() */
    bool ring_changed;
    uint32_t rx_frames; /* RX frames per queue, see io_af_xdp_prepare_rx_ring() */
    bool xdp_program; /* XDP program attached before the initialization */
} io_af_xdp_state_s;

/* NIC RX ring size configured if the ring is smaller and supported by the
 * NIC, see io_af_xdp_prepare_rx_ring(). */
#define AF_XDP_RX_RING 4096

/* Some drivers (e.g. i40e) reject configuration changes with EBUSY while
 * a reset caused by a previous change is still in progress. */
#define AF_XDP_ETHTOOL_RETRIES      20
#define AF_XDP_ETHTOOL_RETRY_NS     50000000 /* 50ms */

/* Conservative worst-case per-packet overhead (double VLAN tag, ...) added
 * on top of the interface MTU when checking it against the AF_XDP frame
 * size. */
#define AF_XDP_MTU_OVERHEAD 128

/* The kernel places received frames at XDP_PACKET_HEADROOM within the
 * UMEM frame, which limits the max size of a received frame. */
#define AF_XDP_RX_FRAME_MAX (XSK_UMEM__DEFAULT_FRAME_SIZE - XDP_PACKET_HEADROOM)

/* A failed native mode attempt has already bound the queue, which the
 * kernel releases asynchronously after the socket is closed. The generic
 * mode bind to the same queue fails with EBUSY until then. */
#define AF_XDP_BIND_RETRIES     20
#define AF_XDP_BIND_RETRY_NS    50000000 /* 50ms */

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

static int
io_af_xdp_ethtool_set(int fd, struct ifreq *ifr)
{
    struct timespec retry_delay = {.tv_sec = 0, .tv_nsec = AF_XDP_ETHTOOL_RETRY_NS};
    uint32_t retries = 0;

    while(ioctl(fd, SIOCETHTOOL, ifr) == -1) {
        if((errno != EBUSY && errno != EAGAIN) || retries++ >= AF_XDP_ETHTOOL_RETRIES) {
            return -1;
        }
        nanosleep(&retry_delay, NULL);
    }
    return 0;
}

static uint32_t
io_af_xdp_rx_channels(struct ethtool_channels *ch)
{
    return ch->combined_count ? ch->combined_count : ch->rx_count;
}

/**
 * Save the NIC configuration changed by the AF_XDP initialization
 * (channels, RSS indirection table, RX ring and RX VLAN offload flag),
 * which is restored by io_af_xdp_cleanup() to leave the NIC as found.
 */
static bool
io_af_xdp_save_state(bbl_interface_s *interface)
{
    io_af_xdp_state_s *state;
    struct ifreq ifr = {0};
    struct ethtool_rxfh size_probe = {0};
    struct ethtool_rxfh *rxfh;
    uint32_t rx_channels;
    uint32_t i;
    int fd;

    state = calloc(1, sizeof(io_af_xdp_state_s));
    if(!state) {
        return false;
    }
    interface->io.af_xdp_state = state;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        return true;
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);

    state->channels.cmd = ETHTOOL_GCHANNELS;
    ifr.ifr_data = (void*)&state->channels;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        state->channels.cmd = 0;
    }
    state->ring.cmd = ETHTOOL_GRINGPARAM;
    ifr.ifr_data = (void*)&state->ring;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        state->ring.cmd = 0;
    }
    state->flags.cmd = ETHTOOL_GFLAGS;
    ifr.ifr_data = (void*)&state->flags;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        state->flags.cmd = 0;
    }

    size_probe.cmd = ETHTOOL_GRSSH;
    ifr.ifr_data = (void*)&size_probe;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == 0 && size_probe.indir_size) {
        /* Read the indirection table only (key_size 0), the hash key
         * is never changed. */
        rxfh = calloc(1, sizeof(struct ethtool_rxfh) + size_probe.indir_size * sizeof(uint32_t));
        if(!rxfh) {
            close(fd);
            return false;
        }
        rxfh->cmd = ETHTOOL_GRSSH;
        rxfh->indir_size = size_probe.indir_size;
        ifr.ifr_data = (void*)rxfh;
        if(ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
            state->rss_indir_size = size_probe.indir_size;
            state->rss_indir = malloc(state->rss_indir_size * sizeof(uint32_t));
            if(!state->rss_indir) {
                free(rxfh);
                close(fd);
                return false;
            }
            memcpy(state->rss_indir, rxfh->rss_config, state->rss_indir_size * sizeof(uint32_t));
            rx_channels = state->channels.cmd ? io_af_xdp_rx_channels(&state->channels) : 0;
            state->rss_default = rx_channels > 0;
            for(i = 0; i < state->rss_indir_size && state->rss_default; i++) {
                if(state->rss_indir[i] != i % rx_channels) {
                    state->rss_default = false;
                }
            }
        }
        free(rxfh);
    }
    close(fd);
    return true;
}

static uint32_t
io_af_xdp_program_id(bbl_interface_s *interface)
{
    uint32_t prog_id = 0;

#ifdef BNGBLASTER_LIBXDP
    /* libxdp might be used with libbpf < 0.8, which does not provide
     * bpf_xdp_query_id(). */
    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(interface->kernel_index);
    if(!libxdp_get_error(mp) && mp) {
        if(xdp_multiprog__main_prog(mp)) {
            prog_id = xdp_program__id(xdp_multiprog__main_prog(mp));
        }
        xdp_multiprog__close(mp);
    }
#else
    if(bpf_get_link_xdp_id(interface->kernel_index, &prog_id, 0) != 0) {
        prog_id = 0;
    }
#endif
    return prog_id;
}

/**
 * With libxdp, the XDP program is attached via netlink and remains
 * attached if BNG Blaster is killed or crashes. Such a program does not
 * prevent further tests with libxdp, but might also be used by another
 * application, so it is not removed automatically.
 */
static void
io_af_xdp_check_xdp_program(bbl_interface_s *interface)
{
    uint32_t prog_id = io_af_xdp_program_id(interface);

    if(prog_id) {
        interface->io.af_xdp_state->xdp_program = true;
        LOG(INFO, "Warning: AF_XDP interface %s has XDP program %u already attached "
            "(e.g. left behind by a killed BNG Blaster), please remove it if not used "
            "by another application (e.g. 'xdp-loader unload %s --all')\n",
            interface->name, prog_id, interface->name);
    }
}

/**
 * Detach an XDP program attached by this instance, which remains after
 * all sockets are deleted. libbpf < 1.0 attaches the program via netlink
 * instead of a BPF link, if attaching a BPF link fails (e.g. because
 * libbpf probes BPF link support with the loopback interface, which
 * fails if another process probes at the same time). Such a program is
 * not detached when the sockets are deleted.
 *
 * @param interface interface
 * @return false if the program could not be detached
 */
static bool
io_af_xdp_detach_xdp_program(bbl_interface_s *interface)
{
    uint32_t prog_id = io_af_xdp_program_id(interface);

    if(!prog_id) {
        return true;
    }
#ifdef BNGBLASTER_LIBXDP
    struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(interface->kernel_index);
    if(!libxdp_get_error(mp) && mp) {
        xdp_multiprog__detach(mp);
        xdp_multiprog__close(mp);
    }
#else
    bpf_set_link_xdp_fd(interface->kernel_index, -1, XDP_FLAGS_DRV_MODE);
    bpf_set_link_xdp_fd(interface->kernel_index, -1, XDP_FLAGS_SKB_MODE);
#endif
    if(io_af_xdp_program_id(interface)) {
        LOG(ERROR, "AF_XDP: failed to detach XDP program %u from interface %s, please remove it "
            "manually (e.g. 'ip link set %s xdp off')\n", prog_id, interface->name, interface->name);
        return false;
    }
    LOG(AFXDP, "AF_XDP: detached XDP program %u left behind on interface %s\n",
        prog_id, interface->name);
    return true;
}

/**
 * AF_XDP sockets are bound without multi-buffer support (XDP_USE_SG), so
 * received frames larger than a single UMEM frame are dropped by the
 * kernel. Interfaces are commonly left at a larger (e.g. jumbo) MTU for
 * other purposes even though BNG Blaster itself never sends packets that
 * large unless jumbo-frames is enabled (which is rejected for AF_XDP), so
 * a larger MTU is accepted. However, some drivers (e.g. i40e) refuse to
 * attach an XDP program without multi-buffer (frags) support in native
 * mode if the MTU exceeds their max linear frame size, in which case the
 * socket falls back to the much slower generic (SKB) mode.
 */
static void
io_af_xdp_check_mtu(bbl_interface_s *interface)
{
    struct ifreq ifr = {0};
    int fd;
    int mtu;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        return;
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if(ioctl(fd, SIOCGIFMTU, &ifr) == -1) {
        close(fd);
        return;
    }
    close(fd);
    mtu = ifr.ifr_mtu;

    if((uint32_t)mtu + AF_XDP_MTU_OVERHEAD > AF_XDP_RX_FRAME_MAX) {
        LOG(INFO, "Warning: AF_XDP interface %s has MTU %d, received frames larger than "
            "%u byte are dropped and native mode might not be supported by the driver, "
            "please lower the interface MTU (e.g. 'ip link set %s mtu 1500')\n",
            interface->name, mtu, AF_XDP_RX_FRAME_MAX, interface->name);
    }
}

/**
 * The NIC RX ring is filled with frames of the AF_XDP socket. A small
 * ring can't absorb short delays of the RX thread, and if the ring
 * exceeds half of those frames, the frames still waiting to be processed
 * are missing to refill the ring. Both cause RX loss, visible only as
 * rx_missed_errors in the NIC statistics.
 *
 * Therefore increase the RX ring to AF_XDP_RX_RING (limited to the NIC
 * maximum, a larger ring is kept) and size the RX frames to at least twice
 * the ring, unless io-slots-rx is configured explicitly. The ring is
 * restored on exit.
 */
static void
io_af_xdp_prepare_rx_ring(bbl_interface_s *interface)
{
    io_af_xdp_state_s *state = interface->io.af_xdp_state;
    bbl_link_config_s *config = interface->config;
    struct ifreq ifr = {0};
    struct ethtool_ringparam ring = state->ring;
    uint32_t rx_ring = ring.rx_pending;
    uint32_t rx_frames;
    int fd;

    state->rx_frames = next_pow2(config->io_slots_rx);
    if(!ring.cmd || !rx_ring) {
        /* RX ring size not supported by the driver. */
        return;
    }

    if(rx_ring < AF_XDP_RX_RING && ring.rx_max_pending > rx_ring) {
        fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
        if(fd != -1) {
            snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
            ring.cmd = ETHTOOL_SRINGPARAM;
            ring.rx_pending = ring.rx_max_pending < AF_XDP_RX_RING ? ring.rx_max_pending : AF_XDP_RX_RING;
            ifr.ifr_data = (void*)&ring;
            state->ring_changed = true;
            if(io_af_xdp_ethtool_set(fd, &ifr) == -1) {
                LOG(INFO, "Warning: AF_XDP failed to increase the NIC RX ring of interface %s "
                    "from %u to %u (%s), which might cause RX loss\n",
                    interface->name, rx_ring, ring.rx_pending, strerror(errno));
            }
            /* The driver might adjust the requested size. */
            ring.cmd = ETHTOOL_GRINGPARAM;
            if(ioctl(fd, SIOCETHTOOL, &ifr) == 0 && ring.rx_pending) {
                if(ring.rx_pending != rx_ring) {
                    LOG(AFXDP, "AF_XDP: interface %s NIC RX ring increased to %u (was %u)\n",
                        interface->name, ring.rx_pending, rx_ring);
                }
                rx_ring = ring.rx_pending;
            }
            close(fd);
        }
    }

    rx_frames = next_pow2(rx_ring * 2);
    if(rx_frames <= state->rx_frames) {
        return;
    }
    if(config->io_slots_rx_set) {
        LOG(INFO, "Warning: AF_XDP NIC RX ring %u of interface %s exceeds half of "
            "the %u RX frames (io-slots-rx), which causes RX loss, please increase "
            "io-slots-rx to %u or remove it to size the RX frames automatically\n",
            rx_ring, interface->name, state->rx_frames, rx_frames);
        return;
    }
    LOG(AFXDP, "AF_XDP: interface %s uses %u RX frames per queue for NIC RX ring %u\n",
        interface->name, rx_frames, rx_ring);
    state->rx_frames = rx_frames;
}

/**
 * With RX VLAN offload enabled (the default on most drivers), the NIC
 * strips the VLAN tag in hardware and reports it out-of-band via the skb
 * (skb->vlan_tci) instead of leaving it in the frame data - that is how
 * io_packet_mmap.c recovers it, via tp_vlan_tci/TP_STATUS_VLAN_VALID.
 * AF_XDP has no equivalent side channel: the xdp_desc UMEM frame handed to
 * us is the raw DMA buffer, so a hardware-stripped tag is simply gone by
 * the time we see it, in both native and generic (SKB) mode. Disable RX
 * VLAN offload so the tag stays in-band where we can parse it.
 */
static bool
io_af_xdp_disable_rxvlan_offload(bbl_interface_s *interface)
{
    struct ifreq ifr = {0};
    struct ethtool_value eval = {0};
    int fd;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        return true; /* best effort, do not block on this check */
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);

    eval.cmd = ETHTOOL_GFLAGS;
    ifr.ifr_data = (void*)&eval;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        /* Driver does not support ethtool flags (e.g. some virtual
         * interfaces) - nothing we can/need to do. */
        close(fd);
        return true;
    }
    if(!(eval.data & ETH_FLAG_RXVLAN)) {
        close(fd);
        return true;
    }

    eval.cmd = ETHTOOL_SFLAGS;
    eval.data &= ~ETH_FLAG_RXVLAN;
    ifr.ifr_data = (void*)&eval;
    if(io_af_xdp_ethtool_set(fd, &ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to disable RX VLAN offload on interface %s (%s), "
            "VLAN tags will be missing from received frames, please disable it "
            "manually (e.g. 'ethtool -K %s rxvlan off')\n",
            interface->name, strerror(errno), interface->name);
        close(fd);
        return false;
    }

    LOG(AFXDP, "AF_XDP: RX VLAN offload disabled on interface %s\n", interface->name);
    close(fd);
    return true;
}

/**
 * Read the NIC's RSS indirection table and bring it within 0..limit-1,
 * writing the table back if anything changed.
 *
 * With rebalance, the table is rebuilt as an even round-robin over
 * 0..limit-1 (entry i -> i % limit). This keeps TX-only queues excluded
 * from RX distribution (io_af_xdp_constrain_rss()), after the channels
 * have been configured.
 *
 * Without rebalance, only entries referencing a queue at or beyond limit
 * are remapped (entry -> entry % limit). This is required before shrinking
 * the channel count: once an RSS indirection table has been explicitly
 * configured (which a prior bngblaster run with more rx-threads/tx-threads
 * does), the kernel refuses ETHTOOL_SCHANNELS with EINVAL if that table
 * still references a queue index at or beyond the channel count being
 * requested. Rebalancing at this point is not possible, as the table must
 * remain valid for the current channel count as well.
 *
 * The rebalanced table is unconditionally rebuilt by index rather than only
 * remapping out-of-range entries by value. Patching only out-of-range
 * entries is not enough: a table previously collapsed onto a single queue
 * (e.g. by an earlier run with rx-threads 1, where every entry % 1 == 0)
 * has every entry already in range for any larger limit, so it would never
 * be touched again and RSS would stay collapsed onto queue 0 even after
 * rx-threads is increased. Remapping in-range values by their old value
 * is also not sufficient, since old_combined % limit != 0 skews a handful
 * of low queue indices with extra weight from the wrapped-around entries.
 * Rebuilding by table index guarantees an even (+/-1) distribution
 * regardless of the table's prior content.
 */
static bool
io_af_xdp_clamp_rss_indir(bbl_interface_s *interface, uint32_t limit, bool rebalance, bool *changed)
{
    struct ifreq ifr = {0};
    struct ethtool_rxfh size_probe = {0};
    struct ethtool_rxfh *rxfh;
    uint32_t *indir;
    uint8_t *buf;
    size_t buf_len;
    int fd;
    uint32_t i;

    *changed = false;

    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        LOG(ERROR, "AF_XDP: failed to open socket to configure the RSS indirection "
            "table of interface %s (%s)\n", interface->name, strerror(errno));
        return false;
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);

    size_probe.cmd = ETHTOOL_GRSSH;
    ifr.ifr_data = (void*)&size_probe;
    if(ioctl(fd, SIOCETHTOOL, &ifr) == -1) {
        if(errno == EOPNOTSUPP) {
            /* No RSS support on this driver/NIC - nothing to constrain. */
            close(fd);
            return true;
        }
        /* Driver exposes multiple queues but not the RSS indirection
         * table - we cannot verify queues >= limit are excluded from
         * RSS, so fail loudly instead of risking silent per-flow RX
         * loss or an unexplained EINVAL further down the line. */
        LOG(ERROR, "AF_XDP: interface %s does not support querying the RSS "
            "indirection table (%s), cannot guarantee it is constrained to "
            "%u queue%s\n",
            interface->name, strerror(errno), limit, limit == 1 ? "" : "s");
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
        return false;
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
        uint32_t entry = rebalance ? i % limit : indir[i] % limit;
        if(indir[i] != entry) {
            indir[i] = entry;
            *changed = true;
        }
    }
    if(!*changed) {
        free(buf);
        close(fd);
        return true;
    }

    rxfh->cmd = ETHTOOL_SRSSH;
    rxfh->rss_context = 0;
    ifr.ifr_data = (void*)rxfh;
    if(interface->io.af_xdp_state) {
        interface->io.af_xdp_state->rss_changed = true;
    }
    if(io_af_xdp_ethtool_set(fd, &ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to constrain the RSS indirection table on interface %s "
            "to the first %u queue%s (%s), please configure it manually "
            "(e.g. 'ethtool -X %s equal %u')\n",
            interface->name, limit, limit == 1 ? "" : "s", strerror(errno),
            interface->name, limit);
        free(buf);
        close(fd);
        return false;
    }

    free(buf);
    close(fd);
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
        if(queues < old_combined) {
            bool rss_changed;
            if(!io_af_xdp_clamp_rss_indir(interface, queues, false, &rss_changed)) {
                close(fd);
                return false;
            }
        }
        ch.cmd = ETHTOOL_SCHANNELS;
        ch.combined_count = queues;
        if(io_af_xdp_ethtool_set(fd, &ifr) == -1) {
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
        if(queues < ch.rx_count) {
            bool rss_changed;
            if(!io_af_xdp_clamp_rss_indir(interface, queues, false, &rss_changed)) {
                close(fd);
                return false;
            }
        }
        ch.cmd = ETHTOOL_SCHANNELS;
        ch.rx_count = queues;
        ch.tx_count = queues;
        if(io_af_xdp_ethtool_set(fd, &ifr) == -1) {
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
    bool changed;

    if(rx_queues >= total_queues) {
        /* No TX-only queue exists, nothing for RSS to avoid. */
        return true;
    }

    if(!io_af_xdp_clamp_rss_indir(interface, rx_queues, true, &changed)) {
        /* Cannot guarantee TX-only queues are excluded from RX traffic
         * distribution - io_af_xdp_clamp_rss_indir() already logged why. */
        return false;
    }

    if(changed) {
        LOG(AFXDP, "AF_XDP: interface %s RSS indirection table constrained to queue%s 0-%u "
            "(queue%s %u-%u reserved for TX only, excluded from RX distribution)\n",
            interface->name, rx_queues == 1 ? "" : "s", rx_queues - 1,
            total_queues - rx_queues == 1 ? "" : "s", rx_queues, total_queues - 1);
    }
    return true;
}

/**
 * Delete the UMEM of a queue without socket (e.g. after a failed bind).
 *
 * libbpf < 0.8.1 and older libxdp versions do not unmap the fill and
 * completion rings in xsk_umem__delete() if xsk_socket__create() failed.
 * Those mappings keep the UMEM socket alive, so its queue remains bound
 * and every further bind to this queue fails with EBUSY. Therefore unmap
 * the rings if they are still mapped after the UMEM is deleted. This is
 * safe because no other thread creates mappings during interface init.
 */
static void
io_af_xdp_umem_delete(io_af_xdp_queue_s *q)
{
    struct xdp_mmap_offsets off = {0};
    socklen_t optlen = sizeof(off);
    void *fill_map = NULL;
    void *comp_map = NULL;
    size_t fill_len = 0;
    size_t comp_len = 0;

    if(!q->umem) return;
    if(q->fill.ring && q->comp.ring &&
       getsockopt(xsk_umem__fd(q->umem), SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) == 0 &&
       optlen == sizeof(off)) {
        fill_map = (uint8_t*)q->fill.ring - off.fr.desc;
        fill_len = off.fr.desc + q->fill.size * sizeof(uint64_t);
        comp_map = (uint8_t*)q->comp.ring - off.cr.desc;
        comp_len = off.cr.desc + q->comp.size * sizeof(uint64_t);
    }
    xsk_umem__delete(q->umem);
    q->umem = NULL;

    /* msync() fails with ENOMEM if the range is not mapped. */
    if(fill_map && msync(fill_map, fill_len, MS_ASYNC) == 0) {
        munmap(fill_map, fill_len);
    }
    if(comp_map && msync(comp_map, comp_len, MS_ASYNC) == 0) {
        munmap(comp_map, comp_len);
    }
    memset(&q->fill, 0, sizeof(q->fill));
    memset(&q->comp, 0, sizeof(q->comp));
    memset(&q->rx, 0, sizeof(q->rx));
    memset(&q->tx, 0, sizeof(q->tx));
}

static void
io_af_xdp_queue_destroy(io_af_xdp_queue_s *q)
{
    if(!q) return;
    if(q->xsk) {
        /* The socket owns and unmaps the rings. */
        xsk_socket__delete(q->xsk);
        xsk_umem__delete(q->umem);
    } else {
        io_af_xdp_umem_delete(q);
    }
    free(q->tx_free);
    free(q->umem_area);
    free(q);
}

/**
 * Restore the channels before the RSS indirection table, which might
 * reference queues that do not exist before. A table referencing queues
 * beyond the restored channel count is clamped before (see
 * io_af_xdp_clamp_rss_indir()).
 */
static bool
io_af_xdp_restore_channels(bbl_interface_s *interface, io_af_xdp_state_s *state, int fd, struct ifreq *ifr)
{
    struct ethtool_channels ch = {0};
    struct timespec retry_delay = {.tv_sec = 0, .tv_nsec = AF_XDP_ETHTOOL_RETRY_NS};
    uint32_t rx_channels = io_af_xdp_rx_channels(&state->channels);
    uint32_t retries = 0;
    bool rss_changed;

    ch.cmd = ETHTOOL_GCHANNELS;
    ifr->ifr_data = (void*)&ch;
    if(ioctl(fd, SIOCETHTOOL, ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to read channels of interface %s (%s)\n",
            interface->name, strerror(errno));
        return false;
    }
    if(ch.combined_count == state->channels.combined_count &&
       ch.rx_count == state->channels.rx_count &&
       ch.tx_count == state->channels.tx_count) {
        return true;
    }
    if(rx_channels && rx_channels < io_af_xdp_rx_channels(&ch)) {
        if(!io_af_xdp_clamp_rss_indir(interface, rx_channels, false, &rss_changed)) {
            return false;
        }
    }
    /* The kernel refuses to remove queues with an AF_XDP socket bound
     * (EINVAL), which it releases asynchronously after the socket is
     * deleted. */
    state->channels.cmd = ETHTOOL_SCHANNELS;
    ifr->ifr_data = (void*)&state->channels;
    while(io_af_xdp_ethtool_set(fd, ifr) == -1) {
        if(errno != EINVAL || retries++ >= AF_XDP_ETHTOOL_RETRIES) {
            LOG(ERROR, "AF_XDP: failed to restore channels of interface %s (%s), please restore "
                "them manually (e.g. 'ethtool -L %s combined %u')\n",
                interface->name, strerror(errno), interface->name, rx_channels);
            return false;
        }
        nanosleep(&retry_delay, NULL);
    }
    LOG(AFXDP, "AF_XDP: interface %s channels restored (%u combined, %u RX, %u TX)\n",
        interface->name, state->channels.combined_count, state->channels.rx_count,
        state->channels.tx_count);
    return true;
}

/**
 * Writing the RSS indirection table marks it as configured by the user,
 * which prevents the driver from adjusting it to later channel changes.
 * Therefore a table that was the driver default before is reset to the
 * default (indir_size 0) instead of written back.
 */
static bool
io_af_xdp_restore_rss(bbl_interface_s *interface, io_af_xdp_state_s *state, int fd, struct ifreq *ifr)
{
    struct ethtool_rxfh *rxfh;

    rxfh = calloc(1, sizeof(struct ethtool_rxfh) + state->rss_indir_size * sizeof(uint32_t));
    if(!rxfh) {
        return false;
    }
    rxfh->cmd = ETHTOOL_SRSSH;
    if(!state->rss_default) {
        rxfh->indir_size = state->rss_indir_size;
        memcpy(rxfh->rss_config, state->rss_indir, state->rss_indir_size * sizeof(uint32_t));
    }
    ifr->ifr_data = (void*)rxfh;
    if(io_af_xdp_ethtool_set(fd, ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to restore the RSS indirection table of interface %s (%s)\n",
            interface->name, strerror(errno));
        free(rxfh);
        return false;
    }
    LOG(AFXDP, "AF_XDP: interface %s RSS indirection table restored%s\n",
        interface->name, state->rss_default ? " to default" : "");
    free(rxfh);
    return true;
}

/**
 * Restore the RX ring only, other ring parameters are not changed.
 */
static bool
io_af_xdp_restore_ring(bbl_interface_s *interface, io_af_xdp_state_s *state, int fd, struct ifreq *ifr)
{
    struct ethtool_ringparam ring = {0};
    uint32_t rx_ring;

    ring.cmd = ETHTOOL_GRINGPARAM;
    ifr->ifr_data = (void*)&ring;
    if(ioctl(fd, SIOCETHTOOL, ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to read the NIC RX ring of interface %s (%s)\n",
            interface->name, strerror(errno));
        return false;
    }
    if(ring.rx_pending == state->ring.rx_pending) {
        return true;
    }
    rx_ring = ring.rx_pending;
    ring.cmd = ETHTOOL_SRINGPARAM;
    ring.rx_pending = state->ring.rx_pending;
    if(io_af_xdp_ethtool_set(fd, ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to restore the NIC RX ring of interface %s (%s), please restore "
            "it manually (e.g. 'ethtool -G %s rx %u')\n",
            interface->name, strerror(errno), interface->name, state->ring.rx_pending);
        return false;
    }
    LOG(AFXDP, "AF_XDP: interface %s NIC RX ring restored to %u (was %u)\n",
        interface->name, state->ring.rx_pending, rx_ring);
    return true;
}

/**
 * Restore the RX VLAN offload flag only, other flags are not changed.
 */
static bool
io_af_xdp_restore_flags(bbl_interface_s *interface, io_af_xdp_state_s *state, int fd, struct ifreq *ifr)
{
    struct ethtool_value eval = {0};

    eval.cmd = ETHTOOL_GFLAGS;
    ifr->ifr_data = (void*)&eval;
    if(ioctl(fd, SIOCETHTOOL, ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to read flags of interface %s (%s)\n",
            interface->name, strerror(errno));
        return false;
    }
    if((eval.data & ETH_FLAG_RXVLAN) == (state->flags.data & ETH_FLAG_RXVLAN)) {
        return true;
    }
    eval.cmd = ETHTOOL_SFLAGS;
    eval.data = (eval.data & ~ETH_FLAG_RXVLAN) | (state->flags.data & ETH_FLAG_RXVLAN);
    if(io_af_xdp_ethtool_set(fd, ifr) == -1) {
        LOG(ERROR, "AF_XDP: failed to restore RX VLAN offload of interface %s (%s)\n",
            interface->name, strerror(errno));
        return false;
    }
    LOG(AFXDP, "AF_XDP: RX VLAN offload restored on interface %s\n", interface->name);
    return true;
}

/**
 * Restore the NIC configuration saved by io_af_xdp_save_state(), after
 * all sockets of the interface are deleted.
 */
static bool
io_af_xdp_restore_state(bbl_interface_s *interface)
{
    io_af_xdp_state_s *state = interface->io.af_xdp_state;
    struct ifreq ifr = {0};
    bool success = true;
    int fd;

    if(!state) {
        return true;
    }
    if(if_nametoindex(interface->name) != interface->kernel_index) {
        LOG(ERROR, "AF_XDP: interface %s was removed or recreated, NIC configuration not restored\n",
            interface->name);
        success = false;
        goto FREE;
    }
    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd == -1) {
        LOG(ERROR, "AF_XDP: failed to open socket to restore the NIC configuration of interface %s (%s)\n",
            interface->name, strerror(errno));
        success = false;
        goto FREE;
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);

    if(!state->xdp_program && !io_af_xdp_detach_xdp_program(interface)) {
        success = false;
    }
    if(state->channels.cmd && !io_af_xdp_restore_channels(interface, state, fd, &ifr)) {
        success = false;
        if(state->rss_changed) {
            LOG(ERROR, "AF_XDP: RSS indirection table of interface %s not restored "
                "because restoring the channels failed\n", interface->name);
            state->rss_changed = false;
        }
    }
    if(state->rss_changed && state->rss_indir && !io_af_xdp_restore_rss(interface, state, fd, &ifr)) {
        success = false;
    }
    if(state->ring_changed && !io_af_xdp_restore_ring(interface, state, fd, &ifr)) {
        success = false;
    }
    if(state->flags.cmd && !io_af_xdp_restore_flags(interface, state, fd, &ifr)) {
        success = false;
    }
    close(fd);
FREE:
    interface->io.af_xdp_state = NULL;
    free(state->rss_indir);
    free(state);
    return success;
}

/**
 * Delete all AF_XDP sockets after the IO threads are stopped and restore
 * the NIC configuration. This is also called if the initialization of
 * an interface failed.
 *
 * With libxdp, the XDP program is attached via netlink and remains
 * attached after the process exits. It is detached only if the last
 * socket of the interface is deleted with xsk_socket__delete().
 *
 * @return false if the NIC configuration of an interface was not
 * completely restored
 */
bool
io_af_xdp_cleanup()
{
    bbl_interface_s *interface;
    io_handle_s *io;
    bool success = true;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        for(io = interface->io.rx; io; io = io->next) {
            if(io->mode == IO_MODE_AF_XDP && io->af_xdp_queue) {
                io_af_xdp_queue_destroy(io->af_xdp_queue);
                io->af_xdp_queue = NULL;
                io->fd = -1;
            }
        }
        for(io = interface->io.tx; io; io = io->next) {
            if(io->mode == IO_MODE_AF_XDP && io->af_xdp_queue) {
                io_af_xdp_queue_destroy(io->af_xdp_queue);
                io->af_xdp_queue = NULL;
                io->fd = -1;
            }
        }
        if(!io_af_xdp_restore_state(interface)) {
            success = false;
        }
    }
    return success;
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
                        bool select_mode, uint32_t *xdp_flags, io_af_xdp_queue_s **queue_out)
{
    bbl_link_config_s *config = interface->config;
    io_af_xdp_queue_s *q;
    struct xsk_umem_config umem_cfg = {0};
    struct xsk_socket_config sock_cfg = {0};
    struct xsk_ring_cons *rx_ring;
    struct xsk_ring_prod *tx_ring;
    struct timespec retry_delay = {.tv_sec = 0, .tv_nsec = AF_XDP_BIND_RETRY_NS};
    uint32_t page_size = getpagesize();
    bool want_rx = (qmode != AF_XDP_Q_TX_ONLY);
    bool want_tx = (qmode != AF_XDP_Q_RX_ONLY);
    uint32_t retries = 0;
    uint32_t i;
    int ret;
    int err;

    q = calloc(1, sizeof(io_af_xdp_queue_s));
    if(!q) {
        return false;
    }

    q->frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
    /* The UMEM always reserves space for both a fill and a completion
     * ring (they belong to the UMEM, not to a socket's RX/TX bind), but
     * a direction this queue does not use only needs the kernel-enforced
     * minimum ring size instead of the full configured slot count. */
    q->rx_frames = want_rx ? interface->io.af_xdp_state->rx_frames : 2;
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

    /* A NULL ring pointer (with the matching *_size left at 0) tells
     * libbpf to not set up that direction at all, giving us an RX-only
     * or TX-only socket as needed - each queue still gets its own
     * independent UMEM, no XDP_SHARED_UMEM is required for this. */
    rx_ring = want_rx ? &q->rx : NULL;
    tx_ring = want_tx ? &q->tx : NULL;
    sock_cfg.rx_size = want_rx ? q->rx_frames : 0;
    sock_cfg.tx_size = want_tx ? q->tx_frames : 0;
    sock_cfg.libbpf_flags = 0;

    /* Prefer native (driver) mode for the best performance and fall back
     * to generic (SKB) mode transparently, e.g. for virtual interfaces
     * (veth, ...), drivers without native XDP support or an MTU which is
     * not supported in native mode. The selected mode is returned via
     * xdp_flags, so further queues of the same interface skip a native
     * attempt which already failed. A failed attempt can leave the UMEM
     * in a state some libbpf versions do not fully unwind, so every
     * attempt is done against a freshly created UMEM. */
    sock_cfg.xdp_flags = *xdp_flags;
    while(true) {
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
        /* Without XDP_COPY, the kernel binds in zero-copy mode if the
         * driver supports it, regardless of the XDP mode. In generic mode,
         * the driver (e.g. i40e) then neither receives nor sends anything
         * on this queue because no native XDP program is attached.
         * Copy mode can be selected explicitly, e.g. if the zero-copy
         * mode of the driver performs badly (ice with IOMMU translation
         * fills the NIC RX ring only partially on some kernels). */
        sock_cfg.bind_flags = XDP_USE_NEED_WAKEUP;
        if(sock_cfg.xdp_flags == XDP_FLAGS_SKB_MODE || config->af_xdp_mode == AF_XDP_MODE_COPY) {
            sock_cfg.bind_flags |= XDP_COPY;
        } else if(config->af_xdp_mode == AF_XDP_MODE_ZERO_COPY) {
            sock_cfg.bind_flags |= XDP_ZEROCOPY;
        }
        ret = xsk_socket__create(&q->xsk, interface->name, queue_id, q->umem, rx_ring, tx_ring, &sock_cfg);
        if(!ret) {
            break;
        }
        /* Some libbpf < 1.0 errors are returned as -1 with errno set. */
        err = ret == -1 ? errno : -ret;

        q->xsk = NULL;
        io_af_xdp_umem_delete(q);

        /* The mode is selected with the first queue and used for all
         * further queues, which must not fall back to another mode. */
        if(select_mode && sock_cfg.xdp_flags == XDP_FLAGS_DRV_MODE &&
           config->af_xdp_mode != AF_XDP_MODE_ZERO_COPY) {
            LOG(INFO, "Warning: AF_XDP native mode not available for interface %s (%s), "
                "falling back to generic (SKB) mode\n", interface->name, strerror(err));
            sock_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        } else if(err == EBUSY && retries < AF_XDP_BIND_RETRIES) {
            retries++;
            LOG(DEBUG, "AF_XDP: interface %s queue %u busy, retry bind (%u/%u)\n",
                interface->name, queue_id, retries, AF_XDP_BIND_RETRIES);
            nanosleep(&retry_delay, NULL);
        } else if(!select_mode) {
            /* Previous queues of this interface are bound. */
            LOG(ERROR, "AF_XDP: failed to create socket for interface %s queue %u (%s), "
                "while the previous queues were bound - the driver might support AF_XDP "
                "on fewer queues than required by rx-threads/tx-threads (e.g. i40e only "
                "on as many queues as CPUs, which are %d), please reduce the threads\n",
                interface->name, queue_id, strerror(err), get_nprocs());
            io_af_xdp_queue_destroy(q);
            return false;
        } else {
            LOG(ERROR, "AF_XDP: failed to create socket for interface %s queue %u (%s) - "
                "possible causes: not enough RX/TX queues on the interface, an XDP "
                "program already attached to it, missing CAP_NET_RAW/CAP_BPF privileges%s\n",
                interface->name, queue_id, strerror(err),
                config->af_xdp_mode == AF_XDP_MODE_ZERO_COPY ?
                " or zero-copy mode not supported by the driver (af-xdp-mode)" : "");
            io_af_xdp_queue_destroy(q);
            return false;
        }
    }
    *xdp_flags = sock_cfg.xdp_flags;
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
            q->copy_mode = !(opts.flags & XDP_OPTIONS_ZEROCOPY);
        } else {
            q->copy_mode = true;
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

/**
 * With XDP_USE_NEED_WAKEUP, the driver fills the NIC RX ring from the
 * fill ring only if woken up, e.g. after the NIC RX ring ran empty or if
 * the driver could not fill it when the socket was bound (e.g. ice). An
 * empty NIC RX ring drops all packets without interrupt, so the driver
 * must be woken up also if nothing was received, otherwise RX stalls
 * forever (visible as increasing rx_dropped).
 */
static inline void
io_af_xdp_rx_wakeup(io_af_xdp_queue_s *q)
{
    if(xsk_ring_prod__needs_wakeup(&q->fill)) {
        recvfrom(q->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    }
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
    io_af_xdp_rx_wakeup(q);
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
 * Kick the kernel to transmit outstanding TX descriptors.
 *
 * This must be done whenever TX descriptors are outstanding (submitted
 * but not yet completed), not only if new descriptors were queued in the
 * current round. In copy mode the kernel sends only a limited batch of
 * descriptors per kick, so the backlog is never drained otherwise and TX
 * stalls once all TX frames are outstanding.
 */
static inline void
io_af_xdp_kick_tx(io_af_xdp_queue_s *q)
{
    if(q->tx_free_count < q->tx_frames &&
       (q->copy_mode || xsk_ring_prod__needs_wakeup(&q->tx))) {
        sendto(q->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
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
    io_af_xdp_rx_wakeup(q);
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

    io_af_xdp_kick_tx(q);
    io->queued = 0;
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
    uint8_t *bufs[AF_XDP_BURST];
    uint16_t lens[AF_XDP_BURST];
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
            io_af_xdp_rx_wakeup(q);
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
            bufs[i] = xsk_umem__get_data(q->umem_area, desc->addr);
            lens[i] = desc->len;
        }
        io->vlan_tci = 0;
        io_thread_rx_burst(thread, io, bufs, lens, rcvd);
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
    uint32_t burst = 0;
    uint32_t used = 0;
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

        /* Reserve TX ring slots for the whole burst at once and publish
         * them with a single producer update per round. Submitting per
         * packet lets NAPI (running on another core) consume the ring in
         * tiny chunks and bounces the producer cache line for every packet.
         * The TX ring has as many slots as there are TX frames, so a
         * reservation limited to tx_free_count can not fail. */
        burst = io_burst;
        if(burst > q->tx_free_count) {
            burst = q->tx_free_count;
        }
        if(burst && xsk_ring_prod__reserve(&q->tx, burst, &tidx) != burst) {
            burst = 0;
        }
        used = 0;

        /* First send all control traffic which has higher priority. */
        while(used < burst && (slot = bbl_txq_read_slot(txq))) {
            addr = q->tx_free[--q->tx_free_count];
            io->buf = xsk_umem__get_data(q->umem_area, addr);
            memcpy(io->buf, slot->packet, slot->packet_len);

            desc = xsk_ring_prod__tx_desc(&q->tx, tidx + used);
            desc->addr = addr;
            desc->len = slot->packet_len;
            desc->options = 0;
            used++;

            io->stats.packets++;
            io->stats.bytes += slot->packet_len;
            bbl_txq_read_next(txq);
        }

        /* Get TX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);

        if(g_traffic && g_init_phase == false && interface->state == INTERFACE_UP) {
            now = timespec_to_nsec(&io->timestamp);
            /* Send traffic streams up to allowed burst. */
            while(used < burst) {
                stream = bbl_stream_io_send_iter(io, now);
                if(unlikely(stream == NULL)) {
                    break;
                }
                addr = q->tx_free[--q->tx_free_count];
                io->buf = xsk_umem__get_data(q->umem_area, addr);
                memcpy(io->buf, stream->tx_buf, stream->tx_len);

                desc = xsk_ring_prod__tx_desc(&q->tx, tidx + used);
                desc->addr = addr;
                desc->len = stream->tx_len;
                desc->options = 0;
                used++;

                stream->tx_packets++;
                stream->flow_seq++;
                io->stats.packets++;
                io->stats.bytes += stream->tx_len;
            }
        } else {
            bbl_stream_io_stop(io);
        }

        if(burst < io_burst && used == burst) {
            /* Round was limited by free TX frames. */
            io->stats.no_buffer++;
        }
        /* Release reserved but unused slots (xsk_ring_prod__cancel). */
        q->tx.cached_prod -= burst - used;
        if(used) {
            xsk_ring_prod__submit(&q->tx, used);
            io->queued += used;
            q->tx_kick_pending += used;
        }

        now = timespec_to_nsec(&io->timestamp);
        if(q->copy_mode || q->tx_kick_pending >= AF_XDP_TX_KICK_BATCH ||
           now - q->tx_kick_last >= AF_XDP_TX_KICK_INTERVAL_NS) {
            io_af_xdp_kick_tx(q);
            q->tx_kick_pending = 0;
            q->tx_kick_last = now;
        }
        if(io->queued) {
            idle_rounds = 0;
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
    uint32_t xdp_flags = config->af_xdp_mode == AF_XDP_MODE_GENERIC ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;

    io_af_xdp_queue_s *q;
    io_handle_s *rx_io;
    io_handle_s *tx_io;

    if(g_ctx->config.jumbo_frames) {
        LOG(ERROR, "AF_XDP: jumbo frames are not supported by interface %s, "
            "the max AF_XDP frame size is %u byte\n", interface->name, XSK_UMEM__DEFAULT_FRAME_SIZE);
        return false;
    }

    if(!io_af_xdp_save_state(interface)) {
        LOG(ERROR, "AF_XDP: failed to save the NIC configuration of interface %s\n", interface->name);
        return false;
    }
    io_af_xdp_check_xdp_program(interface);
    io_af_xdp_check_mtu(interface);

    if(!io_af_xdp_disable_rxvlan_offload(interface)) {
        return false;
    }

    if(!io_af_xdp_set_channels(interface, total_queues)) {
        return false;
    }

    io_af_xdp_prepare_rx_ring(interface);

    if(!io_af_xdp_constrain_rss(interface, rx_queues, total_queues)) {
        return false;
    }

    for(queue = 0; queue < rx_queues; queue++) {
        if(!io_af_xdp_queue_create(interface, queue, AF_XDP_Q_RX_ONLY, queue == 0, &xdp_flags, &q)) {
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
        if(!io_af_xdp_queue_create(interface, nic_queue_id, AF_XDP_Q_TX_ONLY, false, &xdp_flags, &q)) {
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
