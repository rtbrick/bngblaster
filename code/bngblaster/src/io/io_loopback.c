/*
 * BNG Blaster (BBL) - IO Loopback Functions
 *
 * The loopback IO mode connects two links of the same BNG Blaster
 * instance back to back via in-memory rings, without any kernel
 * interface, driver or NIC in between. This allows to measure the
 * IO performance of BNG Blaster itself (packet generation, stream
 * processing, decoding, ...) independent of the underlying IO stack.
 *
 * Every TX IO handle owns one single-producer/single-consumer ring
 * per direction, which is read by exactly one RX IO handle of the
 * peer link (ring N is assigned to RX IO handle N % rx-queues). An
 * RX IO handle may therefore poll multiple rings, but each ring has
 * exactly one producer and one consumer, so no locking is required.
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"
#include <sys/mman.h>

#define IO_LOOPBACK_SLOT_SIZE       4096
#define IO_LOOPBACK_SLOT_HDR_LEN    16
#define IO_LOOPBACK_BURST           256
#define IO_LOOPBACK_HUGEPAGE_SIZE   (2 * 1024 * 1024)

extern bool g_init_phase;
extern bool g_traffic;

typedef struct io_loopback_slot_ {
    uint32_t len;
    uint32_t reserved[3];
    uint8_t packet[];
} io_loopback_slot_s;

/* Producer and consumer indices are free running and kept in separate
 * cache lines. Each side caches the last seen index of the other side
 * and reloads it only if the ring looks full (producer) or empty
 * (consumer), which avoids bouncing cache lines for every packet. */
typedef struct io_loopback_ring_ {
    uint8_t *slots;
    uint64_t mem_size;
    uint32_t size;
    uint32_t mask;
    uint32_t slot_size;

    struct {
        atomic_uint_least32_t index;
        uint32_t cons_cached;
    } prod __attribute__((__aligned__(CACHE_LINE_SIZE)));

    struct {
        atomic_uint_least32_t index;
        uint32_t prod_cached;
    } cons __attribute__((__aligned__(CACHE_LINE_SIZE)));
} io_loopback_ring_s;

static uint32_t
io_loopback_slot_size()
{
    if(g_ctx->config.jumbo_frames) {
        return IO_JUMBO_BLOCK_SIZE;
    }
    return IO_LOOPBACK_SLOT_SIZE;
}

static io_loopback_ring_s *
io_loopback_ring_alloc(uint32_t slots)
{
    io_loopback_ring_s *ring;
    uint32_t size = 2;

    while(size < slots) {
        size <<= 1;
    }

    if(posix_memalign((void**)&ring, CACHE_LINE_SIZE, sizeof(io_loopback_ring_s)) != 0) {
        return NULL;
    }
    memset(ring, 0x0, sizeof(io_loopback_ring_s));
    ring->size = size;
    ring->mask = size - 1;
    ring->slot_size = io_loopback_slot_size();
    ring->mem_size = (uint64_t)size * ring->slot_size;

    /* Back the slots with transparent huge pages if possible, as every
     * packet touches a new slot and therefore likely a new 4K page. */
    if(posix_memalign((void**)&ring->slots, IO_LOOPBACK_HUGEPAGE_SIZE, ring->mem_size) != 0) {
        free(ring);
        return NULL;
    }
    madvise(ring->slots, ring->mem_size, MADV_HUGEPAGE);
    /* Pre-fault all pages to prevent page faults in the data path. */
    memset(ring->slots, 0x0, ring->mem_size);
    return ring;
}

static inline io_loopback_slot_s *
io_loopback_ring_slot(io_loopback_ring_s *ring, uint32_t index)
{
    return (io_loopback_slot_s*)(ring->slots + ((uint64_t)(index & ring->mask) * ring->slot_size));
}

/**
 * Return number of free slots (up to n) starting
 * at the current producer index.
 */
static inline uint32_t
io_loopback_ring_reserve(io_loopback_ring_s *ring, uint32_t n)
{
    uint32_t prod = atomic_load_explicit(&ring->prod.index, memory_order_relaxed);
    uint32_t free = ring->size - (prod - ring->prod.cons_cached);
    if(free < n) {
        ring->prod.cons_cached = atomic_load_explicit(&ring->cons.index, memory_order_acquire);
        free = ring->size - (prod - ring->prod.cons_cached);
        if(free < n) {
            n = free;
        }
    }
    return n;
}

static inline void
io_loopback_ring_submit(io_loopback_ring_s *ring, uint32_t n)
{
    uint32_t prod = atomic_load_explicit(&ring->prod.index, memory_order_relaxed);
    atomic_store_explicit(&ring->prod.index, prod + n, memory_order_release);
}

/**
 * Return number of available slots (up to n) starting
 * at the current consumer index.
 */
static inline uint32_t
io_loopback_ring_peek(io_loopback_ring_s *ring, uint32_t n)
{
    uint32_t cons = atomic_load_explicit(&ring->cons.index, memory_order_relaxed);
    uint32_t avail = ring->cons.prod_cached - cons;
    if(avail < n) {
        ring->cons.prod_cached = atomic_load_explicit(&ring->prod.index, memory_order_acquire);
        avail = ring->cons.prod_cached - cons;
        if(avail < n) {
            n = avail;
        }
    }
    return n;
}

static inline void
io_loopback_ring_release(io_loopback_ring_s *ring, uint32_t n)
{
    uint32_t cons = atomic_load_explicit(&ring->cons.index, memory_order_relaxed);
    atomic_store_explicit(&ring->cons.index, cons + n, memory_order_release);
}

/**
 * This job is for loopback RX in main thread!
 */
void
io_loopback_rx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    io_loopback_ring_s *ring;
    io_loopback_slot_s *slot;
    bbl_ethernet_header_s *eth;
    uint32_t cons;
    uint32_t rcvd;
    uint32_t i;
    uint16_t r;

    protocol_error_t decode_result;
    bool pcap = false;

    assert(io->mode == IO_MODE_LOOPBACK);
    assert(io->direction == IO_INGRESS);
    assert(io->thread == NULL);

    /* Get RX timestamp */
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;

    for(r = 0; r < io->loopback_ring_count; r++) {
        ring = io->loopback_rings[r];
        while((rcvd = io_loopback_ring_peek(ring, IO_LOOPBACK_BURST))) {
            cons = atomic_load_explicit(&ring->cons.index, memory_order_relaxed);
            for(i = 0; i < rcvd; i++) {
                slot = io_loopback_ring_slot(ring, cons + i);
                io->buf = slot->packet;
                io->buf_len = slot->len;
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
            io_loopback_ring_release(ring, rcvd);
        }
    }
    if(pcap) {
        pcapng_fflush();
    }
}

/**
 * This job is for loopback TX in main thread!
 */
void
io_loopback_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;
    io_loopback_ring_s *ring = io->loopback_rings[0];

    io_loopback_slot_s *slot;
    bbl_stream_s *stream = NULL;
    uint16_t io_burst = interface->config->io_burst;
    uint32_t burst;
    uint32_t used = 0;
    uint32_t prod;
    uint64_t now;

    bool ctrl = true;
    bool pcap = false;

    assert(io->mode == IO_MODE_LOOPBACK);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    if(io->update_streams) {
        io_stream_update_pps(io);
    }

    /* Get TX timestamp */
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;
    now = timespec_to_nsec(timer->timestamp);

    burst = io_loopback_ring_reserve(ring, io_burst);
    prod = atomic_load_explicit(&ring->prod.index, memory_order_relaxed);
    while(used < burst) {
        slot = io_loopback_ring_slot(ring, prod + used);
        io->buf = slot->packet;
        if(unlikely(ctrl)) {
            /* First send all control traffic which has higher priority. */
            if(bbl_tx(interface, io->buf, &io->buf_len) != PROTOCOL_SUCCESS) {
                ctrl = false;
                continue;
            }
            /* Dump the packet into pcap file. */
            if(g_ctx->pcap.write_buf) {
                pcap = true;
                pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                          interface->ifindex, PCAPNG_EPB_FLAGS_OUTBOUND);
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
            stream->tx_packets++;
            stream->flow_seq++;
            /* Dump the packet into pcap file. */
            if(g_ctx->pcap.write_buf && g_ctx->pcap.include_streams) {
                pcap = true;
                pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                          interface->ifindex, PCAPNG_EPB_FLAGS_OUTBOUND);
            }
        }
        slot->len = io->buf_len;
        io->stats.packets++;
        io->stats.bytes += io->buf_len;
        used++;
    }
    if(burst < io_burst && used == burst) {
        /* Round was limited by free ring slots. */
        io->stats.no_buffer++;
    }
    if(used) {
        io_loopback_ring_submit(ring, used);
    }
    if(pcap) {
        pcapng_fflush();
    }
}

static void
io_loopback_thread_rx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;

    io_loopback_ring_s *ring;
    io_loopback_slot_s *slot;
    uint32_t cons;
    uint32_t rcvd;
    uint32_t total;
    uint32_t i;
    uint16_t r;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 10000; /* 0.01ms */

    /* See io_packet_mmap_thread_rx_run_fn() for the rationale behind only
     * backing off after many consecutive empty rounds. */
    uint32_t idle_rounds = 0;
    const uint32_t idle_spin_rounds = 10000;

    assert(io->mode == IO_MODE_LOOPBACK);
    assert(io->direction == IO_INGRESS);
    assert(io->thread);

    while(thread->active) {
        total = 0;
        for(r = 0; r < io->loopback_ring_count; r++) {
            ring = io->loopback_rings[r];
            rcvd = io_loopback_ring_peek(ring, IO_LOOPBACK_BURST);
            if(!rcvd) {
                continue;
            }
            total += rcvd;

            /* Get RX timestamp */
            clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
            cons = atomic_load_explicit(&ring->cons.index, memory_order_relaxed);
            for(i = 0; i < rcvd; i++) {
                slot = io_loopback_ring_slot(ring, cons + i);
                io->buf = slot->packet;
                io->buf_len = slot->len;
                io->vlan_tci = 0;
                /* Process packet */
                io_thread_rx_handler(thread, io);
            }
            io_loopback_ring_release(ring, rcvd);
        }
        if(total) {
            idle_rounds = 0;
        } else if(++idle_rounds >= idle_spin_rounds) {
            nanosleep(&sleep, &rem);
            idle_rounds = 0;
        }
    }
}

static void
io_loopback_thread_tx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;
    bbl_interface_s *interface = io->interface;
    io_loopback_ring_s *ring = io->loopback_rings[0];

    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *txq_slot;

    io_loopback_slot_s *slot;
    bbl_stream_s *stream = NULL;
    uint16_t io_burst = interface->config->io_burst;
    uint32_t burst;
    uint32_t used;
    uint32_t prod;
    uint64_t now;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 10000; /* 0.01ms */

    /* See io_packet_mmap_thread_tx_run_fn() for the rationale behind only
     * backing off after many consecutive empty rounds. */
    uint32_t idle_rounds = 0;
    const uint32_t idle_spin_rounds = 10000;

    assert(io->mode == IO_MODE_LOOPBACK);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    while(thread->active) {
        if(io->update_streams) {
            io_stream_update_pps(io);
        }

        /* Reserve ring slots for the whole burst and publish
         * them with a single producer update per round. */
        burst = io_loopback_ring_reserve(ring, io_burst);
        prod = atomic_load_explicit(&ring->prod.index, memory_order_relaxed);
        used = 0;

        /* First send all control traffic which has higher priority. */
        while(used < burst && (txq_slot = bbl_txq_read_slot(txq))) {
            slot = io_loopback_ring_slot(ring, prod + used);
            memcpy(slot->packet, txq_slot->packet, txq_slot->packet_len);
            slot->len = txq_slot->packet_len;
            used++;
            io->stats.packets++;
            io->stats.bytes += txq_slot->packet_len;
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
                slot = io_loopback_ring_slot(ring, prod + used);
                memcpy(slot->packet, stream->tx_buf, stream->tx_len);
                slot->len = stream->tx_len;
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
            /* Round was limited by free ring slots. */
            io->stats.no_buffer++;
        }
        if(used) {
            io_loopback_ring_submit(ring, used);
            idle_rounds = 0;
        } else if(++idle_rounds >= idle_spin_rounds) {
            nanosleep(&sleep, &rem);
            idle_rounds = 0;
        }
    }
}

static bool
io_loopback_add_ring(io_handle_s *io, io_loopback_ring_s *ring)
{
    io_loopback_ring_s **rings;

    rings = realloc(io->loopback_rings, (io->loopback_ring_count + 1) * sizeof(io_loopback_ring_s*));
    if(!rings) {
        return false;
    }
    rings[io->loopback_ring_count++] = ring;
    io->loopback_rings = rings;
    return true;
}

/**
 * Create one ring per TX IO handle of the source interface,
 * each read by one RX IO handle of the destination interface.
 */
static bool
io_loopback_connect(bbl_interface_s *src, bbl_interface_s *dst)
{
    io_handle_s *tx_io = src->io.tx;
    io_handle_s *rx_io = dst->io.rx;
    io_loopback_ring_s *ring;
    uint16_t rings = 0;

    while(tx_io) {
        ring = io_loopback_ring_alloc(src->config->io_slots_tx);
        if(!ring) {
            LOG(ERROR, "Loopback: failed to allocate ring from interface %s to %s\n",
                src->name, dst->name);
            return false;
        }
        if(!rx_io) {
            /* Distribute rings round-robin over RX IO handles. */
            rx_io = dst->io.rx;
        }
        if(!(io_loopback_add_ring(tx_io, ring) && io_loopback_add_ring(rx_io, ring))) {
            return false;
        }
        rx_io = rx_io->next;
        tx_io = tx_io->next;
        rings++;
    }
    LOG(DEBUG, "Loopback: interface %s connected to %s via %u ring%s\n",
        src->name, dst->name, rings, rings == 1 ? "" : "s");
    return true;
}

static char *
io_loopback_peer_name(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;
    bbl_link_config_s *peer_config = g_ctx->config.link_config;

    if(config->loopback_peer) {
        return config->loopback_peer;
    }
    /* Peer might be configured on the other side only. */
    while(peer_config) {
        if(peer_config->loopback_peer &&
           strcmp(peer_config->loopback_peer, interface->name) == 0) {
            return peer_config->interface;
        }
        peer_config = peer_config->next;
    }
    return NULL;
}

static bool
io_loopback_check_peer(bbl_interface_s *interface, char *peer)
{
    bbl_link_config_s *peer_config = g_ctx->config.link_config;

    if(!peer) {
        LOG(ERROR, "Loopback: missing loopback-peer for interface %s\n", interface->name);
        return false;
    }
    if(strcmp(peer, interface->name) == 0) {
        LOG(ERROR, "Loopback: interface %s can not be its own loopback-peer\n", interface->name);
        return false;
    }
    while(peer_config) {
        if(strcmp(peer_config->interface, peer) == 0) {
            break;
        }
        peer_config = peer_config->next;
    }
    if(!peer_config) {
        LOG(ERROR, "Loopback: loopback-peer %s of interface %s not found\n", peer, interface->name);
        return false;
    }
    if(peer_config->io_mode != IO_MODE_LOOPBACK) {
        LOG(ERROR, "Loopback: loopback-peer %s of interface %s is not in io-mode loopback\n",
            peer, interface->name);
        return false;
    }
    if(peer_config->loopback_peer && strcmp(peer_config->loopback_peer, interface->name) != 0) {
        LOG(ERROR, "Loopback: loopback-peer %s of interface %s is connected to %s\n",
            peer, interface->name, peer_config->loopback_peer);
        return false;
    }
    return true;
}

bool
io_loopback_interface_init(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;
    bbl_interface_s *peer_interface;
    char *peer = io_loopback_peer_name(interface);

    io_handle_s *io;
    uint16_t count;

    if(!io_loopback_check_peer(interface, peer)) {
        return false;
    }

    if(*(uint32_t*)config->mac) {
        memcpy(interface->mac, config->mac, ETH_ADDR_LEN);
    } else {
        /* Locally administered unicast address. */
        interface->mac[0] = 0x02;
        interface->mac[1] = 0xbb;
        interface->mac[2] = 0x1b;
        interface->mac[3] = 0x00;
        interface->mac[4] = (interface->ifindex >> 8) & 0xff;
        interface->mac[5] = interface->ifindex & 0xff;
    }

    if((config->rx_auto_cpuset && !config->rx_cpuset_count) ||
       (config->tx_auto_cpuset && !config->tx_cpuset_count)) {
        if(!io_interface_init_topology(interface, -1)) {
            LOG(ERROR, "Failed to discover local CPU topology for interface %s\n", interface->name);
            return false;
        }
    }

    count = config->rx_threads ? config->rx_threads : 1;
    while(count) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --count;
        io->mode = IO_MODE_LOOPBACK;
        io->direction = IO_INGRESS;
        io->interface = interface;
        io->fd = -1;
        io->next = interface->io.rx;
        interface->io.rx = io;
        if(config->rx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
            io->thread->run_fn = io_loopback_thread_rx_run_fn;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.rx_job, "RX", 0,
                               config->rx_interval, io, &io_loopback_rx_job);
        }
    }

    count = config->tx_threads ? config->tx_threads : 1;
    while(count) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --count;
        io->mode = IO_MODE_LOOPBACK;
        io->direction = IO_EGRESS;
        io->interface = interface;
        io->fd = -1;
        io->next = interface->io.tx;
        interface->io.tx = io;
        if(config->tx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
            io->thread->run_fn = io_loopback_thread_tx_run_fn;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.tx_job, "TX", 0,
                               config->tx_interval, io, &io_loopback_tx_job);
        }
    }

    /* The rings are created once both sides are initialized,
     * because both RX and TX queue counts are required. */
    peer_interface = bbl_interface_get(peer);
    if(peer_interface && peer_interface != interface && peer_interface->io.rx) {
        if(!io_loopback_connect(interface, peer_interface)) {
            return false;
        }
        if(!io_loopback_connect(peer_interface, interface)) {
            return false;
        }
        LOG(INFO, "Loopback: interface %s connected to %s\n", interface->name, peer);
    }
    return true;
}

void
io_loopback_set_max_stream_len()
{
    uint16_t len = io_loopback_slot_size() - IO_LOOPBACK_SLOT_HDR_LEN - BBL_MAX_STREAM_OVERHEAD;
    if(len < g_ctx->config.io_max_stream_len) {
        LOG(DEBUG, "Set max allowed stream length to %u because of loopback slot size\n", len);
        g_ctx->config.io_max_stream_len = len;
    }
}
