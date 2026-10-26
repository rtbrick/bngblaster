/*
 * BNG Blaster (BBL) - IO Stream Capture
 *
 * I/O threads copy stream packets into per-thread queues, which
 * are drained by the main thread as the only PCAP writer.
 *
 * Christian Giese, Andreas Zimber, October 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

/* Allocation granularity of packet buffers, so that
 * streams of different length do not realloc. */
#define IO_CAPTURE_ALLOC_ALIGN 256

static void
io_capture_job(timer_s *timer)
{
    io_capture_drain(timer->data);
}

bool
io_capture_init(io_thread_s *thread, uint16_t size)
{
    io_capture_s *capture = aligned_alloc(CACHE_LINE_SIZE, sizeof(io_capture_s));
    if(!capture) return false;
    memset(capture, 0x0, sizeof(io_capture_s));
    capture->size = size < 2 ? 2 : size;
    capture->slots = calloc(capture->size, sizeof(io_capture_slot_s));
    if(!capture->slots) {
        free(capture);
        return false;
    }
    atomic_init(&capture->active, g_ctx->pcap.write_buf != NULL);
    atomic_init(&capture->write, 0);
    atomic_init(&capture->read, 0);
    atomic_init(&capture->dropped, 0);
    atomic_init(&capture->alloc_failed, 0);
    thread->capture = capture;
    timer_add_periodic(&g_ctx->timer_root, &thread->capture_job, "IO Capture",
                       0, thread->io->interface->config->rx_interval,
                       thread, &io_capture_job);
    return true;
}

static void
io_capture_log(io_thread_s *thread, uint64_t dropped, uint64_t alloc_failed)
{
    LOG(ERROR, "Incomplete stream capture on %s (%s thread %u): "
        "%" PRIu64 " packets dropped (queue full), %" PRIu64 " (allocation failed)\n",
        thread->io->interface->name,
        thread->io->direction == IO_INGRESS ? "RX" : "TX",
        thread->io->id, dropped, alloc_failed);
}

void
io_capture_free(io_thread_s *thread)
{
    io_capture_s *capture = thread->capture;
    uint16_t i;

    if(!capture) return;
    timer_del(thread->capture_job);
    io_capture_drain(thread);
    if(capture->dropped_total || capture->alloc_failed_total) {
        io_capture_log(thread, capture->dropped_total, capture->alloc_failed_total);
    }
    for(i = 0; i < capture->size; i++) {
        free(capture->slots[i].packet);
    }
    free(capture->slots);
    free(capture);
    thread->capture = NULL;
}

/* Counters are only written by the I/O thread,
 * which allows to increment without locked instruction. */
static inline void
io_capture_count(atomic_uint_least64_t *counter)
{
    atomic_store_explicit(counter, atomic_load_explicit(counter, memory_order_relaxed) + 1,
                          memory_order_relaxed);
}

/**
 * Copy packet to the capture queue (I/O thread).
 *
 * The caller must check io_capture_active() before.
 */
void
io_capture_packet(io_handle_s *io, const uint8_t *packet, uint16_t packet_len)
{
    io_capture_s *capture = io->thread->capture;
    io_capture_slot_s *slot;
    uint8_t *buf;
    uint16_t write, next, capacity;

    write = atomic_load_explicit(&capture->write, memory_order_relaxed);
    next = (write + 1) % capture->size;
    if(next == capture->read_cache) {
        capture->read_cache = atomic_load_explicit(&capture->read, memory_order_acquire);
        if(next == capture->read_cache) {
            io_capture_count(&capture->dropped);
            return;
        }
    }
    slot = &capture->slots[write];
    if(packet_len > slot->capacity) {
        capacity = (packet_len + IO_CAPTURE_ALLOC_ALIGN - 1) & ~(IO_CAPTURE_ALLOC_ALIGN - 1);
        if(capacity < packet_len) capacity = packet_len;
        buf = realloc(slot->packet, capacity);
        if(!buf) {
            io_capture_count(&capture->alloc_failed);
            return;
        }
        slot->packet = buf;
        slot->capacity = capacity;
    }
    memcpy(slot->packet, packet, packet_len);
    slot->packet_len = packet_len;
    slot->timestamp = io->timestamp;
    if(io->direction == IO_INGRESS) {
        slot->vlan_tci = io->vlan_tci;
        slot->vlan_tpid = io->vlan_tpid;
    } else {
        slot->vlan_tci = 0;
        slot->vlan_tpid = 0;
    }
    atomic_store_explicit(&capture->write, next, memory_order_release);
}

/**
 * Write queued packets to the PCAP file (main thread).
 *
 * Packets queued while no PCAP is open (e.g. after
 * pcap-stop) are discarded and the I/O thread stops
 * capturing until the next PCAP is opened.
 */
void
io_capture_drain(io_thread_s *thread)
{
    io_capture_s *capture = thread->capture;
    io_handle_s *io = thread->io;
    io_capture_slot_s *slot;
    uint16_t read, write;
    uint32_t flags;
    uint64_t dropped, alloc_failed;
    bool pcap = g_ctx->pcap.write_buf != NULL;

    if(!capture) return;
    atomic_store_explicit(&capture->active, pcap, memory_order_relaxed);

    read = atomic_load_explicit(&capture->read, memory_order_relaxed);
    write = atomic_load_explicit(&capture->write, memory_order_acquire);
    if(read != write) {
        if(pcap) {
            flags = io->direction == IO_INGRESS ? PCAPNG_EPB_FLAGS_INBOUND : PCAPNG_EPB_FLAGS_OUTBOUND;
            while(read != write) {
                slot = &capture->slots[read];
                pcapng_push_packet_header_vlan(&slot->timestamp, slot->packet, slot->packet_len,
                                               io->interface->ifindex, flags,
                                               slot->vlan_tpid, slot->vlan_tci);
                read = (read + 1) % capture->size;
            }
            pcapng_fflush();
        }
        atomic_store_explicit(&capture->read, write, memory_order_release);
    }

    dropped = atomic_load_explicit(&capture->dropped, memory_order_relaxed);
    alloc_failed = atomic_load_explicit(&capture->alloc_failed, memory_order_relaxed);
    if(dropped != capture->dropped_total || alloc_failed != capture->alloc_failed_total) {
        /* Log once, totals are logged when the thread stops. */
        if(!(capture->dropped_total || capture->alloc_failed_total)) {
            io_capture_log(thread, dropped, alloc_failed);
        }
        capture->dropped_total = dropped;
        capture->alloc_failed_total = alloc_failed;
    }
}
