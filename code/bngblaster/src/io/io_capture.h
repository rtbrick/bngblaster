/*
 * BNG Blaster (BBL) - IO Stream Capture
 *
 * Christian Giese, Andreas Zimber, October 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_CAPTURE_H__
#define __BBL_IO_CAPTURE_H__

typedef struct io_capture_slot_ {
    struct timespec timestamp;
    uint8_t *packet; /* allocated on demand */
    uint16_t packet_len;
    uint16_t capacity;
    uint16_t vlan_tci;
    uint16_t vlan_tpid; /* stripped outer VLAN if not zero */
} io_capture_slot_s;

/* Single producer (I/O thread), single consumer (main thread) queue. */
typedef struct io_capture_ {
    io_capture_slot_s *slots;
    uint16_t size;
    atomic_bool active; /* PCAP open, updated by main thread */

    char _pad0 __attribute__((__aligned__(CACHE_LINE_SIZE)));

    atomic_uint_least16_t write;
    uint16_t read_cache; /* producer copy of read */
    atomic_uint_least64_t dropped; /* only written by producer */
    atomic_uint_least64_t alloc_failed;

    char _pad1 __attribute__((__aligned__(CACHE_LINE_SIZE)));

    atomic_uint_least16_t read;
    uint64_t dropped_total; /* last values read by consumer */
    uint64_t alloc_failed_total;
} io_capture_s;

static inline __attribute__((always_inline)) bool
io_capture_active(io_thread_s *thread)
{
    return thread->capture &&
           atomic_load_explicit(&thread->capture->active, memory_order_relaxed);
}

bool
io_capture_init(io_thread_s *thread, uint16_t size);

void
io_capture_free(io_thread_s *thread);

void
io_capture_packet(io_handle_s *io, const uint8_t *packet, uint16_t packet_len);

void
io_capture_drain(io_thread_s *thread);

#endif
