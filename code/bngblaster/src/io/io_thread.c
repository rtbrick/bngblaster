/*
 * BNG Blaster (BBL) - IO RX Threads
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

static bool g_io_cpu_reserved[CPU_SETSIZE];

/** 
 * This function redirects the packet in the
 * IO buffer to the main thread via the TXQ 
 * ring buffer. 
 * 
 * @param thread thread handle
 * @param io IO handle
 * @return IO_REDIRECT if successfully redirected
 */
static io_result_t
redirect(io_thread_s *thread, io_handle_s *io)
{
    bbl_txq_slot_t *slot;

    assert(io->direction == IO_INGRESS);
    assert(io->thread != NULL);
    if(io->buf_len > BBL_TXQ_BUFFER_LEN) {
        io->stats.to_long++;
        return IO_ERROR;
    }

    if((slot = bbl_txq_write_slot(thread->txq))) {
        slot->timestamp.tv_sec = io->timestamp.tv_sec;
        slot->timestamp.tv_nsec = io->timestamp.tv_nsec;
        slot->vlan_tci = io->vlan_tci;
        slot->vlan_tpid = io->vlan_tpid;
        slot->packet_len = io->buf_len;
        memcpy(slot->packet, io->buf, io->buf_len);
        bbl_txq_write_next(thread->txq);
        return IO_REDIRECT;
    }
    return IO_FULL;
}

/** 
 * This function processes all received packets
 * from RX threads. 
 * 
 * @param thread thread handle
 * @param io IO handle
 * @return IO result
 */
static inline __attribute__((always_inline)) io_result_t
rx_handler(io_thread_s *thread, io_handle_s *io)
{
    assert(io->direction == IO_INGRESS);
    assert(io->thread != NULL);

    bbl_ethernet_header_s *eth;
    uint16_t vlan;

    protocol_error_t decode_result;

    io->stats.packets++;
    io->stats.bytes += io->buf_len;
    if(packet_is_bbl(io->buf, io->buf_len)) {
        /** Process */
        decode_result = decode_ethernet(io->buf, io->buf_len, thread->sp, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            if(io->vlan_tci) {
                vlan = io->vlan_tci & BBL_ETH_VLAN_ID_MAX;
                /* Restore outer VLAN */
                eth->vlan_inner = eth->vlan_outer;
                eth->vlan_inner_priority = eth->vlan_outer_priority;
                eth->vlan_outer = vlan;
                eth->vlan_outer_priority = io->vlan_tci >> 13;
                if(io->vlan_tpid == ETH_TYPE_QINQ) {
                    eth->qinq = true;
                }
            }
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = io->timestamp.tv_sec;
            eth->timestamp.tv_nsec = io->timestamp.tv_nsec;
            if(bbl_rx_thread(io->interface, eth)) {
                return IO_SUCCESS;
            }
        } else if(decode_result == UNKNOWN_PROTOCOL) {
            io->stats.unknown++;
        } else {
            io->stats.protocol_errors++;
        }
    }
    /** Redirect to main thread. */
    return redirect(thread, io);
}

io_result_t
io_thread_rx_handler(io_thread_s *thread, io_handle_s *io)
{
    return rx_handler(thread, io);
}

/* Number of packets each prefetch stage runs ahead of the next one. */
#define IO_RX_PREFETCH_DISTANCE 4

/* Minimum number of streams to prefetch stream state. With
 * less streams, their RX cache lines stay in the CPU cache
 * and prefetching them would only add overhead. */
#define IO_RX_PREFETCH_STREAMS_MIN 256

static inline __attribute__((always_inline)) void
rx_prefetch_packet(uint8_t *buf, uint16_t len)
{
    uint8_t *bbl;
    if(len >= BBL_MIN_LEN) {
        bbl = buf + len - BBL_HEADER_LEN;
        __builtin_prefetch(buf);
        __builtin_prefetch(bbl);
        __builtin_prefetch(bbl + BBL_HEADER_LEN - 1);
    }
}

/**
 * This function processes a burst of received packets
 * from RX threads.
 *
 * The stream lookup of each packet depends on a chain of
 * memory loads (packet, stream index, stream), which miss
 * the cache with many flows. Those loads are prefetched in
 * a software pipeline running ahead of packet processing,
 * so that the cache misses of multiple packets overlap:
 *
 * Stage 1: prefetch packet and BBL header (trailer)
 * Stage 2: read flow-id and prefetch stream index entry
 * Stage 3: read stream index and prefetch stream RX cache line
 * Stage 4: process packet
 *
 * With only a few streams, stages 2 and 3 are skipped.
 *
 * @param thread thread handle
 * @param io IO handle
 * @param bufs packet buffers
 * @param lens packet lengths
 * @param count number of packets (max IO_RX_BURST_MAX)
 */
void
io_thread_rx_burst(io_thread_s *thread, io_handle_s *io,
                   uint8_t **bufs, uint16_t *lens, uint16_t count)
{
    uint32_t flow_ids[IO_RX_BURST_MAX];
    uint32_t flow_id;
    bbl_stream_s *stream;
    uint8_t *bbl;
    int i, j;

    assert(count <= IO_RX_BURST_MAX);

    if(g_ctx->streams < IO_RX_PREFETCH_STREAMS_MIN) {
        for(i = 0; i < count + IO_RX_PREFETCH_DISTANCE; i++) {
            if(i < count) {
                rx_prefetch_packet(bufs[i], lens[i]);
            }
            j = i - IO_RX_PREFETCH_DISTANCE;
            if(j >= 0) {
                io->buf = bufs[j];
                io->buf_len = lens[j];
                if(rx_handler(thread, io) == IO_FULL) {
                    io->stats.dropped++;
                }
            }
        }
        return;
    }

    for(i = 0; i < count + 3 * IO_RX_PREFETCH_DISTANCE; i++) {
        /* Stage 1 */
        if(i < count) {
            rx_prefetch_packet(bufs[i], lens[i]);
        }
        /* Stage 2 */
        j = i - IO_RX_PREFETCH_DISTANCE;
        if(j >= 0 && j < count) {
            flow_id = 0;
            if(packet_is_bbl(bufs[j], lens[j])) {
                bbl = bufs[j] + lens[j] - BBL_HEADER_LEN;
                flow_id = *(uint32_t*)(bbl + BBL_FLOW_ID_OFFSET);
                if(g_ctx->stream_index && flow_id <= g_ctx->streams && flow_id > 0) {
                    __builtin_prefetch(&g_ctx->stream_index[flow_id-1]);
                } else {
                    flow_id = 0;
                }
            }
            flow_ids[j] = flow_id;
        }
        /* Stage 3 */
        j -= IO_RX_PREFETCH_DISTANCE;
        if(j >= 0 && j < count && flow_ids[j]) {
            stream = g_ctx->stream_index[flow_ids[j]-1];
            if(stream) {
                __builtin_prefetch(&stream->rx_packets, 1);
            }
        }
        /* Stage 4 */
        j -= IO_RX_PREFETCH_DISTANCE;
        if(j >= 0) {
            io->buf = bufs[j];
            io->buf_len = lens[j];
            if(rx_handler(thread, io) == IO_FULL) {
                io->stats.dropped++;
            }
        }
    }
}

/**
 * This job is scheduled in the main loop receiving
 * packets from a RX thread via TXQ ring buffer. 
 */
void
io_thread_main_rx_job(timer_s *timer)
{
    bbl_interface_s *interface = timer->data;

    io_handle_s *io = interface->io.rx;
    io_thread_s *thread;

    bbl_txq_slot_t *slot;
    bbl_ethernet_header_s *eth;
    uint16_t vlan;

    protocol_error_t decode_result;
    bool pcap = false;
    while(io) {
        thread = io->thread;
        if(thread) {
            while((slot = bbl_txq_read_slot(thread->txq))) {
                decode_result = decode_ethernet(slot->packet, slot->packet_len, g_ctx->sp, SCRATCHPAD_LEN, &eth);
                if(decode_result == PROTOCOL_SUCCESS) {
                    if(slot->vlan_tci) {
                        vlan = slot->vlan_tci & BBL_ETH_VLAN_ID_MAX;
                        /* Restore outer VLAN */
                        eth->vlan_inner = eth->vlan_outer;
                        eth->vlan_inner_priority = eth->vlan_outer_priority;
                        eth->vlan_outer = vlan;
                        eth->vlan_outer_priority = slot->vlan_tci >> 13;
                        if(slot->vlan_tpid == ETH_TYPE_QINQ) {
                            eth->qinq = true;
                        }
                    }
                    /* Copy RX timestamp */
                    eth->timestamp.tv_sec = slot->timestamp.tv_sec;
                    eth->timestamp.tv_nsec = slot->timestamp.tv_nsec;
                    /* Dump the packet into pcap file. */
                    if(g_ctx->pcap.write_buf && (!eth->bbl || g_ctx->pcap.include_streams)) {
                        pcap = true;
                        pcapng_push_packet_header(&slot->timestamp, slot->packet, slot->packet_len,
                                                  interface->ifindex, PCAPNG_EPB_FLAGS_INBOUND);
                    }
                    bbl_rx_handler(interface, eth);
                } else {
                    /* Dump the packet into pcap file. */
                    if(g_ctx->pcap.write_buf) {
                        pcap = true;
                        pcapng_push_packet_header(&slot->timestamp, slot->packet, slot->packet_len,
                                                  interface->ifindex, PCAPNG_EPB_FLAGS_INBOUND);
                    }
                    if(decode_result == UNKNOWN_PROTOCOL) {
                        io->stats.unknown++;
                    } else {
                        io->stats.protocol_errors++;
                    }
                }
                bbl_txq_read_next(thread->txq);
            }
        }
        io = io->next;
    }
    if(pcap) {
        pcapng_fflush();
    }
}

/** 
 * This job is scheduled in the main loop sending 
 * packets to the TX thread via TXQ ring buffer. 
 */
void
io_thread_main_tx_job(timer_s *timer)
{
    bbl_interface_s *interface = timer->data;
    io_handle_s *io = interface->io.tx;
    io_thread_s *thread = io->thread;
    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *slot;

    protocol_error_t tx_result = IGNORED;

    bool pcap = false;

    /* Get TX timestamp */
    struct timespec timestamp;
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    while((slot = bbl_txq_write_slot(txq))) {
        tx_result = bbl_tx(interface, slot->packet, &slot->packet_len);
        if(tx_result == PROTOCOL_SUCCESS) {
            /* Dump the packet into pcap file. */
            if(g_ctx->pcap.write_buf) {
                pcap = true;
                pcapng_push_packet_header(&timestamp, slot->packet, slot->packet_len,
                                          interface->ifindex, PCAPNG_EPB_FLAGS_OUTBOUND);
            }
            bbl_txq_write_next(txq);
        } else if(tx_result == EMPTY) {
            break;
        }
    }
    if(pcap) {
        pcapng_fflush();
    }
}

void *
io_thread_main(void *thread_data)
{
    io_thread_s *thread = thread_data;
    if(thread->setup_fn) {
        (*thread->setup_fn)(thread);
    }
    if(thread->run_fn) {
        (*thread->run_fn)(thread);
    }
    if(thread->teardown_fn) {
        (*thread->teardown_fn)(thread);
    }
    thread->active = false;
    thread->stopped = true;
    return NULL;
}

/**
 * Select a CPU for an I/O thread from the CPUs local to the
 * interface, preferring CPUs which are neither used by other
 * I/O threads nor handling NIC interrupts.
 *
 * @param thread thread handle
 * @param io IO handle
 * @param irq_cpus CPUs handling NIC interrupts
 * @return true if CPU affinity is set
 */
static bool
io_thread_auto_affinity(io_thread_s *thread, io_handle_s *io, bool *irq_cpus)
{
    bbl_interface_s *interface = io->interface;
    bbl_link_config_s *config = interface->config;
    uint16_t *cursor = NULL;
    uint16_t start;
    uint16_t index;
    uint16_t cpu;
    int pass;

    if(!interface->local_cpuset_count) {
        return false;
    }

    if(io->direction == IO_INGRESS) {
        if(!(config->rx_auto_cpuset && !config->rx_cpuset_count)) {
            return false;
        }
        cursor = &config->rx_cpuset_cur;
    } else {
        if(!(config->tx_auto_cpuset && !config->tx_cpuset_count)) {
            return false;
        }
        cursor = &config->tx_cpuset_cur;
    }

    thread->set_cpu_affinity = true;
    CPU_ZERO(&thread->cpuset);

    start = *cursor % interface->local_cpuset_count;
    for(pass = 0; pass < 2; pass++) {
        for(index = 0; index < interface->local_cpuset_count; index++) {
            cpu = interface->local_cpuset[(start + index) % interface->local_cpuset_count];
            if(cpu >= CPU_SETSIZE || g_io_cpu_reserved[cpu]) {
                continue;
            }
            /* Use CPUs handling NIC interrupts only if no other CPU is free. */
            if(pass == 0 && irq_cpus[cpu]) {
                continue;
            }
            CPU_SET(cpu, &thread->cpuset);
            thread->selected_cpu = cpu;
            g_io_cpu_reserved[cpu] = true;
            *cursor = (start + index + 1) % interface->local_cpuset_count;
            return true;
        }
    }

    cpu = interface->local_cpuset[start];
    CPU_SET(cpu, &thread->cpuset);
    thread->selected_cpu = cpu;
    *cursor = (start + 1) % interface->local_cpuset_count;
    LOG(INFO, "Warning: No free CPU for %s thread of interface %s, sharing CPU %u with another thread\n",
        io->direction == IO_INGRESS ? "RX" : "TX", interface->name, cpu);
    return true;
}

bool
io_thread_init(io_handle_s *io)
{
    bbl_interface_s *interface = io->interface;
    bbl_link_config_s *config = interface->config;
    io_thread_s *thread;

    uint16_t slots = config->io_slots_tx;
    if(io->direction == IO_INGRESS) {
        LOG(DEBUG, "Init RX thread for interface %s\n", interface->name);
        slots = config->io_slots_rx;
    } else {
        LOG(DEBUG, "Init TX thread for interface %s\n", interface->name);
    }

    /* Add thread */
    thread = calloc(1, sizeof(io_thread_s));
    thread->next = g_ctx->io_threads;
    g_ctx->io_threads = thread;

    io->thread = thread;
    thread->io = io;
    io->fanout_id = interface->kernel_index;
    io->fanout_type = PACKET_FANOUT_HASH;

    /* Allocate thread scratchpad memory */
    thread->sp = malloc(SCRATCHPAD_LEN);

    /* Init thread TXQ */
    thread->txq = bbl_txq_alloc(slots);
    if(!thread->txq) {
        return false;
    }

    /* Init thread mutex */
    if(pthread_mutex_init(&thread->mutex, NULL) != 0) {
        LOG_NOARG(ERROR, "Failed to init mutex\n");
        return false;
    }

    /* Default run function which might be overwritten */
    thread->run_fn = NULL;

    /* Add thread main loop timers/jobs */
    if(io->direction == IO_INGRESS && !interface->io.rx_job) {
        /** Start job reading from RX thread TXQ */
        timer_add_periodic(&g_ctx->timer_root, &interface->io.rx_job, "RX", 
                           0, config->rx_interval, 
                           interface, &io_thread_main_rx_job);
    }

    if(io->direction == IO_EGRESS && !interface->io.tx_job) {
        /** Start job writing to first TX thread TXQ */
        timer_add_periodic(&g_ctx->timer_root, &interface->io.tx_job, "TX", 
                           0, config->tx_interval, 
                           interface, &io_thread_main_tx_job);
    }

    /* Set CPU affinity */
    if(io->direction == IO_INGRESS && config->rx_cpuset_count) {
        thread->set_cpu_affinity = true;
        CPU_ZERO(&thread->cpuset);
        thread->selected_cpu = config->rx_cpuset[config->rx_cpuset_cur++];
        
        if(thread->selected_cpu < CPU_SETSIZE) {
            CPU_SET(thread->selected_cpu, &thread->cpuset);
        }
        if(thread->selected_cpu < CPU_SETSIZE) {
            g_io_cpu_reserved[thread->selected_cpu] = true;
        }

        if(config->rx_cpuset_cur >= config->rx_cpuset_count) {
            config->rx_cpuset_cur = 0;
        }
    }
    if(io->direction == IO_EGRESS && config->tx_cpuset_count) {
        thread->set_cpu_affinity = true;
        CPU_ZERO(&thread->cpuset);
        thread->selected_cpu = config->tx_cpuset[config->tx_cpuset_cur++];
        
        if(thread->selected_cpu < CPU_SETSIZE) {
            CPU_SET(thread->selected_cpu, &thread->cpuset);
        }
        if(thread->selected_cpu < CPU_SETSIZE) {
            g_io_cpu_reserved[thread->selected_cpu] = true;
        }

        if(config->tx_cpuset_cur >= config->tx_cpuset_count) {
            config->tx_cpuset_cur = 0;
        }
    }
    /* Automatic CPU affinity is selected with all threads started,
     * when the CPUs of all manually pinned threads and the NIC
     * interrupts of all interfaces are known. */
    return true;
}

/**
 * Select CPUs for threads without manual CPU affinity and
 * warn about threads running on CPUs handling NIC interrupts.
 */
static void
io_thread_set_affinity_all()
{
    io_thread_s *thread;
    bbl_interface_s *interface;
    bool irq_cpus[CPU_SETSIZE] = {0};
    uint16_t irqs;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        irqs = io_interface_irq_cpus(interface, irq_cpus);
        if(irqs) {
            LOG(DEBUG, "Found %u interrupts of interface %s\n", irqs, interface->name);
        }
    }

    thread = g_ctx->io_threads;
    while(thread) {
        if(!thread->set_cpu_affinity) {
            io_thread_auto_affinity(thread, thread->io, irq_cpus);
        }
        if(thread->set_cpu_affinity &&
           thread->selected_cpu < CPU_SETSIZE && irq_cpus[thread->selected_cpu]) {
            LOG(INFO, "Warning: %s thread of interface %s runs on CPU %d which handles NIC interrupts, "
                "this may limit the throughput (see /proc/interrupts)\n",
                thread->io->direction == IO_INGRESS ? "RX" : "TX",
                thread->io->interface->name, thread->selected_cpu);
        }
        thread = thread->next;
    }
}

void
io_thread_start_all()
{
    io_thread_s *thread = g_ctx->io_threads;
    struct timespec sleep = {0};
    struct timespec rem = {0};
    char name[16]; /* thread names are limited to 15 characters */
    cpu_set_t cpuset;
    int threads = 0;

    /* Each I/O thread and the main thread should have its own CPU,
     * otherwise threads are delayed, which causes packet loss. */
    while(thread) {
        threads++;
        thread = thread->next;
    }
    if(threads && sched_getaffinity(0, sizeof(cpuset), &cpuset) == 0 &&
       threads + 1 > CPU_COUNT(&cpuset)) {
        LOG(INFO, "Warning: %d I/O threads plus main thread exceed %d available CPUs\n",
            threads, CPU_COUNT(&cpuset));
    }
    io_thread_set_affinity_all();
    thread = g_ctx->io_threads;

    sleep.tv_nsec = 7800179; /* prime number between 7 and 8ms */
    while(thread) {
        thread->active = true;
        pthread_create(&thread->thread, NULL, io_thread_main, (void *)thread);
        /* Thread name with direction first, so that it is kept
         * if long interface names are truncated (e.g. rx0-eth1). */
        snprintf(name, sizeof(name), "%s%d-%s",
                 thread->io->direction == IO_INGRESS ? "rx" : "tx",
                 thread->io->id, thread->io->interface->name);
        pthread_setname_np(thread->thread, name);
        if(thread->set_cpu_affinity) {
            if(pthread_setaffinity_np(thread->thread, sizeof(cpu_set_t), &thread->cpuset)) {
                LOG_NOARG(ERROR, "Failed to set thread CPU affinity\n");
                return;
            }
        }

        nanosleep(&sleep, &rem);
        thread = thread->next;
    }
}

void
io_thread_stop_all()
{
    io_thread_s *thread = g_ctx->io_threads;
    while(thread) {
        thread->active = false;
        thread = thread->next;
    }
    /* Wait for threads to be stopped */
    thread = g_ctx->io_threads;
    while(thread) {
        pthread_join(thread->thread, NULL);
        thread = thread->next;
    }
}
