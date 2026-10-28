/*
 * BNG Blaster (BBL) - IO RX Threads
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"
#include <sys/syscall.h>
#include <dirent.h>
#include <sys/file.h>

static bool g_io_cpu_reserved[CPU_SETSIZE];
/* CPU locks of this instance, see io_thread_cpu_lock(). */
static bool g_io_cpu_locked[CPU_SETSIZE];
static int g_io_cpu_lock_fd[CPU_SETSIZE];
/* Number of other instances using a CPU, see io_thread_cpu_scan(). */
static uint16_t g_io_cpu_users[CPU_SETSIZE];

/* All I/O threads are started and the main thread pinned (CPU or -1). */
static volatile bool g_io_threads_started;
static int g_io_main_cpu = -1;

/* CPUs allowed for this process (e.g. restricted with taskset or a
 * cgroup cpuset), saved at startup before DPDK pins the main thread. */
static cpu_set_t g_io_cpu_allowed;
static bool g_io_cpu_allowed_saved;

void
io_thread_save_allowed_cpus()
{
    CPU_ZERO(&g_io_cpu_allowed);
    g_io_cpu_allowed_saved = sched_getaffinity(0, sizeof(cpu_set_t), &g_io_cpu_allowed) == 0;
}

bool
io_thread_cpu_allowed(uint16_t cpu)
{
    if(!g_io_cpu_allowed_saved) {
        return true;
    }
    return cpu < CPU_SETSIZE && CPU_ISSET(cpu, &g_io_cpu_allowed);
}

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
                if(unlikely(io_capture_active(thread))) io_capture_packet(io, io->buf, io->buf_len);
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
                        pcapng_push_packet_header_vlan(&slot->timestamp, slot->packet, slot->packet_len,
                                                       interface->ifindex, PCAPNG_EPB_FLAGS_INBOUND,
                                                       slot->vlan_tpid, slot->vlan_tci);
                    }
                    bbl_rx_handler(interface, eth);
                } else {
                    /* Dump the packet into pcap file. */
                    if(g_ctx->pcap.write_buf) {
                        pcap = true;
                        pcapng_push_packet_header_vlan(&slot->timestamp, slot->packet, slot->packet_len,
                                                       interface->ifindex, PCAPNG_EPB_FLAGS_INBOUND,
                                                       slot->vlan_tpid, slot->vlan_tci);
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

/* Thread name with direction first, so that it is kept
 * if long interface names are truncated (e.g. rx0-eth1). */
static void
io_thread_name(io_thread_s *thread, char *name, size_t len)
{
    snprintf(name, len, "%s%d-%s",
             thread->io->direction == IO_INGRESS ? "rx" : "tx",
             thread->io->id, thread->io->interface->name);
}

void *
io_thread_main(void *thread_data)
{
    io_thread_s *thread = thread_data;
    char name[16];

    teardown_signals_block();
    thread->tid = syscall(SYS_gettid);
    io_thread_name(thread, name, sizeof(name));
    if(thread->set_cpu_affinity) {
        LOG(INFO, "Started I/O thread %s (TID %d) on CPU %d%s%s\n",
            name, thread->tid, thread->selected_cpu,
            thread->cpu_auto ? " (automatic)" : "",
            thread->cpu_shared ? " (shared)" : "");
    } else {
        LOG(INFO, "Started I/O thread %s (TID %d) without CPU affinity\n",
            name, thread->tid);
    }
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

/* Each instance locks the file "bngblaster_cpu<N>.<PID>.lock" for every
 * CPU used by its threads until exit, which is released by the kernel
 * also if the instance is killed or crashes. The CPUs are selected while
 * holding the startup lock (see bbl.c), so that instances started at the
 * same time select their CPUs one after another. */
#define IO_CPU_LOCK_DIR "/run/lock"

static void
io_thread_cpu_lock_path(char *path, size_t len, uint16_t cpu)
{
    snprintf(path, len, IO_CPU_LOCK_DIR "/bngblaster_cpu%u.%d.lock", cpu, getpid());
}

/**
 * Count the other instances using each CPU, which hold a lock file
 * of this CPU, and remove lock files left behind by killed instances.
 * This is done while holding the startup lock, so no other instance
 * locks a CPU at the same time.
 */
static void
io_thread_cpu_scan()
{
    char path[sizeof(IO_CPU_LOCK_DIR) + 256];
    struct dirent *entry;
    DIR *dir;
    unsigned int cpu;
    int pid;
    int len;
    int fd;

    memset(g_io_cpu_users, 0x0, sizeof(g_io_cpu_users));
    dir = opendir(IO_CPU_LOCK_DIR);
    if(!dir) {
        return;
    }
    while((entry = readdir(dir))) {
        len = 0;
        if(sscanf(entry->d_name, "bngblaster_cpu%u.%d.lock%n", &cpu, &pid, &len) != 2 ||
           !len || entry->d_name[len] != '\0' || cpu >= CPU_SETSIZE) {
            continue;
        }
        snprintf(path, sizeof(path), IO_CPU_LOCK_DIR "/%s", entry->d_name);
        fd = open(path, O_RDONLY|O_CLOEXEC);
        if(fd == -1) {
            continue;
        }
        /* A shared lock is refused only if the instance
         * using this CPU still holds its exclusive lock. */
        if(flock(fd, LOCK_SH|LOCK_NB) == -1) {
            if(errno == EWOULDBLOCK) {
                g_io_cpu_users[cpu]++;
            }
        } else {
            unlink(path);
        }
        close(fd);
    }
    closedir(dir);
}

/**
 * Lock a CPU for this instance, so that the automatic CPU placement of
 * other instances skips it, or shares it evenly if no other CPU is free.
 *
 * @param cpu CPU
 */
static void
io_thread_cpu_lock(uint16_t cpu)
{
    char path[64];
    int fd;

    if(g_io_cpu_locked[cpu]) {
        return;
    }
    io_thread_cpu_lock_path(path, sizeof(path), cpu);
    fd = lock_file_acquire(path);
    if(fd == -1) {
        /* The CPU can't be coordinated with other instances. */
        LOG(DEBUG, "Failed to lock CPU %u with %s (%s)\n", cpu, path, strerror(errno));
        return;
    }
    g_io_cpu_locked[cpu] = true;
    g_io_cpu_lock_fd[cpu] = fd;
}

/**
 * Release all CPUs locked by this instance.
 */
void
io_thread_unlock_cpus()
{
    char path[64];
    uint16_t cpu;

    for(cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if(g_io_cpu_locked[cpu]) {
            io_thread_cpu_lock_path(path, sizeof(path), cpu);
            lock_file_release(g_io_cpu_lock_fd[cpu], path);
            g_io_cpu_locked[cpu] = false;
        }
    }
}

/**
 * Select a CPU from the CPUs local to the interface, preferring CPUs
 * which are neither used by other threads of this or other instances
 * nor handling NIC interrupts. If all CPUs are used by other instances,
 * the CPU used by the fewest other instances is shared. The selected
 * CPU is reserved and locked.
 *
 * @param interface interface
 * @param cursor index of the local CPU to start with, updated
 * @param irq_cpus CPUs handling NIC interrupts
 * @param share accept CPUs used by other instances
 * @param shared set to true if the CPU is used by another instance
 * @return selected CPU or -1 if no CPU is available
 */
static int
io_thread_select_cpu(bbl_interface_s *interface, uint16_t *cursor, bool *irq_cpus,
                     bool share, bool *shared)
{
    uint16_t start = *cursor % interface->local_cpuset_count;
    uint16_t index;
    uint16_t selected = 0;
    uint16_t min_users = UINT16_MAX;
    uint16_t cpu;
    int pass;

    /* Pass 0 skips CPUs handling NIC interrupts. */
    *shared = false;
    for(pass = 0; pass < 2; pass++) {
        for(index = 0; index < interface->local_cpuset_count; index++) {
            cpu = interface->local_cpuset[(start + index) % interface->local_cpuset_count];
            if(cpu >= CPU_SETSIZE || g_io_cpu_reserved[cpu] || g_io_cpu_users[cpu]) {
                continue;
            }
            if(pass == 0 && irq_cpus[cpu]) {
                continue;
            }
            io_thread_cpu_lock(cpu);
            g_io_cpu_reserved[cpu] = true;
            *cursor = (start + index + 1) % interface->local_cpuset_count;
            return cpu;
        }
    }
    if(!share) {
        return -1;
    }
    for(index = 0; index < interface->local_cpuset_count; index++) {
        cpu = interface->local_cpuset[(start + index) % interface->local_cpuset_count];
        if(cpu >= CPU_SETSIZE || g_io_cpu_reserved[cpu]) {
            continue;
        }
        if(g_io_cpu_users[cpu] < min_users) {
            min_users = g_io_cpu_users[cpu];
            selected = index;
        }
    }
    if(min_users == UINT16_MAX) {
        return -1;
    }
    cpu = interface->local_cpuset[(start + selected) % interface->local_cpuset_count];
    io_thread_cpu_lock(cpu);
    g_io_cpu_reserved[cpu] = true;
    *cursor = (start + selected + 1) % interface->local_cpuset_count;
    *shared = true;
    return cpu;
}

/**
 * Select a CPU for an I/O thread from the CPUs local to the interface.
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
    bool shared;
    int cpu;

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

    thread->cpu_auto = true;
    cpu = io_thread_select_cpu(interface, cursor, irq_cpus, true, &shared);
    thread->cpu_shared = cpu < 0 || shared;
    if(cpu < 0) {
        cpu = interface->local_cpuset[*cursor % interface->local_cpuset_count];
        *cursor = (*cursor + 1) % interface->local_cpuset_count;
        LOG(INFO, "Warning: No free CPU for %s thread of interface %s, sharing CPU %d with another thread\n",
            io->direction == IO_INGRESS ? "RX" : "TX", interface->name, cpu);
    } else if(shared) {
        LOG(INFO, "Warning: No free CPU for %s thread of interface %s, sharing CPU %d "
            "with another BNG Blaster instance\n",
            io->direction == IO_INGRESS ? "RX" : "TX", interface->name, cpu);
    }
    CPU_SET(cpu, &thread->cpuset);
    thread->selected_cpu = cpu;
    return true;
}

/**
 * Select a free CPU local to the first interface for the main thread if
 * the automatic CPU placement is used, so that it does not run on the CPUs
 * of I/O threads of this or other instances. The main thread is pinned
 * after all I/O threads are started, which would otherwise inherit its
 * CPU affinity.
 *
 * @param irq_cpus CPUs handling NIC interrupts
 * @return selected CPU or -1
 */
static int
io_thread_main_select_cpu(bool *irq_cpus)
{
    bbl_interface_s *interface;
    bbl_interface_s *local = NULL;
    cpu_set_t cpuset;
    uint16_t cursor = 0;
    bool shared;
    int cpu;

    /* The main thread is already pinned (e.g. by DPDK). */
    if(sched_getaffinity(0, sizeof(cpuset), &cpuset) == 0 && CPU_COUNT(&cpuset) == 1) {
        return -1;
    }
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(interface->local_cpuset_count) {
            local = interface;
            break;
        }
    }
    if(!local) {
        return -1;
    }
    cpu = io_thread_select_cpu(local, &cursor, irq_cpus, false, &shared);
    if(cpu < 0) {
        LOG(INFO, "Warning: No free CPU for the main thread\n");
    }
    return cpu;
}

static void
io_thread_main_pin(int cpu)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) {
        LOG(INFO, "Warning: Failed to pin the main thread to CPU %d\n", cpu);
        return;
    }
    g_io_main_cpu = cpu;
    LOG(INFO, "Main thread pinned to CPU %d\n", cpu);
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
 * warn about threads running on CPUs handling NIC interrupts
 * or used by other instances.
 *
 * @return CPU selected for the main thread or -1
 */
static int
io_thread_set_affinity_all()
{
    io_thread_s *thread;
    bbl_interface_s *interface;
    bool irq_cpus[CPU_SETSIZE] = {0};
    uint16_t irqs;
    bool auto_cpuset = false;
    int main_cpu = -1;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        irqs = io_interface_irq_cpus(interface, irq_cpus);
        if(irqs) {
            LOG(DEBUG, "Found %u interrupts of interface %s\n", irqs, interface->name);
        }
    }

    io_thread_cpu_scan();

    /* Lock the CPUs of manually pinned threads first, which are
     * skipped by the automatic CPU placement of other instances. */
    thread = g_ctx->io_threads;
    while(thread) {
        if(thread->set_cpu_affinity && thread->selected_cpu >= 0 && thread->selected_cpu < CPU_SETSIZE) {
            io_thread_cpu_lock(thread->selected_cpu);
        }
        if(thread->set_cpu_affinity && thread->selected_cpu >= 0 &&
           thread->selected_cpu < CPU_SETSIZE && g_io_cpu_users[thread->selected_cpu]) {
            thread->cpu_shared = true;
            LOG(INFO, "Warning: %s thread of interface %s runs on CPU %d which is also used "
                "by another BNG Blaster instance\n",
                thread->io->direction == IO_INGRESS ? "RX" : "TX",
                thread->io->interface->name, thread->selected_cpu);
        }
        thread = thread->next;
    }

    thread = g_ctx->io_threads;
    while(thread) {
        if(!thread->set_cpu_affinity && io_thread_auto_affinity(thread, thread->io, irq_cpus)) {
            auto_cpuset = true;
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
    if(auto_cpuset) {
        main_cpu = io_thread_main_select_cpu(irq_cpus);
    }
    return main_cpu;
}

/**
 * Start all I/O threads. The CPU affinity is set before the thread is
 * created, so that it never runs on another CPU. If a thread can't be
 * started (e.g. its CPU is not allowed for this process), all threads
 * already started are stopped.
 *
 * @return false if not all threads are started
 */
bool
io_thread_start_all()
{
    io_thread_s *thread = g_ctx->io_threads;
    struct timespec sleep = {0};
    struct timespec rem = {0};
    char name[16]; /* thread names are limited to 15 characters */
    pthread_attr_t attr;
    int main_cpu;
    int threads = 0;
    int ret;

    /* Each I/O thread and the main thread should have its own CPU,
     * otherwise threads are delayed, which causes packet loss. */
    while(thread) {
        /* Also without PCAP file, which can be started later. */
        if(g_ctx->pcap.include_streams) {
            io_handle_s *io = thread->io;
            uint16_t slots = io->direction == IO_INGRESS ?
                io->interface->config->io_slots_rx : io->interface->config->io_slots_tx;
            if(!io_capture_init(thread, slots)) {
                LOG_NOARG(ERROR, "Failed to allocate I/O stream capture queue\n");
                io_thread_stop_all();
                return false;
            }
        }
        threads++;
        thread = thread->next;
    }
    if(threads && g_io_cpu_allowed_saved && threads + 1 > CPU_COUNT(&g_io_cpu_allowed)) {
        LOG(INFO, "Warning: %d I/O threads plus main thread exceed %d available CPUs\n",
            threads, CPU_COUNT(&g_io_cpu_allowed));
    }
    main_cpu = io_thread_set_affinity_all();
    thread = g_ctx->io_threads;

    sleep.tv_nsec = 7800179; /* prime number between 7 and 8ms */
    while(thread) {
        io_thread_name(thread, name, sizeof(name));
        pthread_attr_init(&attr);
        if(thread->set_cpu_affinity) {
            pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &thread->cpuset);
        }
        thread->active = true;
        ret = pthread_create(&thread->thread, &attr, io_thread_main, (void *)thread);
        pthread_attr_destroy(&attr);
        if(ret) {
            thread->active = false;
            if(thread->set_cpu_affinity) {
                LOG(ERROR, "Failed to start I/O thread %s on CPU %d (%s), "
                    "the CPU might not be allowed for this process\n",
                    name, thread->selected_cpu, strerror(ret));
            } else {
                LOG(ERROR, "Failed to start I/O thread %s (%s)\n", name, strerror(ret));
            }
            io_thread_stop_all();
            return false;
        }
        thread->started = true;
        pthread_setname_np(thread->thread, name);

        nanosleep(&sleep, &rem);
        thread = thread->next;
    }
    if(main_cpu >= 0) {
        io_thread_main_pin(main_cpu);
    }
    g_io_threads_started = true;
    return true;
}

bool
io_thread_started()
{
    return g_io_threads_started;
}

static json_t *
io_thread_json(const char *name, const char *type, const char *interface,
               int cpu, bool cpu_auto, bool cpu_shared, pid_t tid)
{
    return json_pack("{ss ss ss* so sb sb si}",
                     "name", name,
                     "type", type,
                     "interface", interface,
                     "cpu", cpu >= 0 ? json_integer(cpu) : json_null(),
                     "cpu-auto", cpu_auto,
                     "cpu-shared", cpu_shared,
                     "tid", tid);
}

/**
 * Control socket command "threads" listing the main thread and all I/O
 * threads with the CPU they are pinned to (null if not pinned), which
 * is available once all threads are started.
 */
int
io_thread_ctrl_threads(int fd, uint32_t session_id __attribute__((unused)),
                       json_t *arguments __attribute__((unused)))
{
    io_thread_s *thread = g_ctx->io_threads;
    char name[16];
    json_t *threads;
    json_t *root;
    int result;

    threads = json_array();
    json_array_append_new(threads, io_thread_json("main", "main", NULL, g_io_main_cpu,
                                                  g_io_main_cpu >= 0, false, getpid()));
    while(thread) {
        io_thread_name(thread, name, sizeof(name));
        json_array_append_new(threads, io_thread_json(
            name, thread->io->direction == IO_INGRESS ? "rx" : "tx",
            thread->io->interface->name,
            thread->set_cpu_affinity ? thread->selected_cpu : -1,
            thread->cpu_auto, thread->cpu_shared, thread->tid));
        thread = thread->next;
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "threads", threads);
    if(root) {
        result = json_dumpfd(root, fd, BBL_JSON_REAL_PRECISION);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(threads);
    }
    return result;
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
        if(thread->started) {
            pthread_join(thread->thread, NULL);
            thread->started = false;
        }
        io_capture_free(thread);
        thread = thread->next;
    }
}
