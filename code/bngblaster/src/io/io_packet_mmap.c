/*
 * BNG Blaster (BBL) - IO PACKET_MMAP
 *
 * Christian Giese, July 2022
 *
 * PACKET_MMAP provides a size configurable circular buffer mapped in user space
 * that can be used to either send or receive packets. This way reading packets
 * just needs to wait for them, most of the time there is no need to issue a single
 * system call. Concerning transmission, multiple packets can be sent through one
 * system call to get the highest bandwidth. By using a shared buffer between the
 * kernel and the user also has the benefit of minimizing packet copies.
 *
 * https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

/* The frame status hands over the frame between kernel and user space,
 * the frame content must not be accessed before (acquire) or after
 * (release) the status, see smp_rmb/smp_wmb in packet_mmap.txt. */
#define TP_STATUS_LOAD(_tphdr) __atomic_load_n(&(_tphdr)->tp_status, __ATOMIC_ACQUIRE)
#define TP_STATUS_STORE(_tphdr, _status) __atomic_store_n(&(_tphdr)->tp_status, _status, __ATOMIC_RELEASE)

extern bool g_init_phase;
extern bool g_traffic;

/* The interface MTU is read again in this interval to follow changes. */
#define IO_PACKET_MMAP_MTU_REFRESH_NS 1000000000ULL

/* The kernel discards frames longer than the interface MTU plus ethernet
 * header, plus 4 byte only if the frame is 802.1Q tagged (tpacket_snd,
 * packet_extra_vlan_len_allowed), silently with PACKET_LOSS. */
static void
io_packet_mmap_tx_max_len(io_handle_s *io, uint64_t now)
{
    struct ifreq ifr = {0};

    io->tx_max_len_refresh = now + IO_PACKET_MMAP_MTU_REFRESH_NS;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", io->interface->name);
    if(ioctl(io->fd, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0 && ifr.ifr_mtu < UINT16_MAX - 18) {
        io->tx_max_len = ifr.ifr_mtu + 14;
    } else {
        io->tx_max_len = UINT16_MAX - 4;
    }
}

/* Called for frames longer than tx_max_len. Frames longer than accepted
 * by the kernel are dropped (return true) and counted, the first one is
 * logged (as with io-mode raw). */
static bool
io_packet_mmap_tx_to_long(io_handle_s *io, uint8_t *frame, uint16_t len)
{
    if(len <= io->tx_max_len + 4 && frame[12] == (ETH_TYPE_VLAN >> 8) && frame[13] == (ETH_TYPE_VLAN & 0xff)) {
        return false;
    }
    if(io->stats.to_long == 0) {
        LOG(ERROR, "PACKET_MMAP frame on interface %s to long (%u byte, max %u or %u with VLAN), please check MTU settings!\n",
            io->interface->name, len, io->tx_max_len, io->tx_max_len + 4);
    }
    io->stats.to_long++;
    return true;
}

static void
poll_kernel(io_handle_s *io, short events)
{
    struct pollfd pollset;
    pollset.fd = io->fd;
    pollset.events = events;
    pollset.revents = 0;
    io->stats.polled++;
    if(poll(&pollset, 1, 0) == -1) {
        LOG(IO, "Failed to poll interface %s", 
            io->interface->name);
    }
}

/**
 * This job is for PACKET_MMAP RX in main thread!
 */
void
io_packet_mmap_rx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    uint8_t *frame_ptr;
    struct tpacket2_hdr *tphdr;

    bbl_ethernet_header_s *eth;
    uint16_t vlan;
    uint32_t budget = IO_RX_BUDGET;

    protocol_error_t decode_result;
    bool pcap = false;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_INGRESS);
    assert(io->thread == NULL);

    frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
    tphdr = (struct tpacket2_hdr*)frame_ptr;
    if(!(TP_STATUS_LOAD(tphdr) & TP_STATUS_USER)) {
        /* If no buffer is available poll kernel */
        poll_kernel(io, POLLIN);
        return;
    }

    /* Get RX timestamp */
    //clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;
    while((TP_STATUS_LOAD(tphdr) & TP_STATUS_USER) && budget--) {
        io->buf = (uint8_t*)tphdr + tphdr->tp_mac;
        io->buf_len = tphdr->tp_snaplen;
        io->stats.packets++;
        io->stats.bytes += io->buf_len;
        if(tphdr->tp_status & TP_STATUS_VLAN_VALID) {
            /* Outer VLAN tag stripped by the kernel. */
            io->stats.bytes += 4;
        }
        decode_result = decode_ethernet(io->buf, io->buf_len, g_ctx->sp, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            if(tphdr->tp_status & TP_STATUS_VLAN_VALID) {
                vlan = tphdr->tp_vlan_tci & BBL_ETH_VLAN_ID_MAX;
                /* Restore stripped outer VLAN tag, which is
                 * also part of the received frame length. */
                eth->length += 4;
                eth->vlan_inner = eth->vlan_outer;
                eth->vlan_inner_priority = eth->vlan_outer_priority;
                eth->vlan_outer = vlan;
                eth->vlan_outer_priority = tphdr->tp_vlan_tci >> 13;
                if(tphdr->tp_vlan_tpid == ETH_TYPE_QINQ) {
                    eth->qinq = true;
                }
            }
            /* Copy RX timestamp */
            //eth->timestamp.tv_sec = tphdr->tp_sec; /* ktime/hw timestamp */
            //eth->timestamp.tv_nsec = tphdr->tp_nsec; /* ktime/hw timestamp */
            eth->timestamp.tv_sec = io->timestamp.tv_sec;
            eth->timestamp.tv_nsec = io->timestamp.tv_nsec;
            /* Dump the packet into pcap file */
            if(g_ctx->pcap.write_buf && (!eth->bbl || g_ctx->pcap.include_streams)) {
                pcap = true;
                pcapng_push_packet_header_tphdr(&io->timestamp, tphdr, interface->ifindex);
            }
            bbl_rx_handler(interface, eth);
        } else {
            /* Dump the packet into pcap file */
            if(g_ctx->pcap.write_buf) {
                pcap = true;
                pcapng_push_packet_header_tphdr(&io->timestamp, tphdr, interface->ifindex);
            }
            if(decode_result == UNKNOWN_PROTOCOL) {
                io->stats.unknown++;
            } else {
                io->stats.protocol_errors++;
            }
        }
        /* Return ownership back to kernel */
        TP_STATUS_STORE(tphdr, TP_STATUS_KERNEL);
        /* Get next packet */
        io->cursor = (io->cursor + 1) % io->req.tp_frame_nr;
        frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
        tphdr = (struct tpacket2_hdr*)frame_ptr;
    }
    if(pcap) {
        pcapng_fflush();
    }
}

/**
 * This job is for PACKET_MMAP TX in main thread!
 */
void
io_packet_mmap_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    struct tpacket2_hdr* tphdr;
    uint8_t *frame_ptr;

    bbl_stream_s *stream = NULL;
    uint16_t burst = interface->config->io_burst;
    uint64_t now;

    bool ctrl = true;
    bool pcap = false;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    if(io->update_streams) {
        io_stream_update_pps(io);
    }

    frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
    tphdr = (struct tpacket2_hdr*)frame_ptr;
    if(TP_STATUS_LOAD(tphdr) != TP_STATUS_AVAILABLE) {
        /* If no buffer is available poll kernel */
        poll_kernel(io, POLLOUT);
        io->stats.no_buffer++;
    } else {
        /* Get TX timestamp */
        //clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        io->timestamp.tv_sec = timer->timestamp->tv_sec;
        io->timestamp.tv_nsec = timer->timestamp->tv_nsec;
        now = timespec_to_nsec(timer->timestamp);
        if(unlikely(now >= io->tx_max_len_refresh)) {
            io_packet_mmap_tx_max_len(io, now);
        }
        while(burst) {
            /* Check if this slot available for writing. */
            if(TP_STATUS_LOAD(tphdr) != TP_STATUS_AVAILABLE) {
                io->stats.no_buffer++;
                break;
            }
            io->buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

            if(unlikely(ctrl)) {
                /* First send all control traffic which has higher priority. */
                if(bbl_tx(interface, io->buf, &io->buf_len) != PROTOCOL_SUCCESS) {
                    ctrl = false;
                    continue;
                }
                if(unlikely(io->buf_len > io->tx_max_len) &&
                   io_packet_mmap_tx_to_long(io, io->buf, io->buf_len)) {
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
                if(unlikely(stream->tx_len > io->tx_max_len) &&
                   io_packet_mmap_tx_to_long(io, stream->tx_buf, stream->tx_len)) {
                    continue;
                }
                memcpy(io->buf, stream->tx_buf, stream->tx_len);
                io->buf_len = stream->tx_len;
                stream->tx_packets++;
                stream->flow_seq++;
            } 
            tphdr->tp_len = io->buf_len;
            TP_STATUS_STORE(tphdr, TP_STATUS_SEND_REQUEST);

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

            /* Get next slot. */
            io->cursor = (io->cursor + 1) % io->req.tp_frame_nr;
            frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
            tphdr = (struct tpacket2_hdr *)frame_ptr;
        }
        if(pcap) {
            pcapng_fflush();
        }
    }

    if(io->queued) {
        /* Notify kernel. */
        if(sendto(io->fd, NULL, 0, 0, NULL, 0) < 0) {
            LOG(IO, "PACKET_MMAP sendto on interface %s failed with error %s (%d)\n", 
                interface->name, strerror(errno), errno);
            io->stats.io_errors++;
        } else {
            io->queued = 0;
        }
    }
}

void
io_packet_mmap_thread_rx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;

    uint32_t cursor = io->cursor;
    uint32_t frame_size = io->req.tp_frame_size; /* 64K with 64K pages */
    uint32_t frame_nr = io->req.tp_frame_nr;
    uint32_t next;
    uint8_t *ring = io->ring;

    struct tpacket2_hdr *tphdr;
    struct tpacket2_hdr *tphdrs[IO_RX_BURST_MAX];
    uint8_t *bufs[IO_RX_BURST_MAX];
    uint16_t lens[IO_RX_BURST_MAX];
    uint32_t vlans[IO_RX_BURST_MAX];
    uint16_t count, done, i;

    /* Frames of a burst are returned to the kernel after the
     * burst is processed, leave enough frames to the kernel. */
    uint16_t burst_max = frame_nr / 2;
    if(burst_max > IO_RX_BURST_MAX) burst_max = IO_RX_BURST_MAX;
    if(burst_max < 1) burst_max = 1;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_INGRESS);
    assert(io->thread);

    struct timespec sleep, rem;

    sleep.tv_sec = 0;
    sleep.tv_nsec = 10000; /* 0.01ms */

    /* Number of consecutive rounds without any packet available before we
     * back off with a nanosleep. Real traffic can arrive in an uneven
     * pattern, so a single check finding the ring momentarily empty is not
     * a reliable idle signal on its own (the next packet may already be
     * only microseconds away) - we only throttle once idleness looks
     * sustained rather than after a single empty check. */
    uint32_t idle_rounds = 0;
    const uint32_t idle_spin_rounds = 10000;

    while(thread->active) {
        tphdr = (struct tpacket2_hdr*)(ring + (cursor * frame_size));
        if(!(TP_STATUS_LOAD(tphdr) & TP_STATUS_USER)) {
            /* If no buffer is available poll kernel */
            //poll_kernel(io, POLLIN);
            if(++idle_rounds >= idle_spin_rounds) {
                nanosleep(&sleep, &rem);
                idle_rounds = 0;
            }
            continue;
        }
        idle_rounds = 0;

        /* Get RX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);

        /* Collect a burst of frames owned by user space, the
         * burst processing prefetches packets and streams ahead. */
        count = 0;
        next = cursor;
        do {
            tphdrs[count] = tphdr;
            bufs[count] = (uint8_t*)tphdr + tphdr->tp_mac;
            lens[count] = tphdr->tp_snaplen;
            if(tphdr->tp_status & TP_STATUS_VLAN_VALID) {
                vlans[count] = (uint32_t)(tphdr->tp_vlan_tpid ? tphdr->tp_vlan_tpid : ETH_TYPE_VLAN) << 16 | tphdr->tp_vlan_tci;
            } else {
                vlans[count] = 0;
            }
            count++;
            if(++next == frame_nr) next = 0;
            tphdr = (struct tpacket2_hdr*)(ring + (next * frame_size));
        } while(count < burst_max && (TP_STATUS_LOAD(tphdr) & TP_STATUS_USER));

        /* Process packets */
        done = io_thread_rx_burst_retry(thread, io, bufs, lens, vlans, count);

        /* Return ownership back to kernel, frames not processed
         * (TXQ to main thread full) are retried. */
        for(i = 0; i < done; i++) {
            TP_STATUS_STORE(tphdrs[i], TP_STATUS_KERNEL);
        }
        cursor += done;
        if(cursor >= frame_nr) cursor -= frame_nr;
    }
}

/* Notify kernel about queued TX frames, back off shortly on error. */
static void
io_packet_mmap_thread_notify(io_handle_s *io, struct timespec *sleep)
{
    struct timespec rem;

    if(sendto(io->fd, NULL, 0, 0, NULL, 0) < 0) {
        LOG(IO, "PACKET_MMAP sendto on interface %s failed with error %s (%d)\n",
            io->interface->name, strerror(errno), errno);
        io->stats.io_errors++;
        nanosleep(sleep, &rem);
    } else {
        io->queued = 0;
    }
}

void
io_packet_mmap_thread_tx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;
    bbl_interface_s *interface = io->interface;

    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *slot;

    struct tpacket2_hdr* tphdr;
    uint8_t *frame_ptr;

    bbl_stream_s *stream = NULL;
    uint16_t io_burst = interface->config->io_burst;
    uint16_t burst = 0;
    uint64_t now;

    bool ctrl = true;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 10000; /* 0.01ms */

    /* Number of consecutive rounds without anything queued before we back
     * off with a nanosleep. With many independently paced stream instances,
     * a single round finding nothing due is common even under heavy
     * aggregate load (the next stream may become due microseconds later),
     * so we only throttle once idleness looks sustained rather than after
     * a single empty round. */
    uint32_t idle_rounds = 0;
    const uint32_t idle_spin_rounds = 10000;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    while(thread->active) {
        if(io->update_streams) {
            io_stream_update_pps(io);
        }

        frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
        tphdr = (struct tpacket2_hdr *)frame_ptr;
        if(TP_STATUS_LOAD(tphdr) != TP_STATUS_AVAILABLE) {
            /* If no buffer is available poll kernel. */
            io->stats.no_buffer++;
            if(io->queued) {
                /* Frames left over from a failed sendto() (e.g. link
                 * down) are only sent after another kick. Without it,
                 * the ring stays full and the interface never sends
                 * again. */
                io_packet_mmap_thread_notify(io, &sleep);
            }
            poll_kernel(io, POLLOUT);
            continue;
        }

        /* Get TX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        
        burst = io_burst;
        ctrl = true;
        now = timespec_to_nsec(&io->timestamp);
        if(unlikely(now >= io->tx_max_len_refresh)) {
            io_packet_mmap_tx_max_len(io, now);
        }
        while(burst) {
            if(TP_STATUS_LOAD(tphdr) != TP_STATUS_AVAILABLE) {
                io->stats.no_buffer++;
                poll_kernel(io, POLLOUT);
                break;
            }
            io->buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

            if(unlikely(ctrl)) {
                /* First send all control traffic which has higher priority. */
                slot = bbl_txq_read_slot(txq);
                if(slot) {
                    if(unlikely(slot->packet_len > io->tx_max_len) &&
                       io_packet_mmap_tx_to_long(io, slot->packet, slot->packet_len)) {
                        bbl_txq_read_next(txq);
                        continue;
                    }
                    io->buf_len = slot->packet_len;
                    memcpy(io->buf, slot->packet, slot->packet_len);
                    bbl_txq_read_next(txq);
                } else {
                    ctrl = false;
                    continue;
                }
            } else {
                if(!(g_traffic && g_init_phase == false && interface->state == INTERFACE_UP)) {
                    bbl_stream_io_stop(io);
                    break;
                }
                /* Send traffic streams up to allowed burst. */
                stream = bbl_stream_io_send_iter(io, now);
                if(unlikely(stream == NULL)) {
                    break;
                }
                if(unlikely(stream->tx_len > io->tx_max_len) &&
                   io_packet_mmap_tx_to_long(io, stream->tx_buf, stream->tx_len)) {
                    continue;
                }
                memcpy(io->buf, stream->tx_buf, stream->tx_len);
                io->buf_len = stream->tx_len;
                stream->tx_packets++;
                stream->flow_seq++;
            }

            if(unlikely(io_capture_active(thread)) && !ctrl) io_capture_packet(io, io->buf, io->buf_len);
            tphdr->tp_len = io->buf_len;
            TP_STATUS_STORE(tphdr, TP_STATUS_SEND_REQUEST);

            io->queued++;
            io->stats.packets++;
            io->stats.bytes += io->buf_len;
            burst--;

            /* Get next slot. */
            io->cursor = (io->cursor + 1) % io->req.tp_frame_nr;
            frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
            tphdr = (struct tpacket2_hdr *)frame_ptr;
        }

        if(io->queued) {
            idle_rounds = 0;
            io_packet_mmap_thread_notify(io, &sleep);
        } else if(++idle_rounds >= idle_spin_rounds) {
            /* Nothing was queued for many consecutive rounds in a row.
             * Only now back off, instead of busy-spinning forever, or
             * sleeping after every single empty round (which would also
             * throttle bursty-but-busy streams that just missed being
             * due by a few microseconds). */
            nanosleep(&sleep, &rem);
            idle_rounds = 0;
        }
    }
}

bool
io_packet_mmap_init(io_handle_s *io)
{
    bbl_interface_s *interface = io->interface;
    bbl_link_config_s *config = interface->config;
    
    io_thread_s *thread = io->thread;
    
    if(!io_socket_open(io)) {
        return false;
    }
    if(io->direction == IO_EGRESS) {
        io_packet_mmap_tx_max_len(io, 0);
    }

    if(thread) {
        if(io->direction == IO_INGRESS) {
            thread->run_fn = io_packet_mmap_thread_rx_run_fn;
        } else {
            thread->run_fn = io_packet_mmap_thread_tx_run_fn;
        }
    } else {
        if(io->direction == IO_INGRESS) {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.rx_job, "RX", 0, 
                config->rx_interval, io, &io_packet_mmap_rx_job);
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.tx_job, "TX", 0, 
                config->tx_interval, io, &io_packet_mmap_tx_job);
        }
    }
    return true;
}

/* Each ring block holds one frame and must be a multiple of the
 * page size, which is 16K or 64K on some aarch64 systems. */
uint32_t
io_packet_mmap_frame_size()
{
    uint32_t page_size = getpagesize();

    if(g_ctx->config.jumbo_frames) {
        return (IO_JUMBO_BLOCK_SIZE + page_size - 1) / page_size * page_size;
    }
    return page_size;
}

void
io_packet_mmap_set_max_stream_len()
{
    uint32_t len;

    len = io_packet_mmap_frame_size() - BBL_MAX_STREAM_OVERHEAD - (TPACKET2_HDRLEN - sizeof(struct sockaddr_ll));
    if(len < g_ctx->config.io_max_stream_len) {
        LOG(DEBUG, "Set max allowed stream length to %u because of packet_mmap limitations\n", len);
        g_ctx->config.io_max_stream_len = len;
    }
}