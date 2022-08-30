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
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

static void
poll_kernel(io_handle_s *io, short events)
{
    struct pollfd fds[1] = {0};
    fds[0].fd = io->fd;
    fds[0].events = events;
    fds[0].revents = 0;
    io->stats.polled++;
    if(poll(fds, 1, 0) == -1) {
        LOG(IO, "Failed to poll interface %s", 
            io->interface->name);
    } else {
        io->polled = true;
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

    bbl_ethernet_header_t *eth;
    uint16_t vlan;

    protocol_error_t decode_result;
    bool pcap = false;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_INGRESS);
    assert(io->thread == NULL);

    frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
    tphdr = (struct tpacket2_hdr*)frame_ptr;
    if(!(tphdr->tp_status & TP_STATUS_USER)) {
        /* If no buffer is available poll kernel */
        poll_kernel(io, POLLIN);
        return;
    }

    /* Get RX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    while(tphdr->tp_status & TP_STATUS_USER) {
        io->buf = (uint8_t*)tphdr + tphdr->tp_mac;
        io->buf_len = tphdr->tp_len;
        interface->stats.packets_rx++;
        interface->stats.bytes_rx += io->buf_len;
        decode_result = decode_ethernet(io->buf, io->buf_len, g_ctx->sp, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            vlan = tphdr->tp_vlan_tci & ETH_VLAN_ID_MAX;
            if(vlan && eth->vlan_outer != vlan) {
                /* The outer VLAN is stripped from header */
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
            bbl_rx_handler(interface, eth);
        } else if(decode_result == UNKNOWN_PROTOCOL) {
            interface->stats.unknown++;
        } else {
            interface->stats.decode_error++;
        }
        /* Dump the packet into pcap file */
        if(g_ctx->pcap.write_buf && (!eth->bbl || g_ctx->pcap.include_streams)) {
            pcap = true;
            pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                      interface->pcap_index, PCAPNG_EPB_FLAGS_INBOUND);
        }
        /* Return ownership back to kernel */
        tphdr->tp_status = TP_STATUS_KERNEL; 
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
    protocol_error_t tx_result = IGNORED;

    struct tpacket2_hdr* tphdr;

    uint8_t *frame_ptr;
    bool pcap = false;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
    tphdr = (struct tpacket2_hdr *)frame_ptr;
    if(tphdr->tp_status != TP_STATUS_AVAILABLE) {
        if(io->polled) {
            /* We already polled kernel. */
            return;
        }
        /* If no buffer is available poll kernel. */
        poll_kernel(io, POLLOUT);
    } else {
        io->polled = false;

        /* Get TX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);

        while(tx_result != EMPTY) {
            /* Check if this slot available for writing. */
            if(tphdr->tp_status != TP_STATUS_AVAILABLE) {
                io->stats.no_buffer++;
                break;
            }
            io->buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
            tx_result = bbl_tx(interface, io->buf, &io->buf_len);
            if(tx_result == PROTOCOL_SUCCESS) {
                io->queued++;
                tphdr->tp_len = io->buf_len;
                tphdr->tp_status = TP_STATUS_SEND_REQUEST;
                interface->stats.packets_tx++;
                interface->stats.bytes_tx += io->buf_len;
                /* Dump the packet into pcap file. */
                if(g_ctx->pcap.write_buf && (interface->io.ctrl || g_ctx->pcap.include_streams)) {
                    pcap = true;
                    pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                              interface->pcap_index, PCAPNG_EPB_FLAGS_OUTBOUND);
                }
                /* Request send from kernel. */
                tphdr->tp_status = TP_STATUS_SEND_REQUEST;
                /* Get next slot. */
                io->cursor = (io->cursor + 1) % io->req.tp_frame_nr;
                frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
                tphdr = (struct tpacket2_hdr *)frame_ptr;
            }
        }
        if(pcap) {
            pcapng_fflush();
        }
    }

    if(io->queued) {
        /* Notify kernel. */
        if(sendto(io->fd, NULL, 0, 0, NULL, 0) == -1) {
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

    uint16_t cursor = io->cursor;
    uint16_t frame_size = io->req.tp_frame_size;
    uint16_t frame_nr = io->req.tp_frame_nr;
    uint8_t *frame_ptr;
    uint8_t *ring = io->ring;

    struct tpacket2_hdr *tphdr;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_INGRESS);
    assert(io->thread);

    struct timespec sleep, rem;

    sleep.tv_sec = 0;
    sleep.tv_nsec = 0;

    while(thread->active) {
        frame_ptr = ring + (cursor * frame_size);
        tphdr = (struct tpacket2_hdr*)frame_ptr;
        if(!(tphdr->tp_status & TP_STATUS_USER)) {
            /* If no buffer is available poll kernel */
            poll_kernel(io, POLLIN);
            sleep.tv_nsec = 100000; /* 0.1ms */
            nanosleep(&sleep, &rem);
            continue;
        }

        /* Get RX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        while(tphdr->tp_status & TP_STATUS_USER) {
            io->buf = (uint8_t*)tphdr + tphdr->tp_mac;
            io->buf_len = tphdr->tp_len;
            io->vlan_tci = tphdr->tp_vlan_tci;
            io->vlan_tpid = tphdr->tp_vlan_tpid;
            /* Process packet */
            io_thread_rx_handler(thread, io);
            /* Return ownership back to kernel */
            tphdr->tp_status = TP_STATUS_KERNEL; 
            /* Get next packet */
            cursor = (cursor + 1) % frame_nr;
            frame_ptr = ring + (cursor * frame_size);
            tphdr = (struct tpacket2_hdr*)frame_ptr;
        }
        sleep.tv_nsec = 1000; /* 0.001ms */
        nanosleep(&sleep, &rem);
    }
}

void
io_packet_mmap_thread_tx_job(timer_s *timer)
{
    io_thread_s *thread = timer->data;
    io_handle_s *io = thread->io;
    bbl_interface_s *interface = io->interface;

    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *slot;

    struct tpacket2_hdr* tphdr;

    uint8_t *frame_ptr;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
    tphdr = (struct tpacket2_hdr *)frame_ptr;
    if(tphdr->tp_status != TP_STATUS_AVAILABLE) {
        if(io->polled) {
            /* We already polled kernel. */
            return;
        }
        /* If no buffer is available poll kernel. */
        poll_kernel(io, POLLOUT);
    } else {
        io->polled = false;

        while((slot = bbl_txq_read_slot(txq))) {
            /* Check if this slot available for writing. */
            if(tphdr->tp_status != TP_STATUS_AVAILABLE) {
                io->stats.no_buffer++;
                break;
            }
            io->buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
            io->buf_len = slot->packet_len;
            io->queued++;
            memcpy(io->buf, slot->packet, slot->packet_len);
            tphdr->tp_len = io->buf_len;
            tphdr->tp_status = TP_STATUS_SEND_REQUEST;
            /* Request send from kernel. */
            tphdr->tp_status = TP_STATUS_SEND_REQUEST;
            /* Get next slot. */
            io->cursor = (io->cursor + 1) % io->req.tp_frame_nr;
            frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
            tphdr = (struct tpacket2_hdr *)frame_ptr;
            bbl_txq_read_next(txq);
        }
    }

    if(io->queued) {
        /* Notify kernel. */
        if(sendto(io->fd, NULL, 0, 0, NULL, 0) == -1) {
            LOG(IO, "PACKET_MMAP sendto on interface %s failed with error %s (%d)\n", 
                interface->name, strerror(errno), errno);
            io->stats.io_errors++;
        } else {
            io->queued = 0;
        }
    }
}

bool
io_packet_mmap_send(io_handle_s *io)
{
    bbl_interface_s *interface = io->interface;

    uint8_t *frame_ptr;
    uint8_t *tphdr_buf;

    struct tpacket2_hdr *tphdr;

    assert(io->mode == IO_MODE_PACKET_MMAP);
    assert(io->direction == IO_EGRESS);

    frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
    tphdr = (struct tpacket2_hdr *)frame_ptr;
    if(tphdr->tp_status != TP_STATUS_AVAILABLE) {
        if(!io->polled) {
            /* If no buffer is available poll kernel. */
            poll_kernel(io, POLLOUT);
        }
        io->stats.no_buffer++;
        return false;
    }
    io->polled = false;
    io->queued++;
    tphdr_buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
    memcpy(tphdr_buf, io->buf, io->buf_len);
    tphdr->tp_len = io->buf_len;
    tphdr->tp_status = TP_STATUS_SEND_REQUEST;
    /* Request send from kernel. */
    tphdr->tp_status = TP_STATUS_SEND_REQUEST;
    /* Get next slot. */
    io->cursor = (io->cursor + 1) % io->req.tp_frame_nr;
    frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
    tphdr = (struct tpacket2_hdr *)frame_ptr;
    if(tphdr->tp_status != TP_STATUS_AVAILABLE) {
        /* Notify kernel. */
        if(sendto(io->fd, NULL, 0, 0, NULL, 0) == -1) {
            LOG(IO, "PACKET_MMAP sendto on interface %s failed with error %s (%d)\n", 
                interface->name, strerror(errno), errno);
            io->stats.io_errors++;
        } else {
            io->queued = 0;
        }
    }
    return true;
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

    if(thread) {
        if(io->direction == IO_INGRESS) {
            thread->run_fn = io_packet_mmap_thread_rx_run_fn;
        } else {
            timer_add_periodic(&thread->timer.root, &thread->timer.io, "TX (threaded)", 0, 
                config->tx_interval, thread, &io_packet_mmap_thread_tx_job);
        }
    } else {
        if(io->direction == IO_INGRESS) {
            timer_add_periodic(&g_ctx->timer_root, &interface->rx_job, "RX", 0, 
                config->rx_interval, io, &io_packet_mmap_rx_job);
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->tx_job, "TX", 0, 
                config->tx_interval, io, &io_packet_mmap_tx_job);
        }
    }
    return true;
}
