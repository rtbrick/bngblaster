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
    if (poll(fds, 1, 0) == -1) {
        LOG(IO, "Failed to poll interface %s", 
            io->interface->name);
    }
}

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
        interface->stats.poll_rx++;
        return;
    }

    /* Get RX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    while(tphdr->tp_status & TP_STATUS_USER) {
        io->buf = (uint8_t*)tphdr + tphdr->tp_mac;
        io->buf_len = tphdr->tp_len;
        interface->stats.packets_rx++;
        interface->stats.bytes_rx += io->buf_len;
        interface->io.ctrl = true;
        decode_result = decode_ethernet(io->buf, io->buf_len, io->sp, SCRATCHPAD_LEN, &eth);
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
        } else if (decode_result == UNKNOWN_PROTOCOL) {
            interface->stats.unknown++;
        } else {
            interface->stats.decode_error++;
        }
        /* Dump the packet into pcap file. */
        if (g_ctx->pcap.write_buf && (interface->io.ctrl || g_ctx->pcap.include_streams)) {
            pcap = true;
            pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                      interface->pcap_index, PCAPNG_EPB_FLAGS_INBOUND);
        }
        /* Return ownership back to kernel. */
        tphdr->tp_status = TP_STATUS_KERNEL; 
        /* Get next packet. */
        io->cursor = (io->cursor + 1) % io->req.tp_frame_nr;
        frame_ptr = io->ring + (io->cursor * io->req.tp_frame_size);
        tphdr = (struct tpacket2_hdr*)frame_ptr;
    }
    if(pcap) {
        pcapng_fflush();
    }
}

void
bbl_io_packet_mmap_tx_job(timer_s *timer)
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
    if (tphdr->tp_status != TP_STATUS_AVAILABLE) {
        if(io->polled) {
            /* We already polled kernel. */
            return;
        }
        /* If no buffer is available poll kernel. */
        poll_kernel(io, POLLOUT);
        io->polled = true;
        interface->stats.poll_tx++;
    } else {
        io->polled = false;

        /* Get TX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);

        while(tx_result != EMPTY) {
            /* Check if this slot available for writing. */
            if (tphdr->tp_status != TP_STATUS_AVAILABLE) {
                interface->stats.no_buffer++;
                break;
            }
            io->buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
            tx_result = bbl_tx(interface, io->buf, &io->buf_len);
            if (tx_result == PROTOCOL_SUCCESS) {
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
        if (sendto(io->fd, NULL, 0, 0, NULL, 0) == -1) {
            LOG(IO, "Sendto failed with errno: %i\n", errno);
            interface->stats.sendto_failed++;
        } else {
            io->queued = 0;
        }
    }
}

bool
io_packet_mmap_init(io_handle_s *io) {
    bbl_interface_s *interface = io->interface;
    bbl_link_config_s *config = interface->config;


}
