/*
 * BNG Blaster (BBL) - IO RAW
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

/**
 * This job is for RAW RX in main thread!
 */
void
io_raw_rx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);

    bbl_ethernet_header_t *eth;

    protocol_error_t decode_result;

    bool pcap = false;

    assert(io->mode == IO_MODE_RAW);
    assert(io->direction == IO_INGRESS);
    assert(io->thread == NULL);

    /* Get RX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    while(true) {
        io->buf_len = recvfrom(io->fd, io->buf, IO_BUFFER_LEN, 0, &saddr , (socklen_t*)&saddr_size);
        if(io->buf_len < 14 || io->buf_len > IO_BUFFER_LEN) {
            break;
        }
        io->stats.packets++;
        io->stats.bytes += io->buf_len;
        interface->io.ctrl = true;
        decode_result = io_decode_ethernet(io->buf, io->buf_len, io->sp, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            /* Copy RX timestamp */
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
    }
    if(pcap) {
        pcapng_fflush();
    }
}

/**
 * This job is for RAW TX in main thread!
 */
void
io_raw_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;
    protocol_error_t tx_result = IGNORED;

    bool pcap = false;

    assert(io->mode == IO_MODE_RAW);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    /* Get TX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    while(tx_result != EMPTY) {
        /* If sendto fails, the failed packet remains in TX buffer to be retried
         * in the next interval. */
        if(!io->buf_len) {
            tx_result = bbl_tx(interface, io->buf, &io->buf_len);
        }
        if(tx_result == PROTOCOL_SUCCESS) {
            if (sendto(io->fd, io->buf, io->buf_len, 0, (struct sockaddr*)&io->addr, sizeof(struct sockaddr_ll)) <0 ) {
                LOG(IO, "Sendto failed with errno: %i\n", errno);
                interface->stats.sendto_failed++;
                return;
            }
            interface->stats.packets_tx++;
            interface->stats.bytes_tx += io->buf_len;
            /* Dump the packet into pcap file. */
            if(g_ctx->pcap.write_buf && (interface->io.ctrl || g_ctx->pcap.include_streams)) {
                pcap = true;
                pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                          interface->pcap_index, PCAPNG_EPB_FLAGS_OUTBOUND);
            }
        }
        io->buf_len = 0;
    }
    if(pcap) {
        pcapng_fflush();
    }
}