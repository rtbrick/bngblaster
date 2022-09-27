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

    bbl_ethernet_header_s *eth;

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
        decode_result = decode_ethernet(io->buf, io->buf_len, g_ctx->sp, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = io->timestamp.tv_sec;
            eth->timestamp.tv_nsec = io->timestamp.tv_nsec;
            bbl_rx_handler(interface, eth);
        } else if (decode_result == UNKNOWN_PROTOCOL) {
            io->stats.unknown++;
        } else {
            io->stats.protocol_errors++;
        }
        /* Dump the packet into pcap file */
        if(g_ctx->pcap.write_buf && (!eth->bbl || g_ctx->pcap.include_streams)) {
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
    protocol_error_t tx_result = PROTOCOL_SUCCESS;

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
            if(sendto(io->fd, io->buf, io->buf_len, 0, (struct sockaddr*)&io->addr, sizeof(struct sockaddr_ll)) <0 ) {
                LOG(IO, "RAW sendto on interface %s failed with error %s (%d)\n", 
                    interface->name, strerror(errno), errno);
                io->stats.io_errors++;
                return;
            }
            io->stats.packets++;
            io->stats.bytes += io->buf_len;
            /* Dump the packet into pcap file. */
            if(g_ctx->pcap.write_buf) {
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

void
io_raw_thread_rx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;

    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);

    struct timespec sleep, rem;

    assert(io->direction == IO_INGRESS);

    sleep.tv_sec = 0;
    sleep.tv_nsec = 0;

    while(thread->active) {
        /* Get RX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        /* Receive from socket */
        io->buf_len = recvfrom(io->fd, io->buf, IO_BUFFER_LEN, 0, &saddr , (socklen_t*)&saddr_size);
        if(io->buf_len < 14 || io->buf_len > IO_BUFFER_LEN) {
            sleep.tv_nsec = 1000; /* 0.001ms */
            nanosleep(&sleep, &rem);
            continue;
        }
        /* Process packet */
        io_thread_rx_handler(thread, io);
    }
}

void
io_raw_thread_tx_job(timer_s *timer)
{
    io_thread_s *thread = timer->data;
    io_handle_s *io = thread->io;

    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *slot;

    assert(io->mode == IO_MODE_RAW);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    while((slot = bbl_txq_read_slot(txq))) {
        if(sendto(io->fd, slot->packet, slot->packet_len, 0, (struct sockaddr*)&io->addr, sizeof(struct sockaddr_ll)) <0 ) {
            LOG(IO, "RAW sendto on interface %s failed with error %s (%d)\n", 
                io->interface->name, strerror(errno), errno);
            io->stats.io_errors++;
            return;
        }
        io->stats.packets++;
        io->stats.bytes += slot->packet_len;
        bbl_txq_read_next(txq);
    }
}

bool
io_raw_send(io_handle_s *io, uint8_t *buf, uint16_t len)
{
    if(sendto(io->fd, buf, len, 0, (struct sockaddr*)&io->addr, sizeof(struct sockaddr_ll)) <0 ) {
        LOG(IO, "RAW sendto on interface %s failed with error %s (%d)\n", 
            io->interface->name, strerror(errno), errno);
        io->stats.io_errors++;
        return false;
    }
    return true;
}

bool
io_raw_init(io_handle_s *io)
{
    bbl_interface_s *interface = io->interface;
    bbl_link_config_s *config = interface->config;
    
    io_thread_s *thread = io->thread;
    
    io->buf = malloc(IO_BUFFER_LEN);

    if(!io_socket_open(io)) {
        return false;
    }

    if(thread) {
        if(io->direction == IO_INGRESS) {
            thread->run_fn = io_raw_thread_rx_run_fn;
        } else {
            timer_add_periodic(&thread->timer.root, &thread->timer.io, "TX (threaded)", 0, 
                config->tx_interval, thread, &io_raw_thread_tx_job);
        }
    } else {
        if(io->direction == IO_INGRESS) {
            timer_add_periodic(&g_ctx->timer_root, &interface->rx_job, "RX", 0, 
                config->rx_interval, io, &io_raw_rx_job);
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->tx_job, "TX", 0, 
                config->tx_interval, io, &io_raw_tx_job);
        }
    }
    return true;
}