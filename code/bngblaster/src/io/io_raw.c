/*
 * BNG Blaster (BBL) - IO RAW
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

extern bool g_init_phase;
extern bool g_traffic;

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
    //clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;
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
    if(pcap) {
        pcapng_fflush();
    }
}

/**
 * If the message is too long to pass atomically through the underlying protocol, 
 * the error EMSGSIZE is returned, and the message is not transmitted. In this 
 * case we must not retry the packet, because it will always fail. 
 */
void
io_raw_tx_lo_long(io_handle_s *io)
{
    bbl_interface_s *interface = io->interface;
    if(io->stats.to_long == 0) {
        /* Log error for first oversized packet only! */
        LOG(ERROR, "RAW sendto on interface %s failed because of to long packet (%u byte), please check MTU settings!\n", 
            interface->name, io->buf_len);
    }
    io->stats.to_long++;
}

/**
 * This job is for RAW TX in main thread!
 */
void
io_raw_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    bbl_stream_s *stream = NULL;
    uint16_t burst = interface->config->io_burst;
    uint64_t now;
    bool pcap = false;

    assert(io->mode == IO_MODE_RAW);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    /* Get TX timestamp */
    //clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;

    while(burst) {
        if(likely(io->buf_len == 0)) {
            if(bbl_tx(interface, io->buf, &io->buf_len) != PROTOCOL_SUCCESS) {
                io->buf_len = 0;
                break;
            }
        }
        if(sendto(io->fd, io->buf, io->buf_len, 0, (struct sockaddr*)&io->addr, sizeof(struct sockaddr_ll)) > 0) {
            /* Dump the packet into pcap file. */
            if(unlikely(g_ctx->pcap.write_buf != NULL)) {
                pcap = true;
                pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                          interface->ifindex, PCAPNG_EPB_FLAGS_OUTBOUND);
            }
            io->stats.packets++;
            io->stats.bytes += io->buf_len;
            io->buf_len = 0;
            burst--;
        } else {
            if(errno == EMSGSIZE) {
                io_raw_tx_lo_long(io);
                io->buf_len = 0;
            } else {
                /* This packet will be retried next interval 
                 * because io->buf_len is not reset to zero. */
                LOG(IO, "RAW sendto on interface %s failed with error %s (%d)\n", 
                    interface->name, strerror(errno), errno);
                io->stats.io_errors++;
                burst = 0;
            }
        }
    }

    if(g_traffic && g_init_phase == false && interface->state == INTERFACE_UP) {
        now = timespec_to_nsec(timer->timestamp);
        while(burst) {
            /* Send traffic streams up to allowed burst. */
            stream = bbl_stream_io_send_iter(io, now);
            if(unlikely(stream == NULL)) {
                break;
            }
            if(sendto(io->fd, stream->tx_buf, stream->tx_len, 0, (struct sockaddr*)&io->addr, sizeof(struct sockaddr_ll)) > 0) {
                /* Dump the packet into pcap file. */
                if(unlikely(g_ctx->pcap.write_buf && g_ctx->pcap.include_streams)) {
                    pcap = true;
                    pcapng_push_packet_header(&io->timestamp, stream->tx_buf, stream->tx_len,
                                              interface->ifindex, PCAPNG_EPB_FLAGS_OUTBOUND);
                }
                stream->tx_packets++;
                stream->flow_seq++;
                io->stats.packets++;
                io->stats.bytes += stream->tx_len;
                burst--;
            } else {
                if(errno == EMSGSIZE) {
                    io->buf_len = stream->tx_len;
                    io_raw_tx_lo_long(io);
                    io->buf_len = 0;
                } else {
                    LOG(IO, "RAW sendto on interface %s failed with error %s (%d)\n", 
                        interface->name, strerror(errno), errno);
                    io->bucket_cur->stream_cur = stream;
                    io->stats.io_errors++;
                    burst = 0;
                }
            }
        }
    } else {
        bbl_stream_io_stop(io);
    }
    if(unlikely(pcap)) {
        pcapng_fflush();
    }
}

void
io_raw_thread_rx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;

    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);

    assert(io->direction == IO_INGRESS);

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 1000; /* 0.001ms */

    while(thread->active) {
        /* Get RX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        /* Receive from socket */
        io->buf_len = recvfrom(io->fd, io->buf, IO_BUFFER_LEN, 0, &saddr , (socklen_t*)&saddr_size);
        if(io->buf_len < 14 || io->buf_len > IO_BUFFER_LEN) {
            nanosleep(&sleep, &rem);
            continue;
        }
        /* Process packet */
        io_thread_rx_handler(thread, io);
    }
}

void
io_raw_thread_tx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;
    bbl_interface_s *interface = io->interface;

    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *slot;

    bbl_stream_s *stream = NULL;
    uint16_t io_burst = interface->config->io_burst;
    uint16_t burst = 0;
    uint64_t now;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 1000 * io_burst; 

    assert(io->mode == IO_MODE_RAW);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    while(thread->active) {
        nanosleep(&sleep, &rem);
        burst = io_burst;

        /* First send all control traffic which has higher priority. */
        while((slot = bbl_txq_read_slot(txq))) {
            if(sendto(io->fd, slot->packet, slot->packet_len, 0, (struct sockaddr*)&io->addr, sizeof(struct sockaddr_ll)) >= 0 ) {
                io->stats.packets++;
                io->stats.bytes += slot->packet_len;
                bbl_txq_read_next(txq);
                if(burst) burst--;
            } else {
                LOG(IO, "RAW sendto on interface %s failed with error %s (%d)\n", 
                    io->interface->name, strerror(errno), errno);
                io->stats.io_errors++;
                burst = 0;
                break;
            }
        }

        /* Get TX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        if(g_traffic && g_init_phase == false && interface->state == INTERFACE_UP) {
            now = timespec_to_nsec(&io->timestamp);
            while(burst) {
                /* Send traffic streams up to allowed burst. */
                stream = bbl_stream_io_send_iter(io, now);
                if(unlikely(stream == NULL)) {
                    break;
                }
                if(unlikely(sendto(io->fd, stream->tx_buf, stream->tx_len, 0, (struct sockaddr*)&io->addr, sizeof(struct sockaddr_ll)) >=0)) {
                    stream->tx_packets++;
                    stream->flow_seq++;
                    io->stats.packets++;
                    io->stats.bytes += stream->tx_len;
                    burst--;
                } else {
                    if(errno == EMSGSIZE) {
                        io->buf_len = stream->tx_len;
                        io_raw_tx_lo_long(io);
                        io->buf_len = 0;
                    } else {
                        LOG(IO, "RAW sendto on interface %s failed with error %s (%d)\n", 
                            io->interface->name, strerror(errno), errno);
                        io->bucket_cur->stream_cur = stream;
                        io->stats.io_errors++;
                        burst = 0;
                    }
                }
            }
        } else {
            bbl_stream_io_stop(io);
        }
    }
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
            thread->run_fn = io_raw_thread_tx_run_fn;
        }
    } else {
        if(io->direction == IO_INGRESS) {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.rx_job, "RX", 0, 
                config->rx_interval, io, &io_raw_rx_job);
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.tx_job, "TX", 0, 
                config->tx_interval, io, &io_raw_tx_job);
        }
    }
    return true;
}