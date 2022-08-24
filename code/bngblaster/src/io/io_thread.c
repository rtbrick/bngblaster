/*
 * BNG Blaster (BBL) - IO RX Threads
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

void
io_thread_rx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_txq_s *txq = io->txq;
    bbl_txq_slot_t *slot;
    bbl_interface_s *interface = io->interface;

    bbl_ethernet_header_t *eth;
    uint16_t vlan;

    protocol_error_t decode_result;
    bool pcap = false;

    while(slot = bbl_txq_read_slot(txq)) {
        decode_result = decode_ethernet(slot->packet, slot->packet_len, interface->io.sp, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            vlan = slot->vlan_tci & ETH_VLAN_ID_MAX;
            if(vlan && eth->vlan_outer != vlan) {
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
        bbl_txq_read_next(txq);
    }
    if(pcap) {
        pcapng_fflush();
    }
}

void
io_thread_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_txq_s *txq = io->txq;
    bbl_txq_slot_t *slot;
    bbl_interface_s *interface = io->interface;

    protocol_error_t tx_result = IGNORED;

    bool pcap = false;

    /* Get TX timestamp */
    struct timespec timestamp;
    clock_gettime(CLOCK_MONOTONIC, &timestamp);

    while(slot = bbl_txq_write_slot(txq)) {
        tx_result = bbl_tx(interface, slot->packet, &slot->packet_len);
        if(tx_result == PROTOCOL_SUCCESS) {
            interface->stats.packets_tx++;
            interface->stats.bytes_tx += slot->packet_len;
            /* Dump the packet into pcap file. */
            if(g_ctx->pcap.write_buf && (interface->io.ctrl || g_ctx->pcap.include_streams)) {
                pcap = true;
                pcapng_push_packet_header(&timestamp, slot->packet, slot->packet_len,
                                        interface->pcap_index, PCAPNG_EPB_FLAGS_OUTBOUND);
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
io_thread_timer(void *thread_data)
{
    io_thread_s *thread = thread_data;
    pthread_mutex_lock(&thread->mutex);
    timer_smear_all_buckets(&thread->timer_root);
    pthread_mutex_unlock(&thread->mutex);
    while(thread->active) {
        timer_walk(&thread->timer_root);
    }
    thread->stopped = true;
    return NULL;
}

bool
io_thread_init(io_handle_s *io)
{
    bbl_interface_s *interface = io->interface;
    bbl_link_config_s *config = interface->config;
    io_thread_s *thread;

    uint16_t slots = config->io_slots;

    thread = calloc(1, sizeof(io_thread_s));
    thread->next = g_ctx->io_threads;
    g_ctx->io_threads = thread;

    io->thread = thread;
    io->fanout_id = interface->ifindex;
    io->fanout_type = PACKET_FANOUT_HASH;


    /* Init thread mutex */
    if (pthread_mutex_init(&thread->mutex, NULL) != 0) {
        LOG_NOARG(ERROR, "Failed to init mutex\n");
        return false;
    }

    /* Init thread timer root */
    timer_init_root(&thread->timer_root);

    if(io->direction == IO_INGRESS) {
        
        if(slots < (UINT16_MAX/2)) {
            slots = slots*2;
        }    


        /** Start job reading from RX thread TXQ. */
        timer_add_periodic(&g_ctx->timer_root, &thread->main_rx_job, "RX", 
                           0, config->rx_interval, 
                           io, &io_thread_rx_job);
    } else if(!interface->tx_job) {
        /** Start job writing to first TX thread TXQ */
        timer_add_periodic(&g_ctx->timer_root, &interface->rx_job, "TX", 
                           0, config->rx_interval, 
                           io, &io_thread_tx_job);
    }

    /* Init TXQ */
    io->txq = calloc(1, sizeof(bbl_txq_s));
    if(!(io->txq && bbl_txq_init(io->txq, slots))) {
        return false;
    }

    return true;
}

void
io_thread_start_all()
{
    io_thread_s *thread = g_ctx->io_threads;
    while(thread) {
        pthread_create(&thread->thread, NULL, thread->start_fn, (void *)thread);
        thread = thread->next;
    }
}

void
io_thread_stop_all()
{
    io_thread_s *thread = g_ctx->io_threads;
    while(thread) {
        pthread_mutex_lock(&thread->mutex);
        thread->active = false;
        pthread_mutex_unlock(&thread->mutex);
        thread = thread->next;

    }
    /* Wait for threads to be stopped */
    thread = g_ctx->io_threads;
    while(thread) {
        pthread_join(thread->thread, NULL);
    }
}