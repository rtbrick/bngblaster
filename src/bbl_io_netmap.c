/*
 * BNG Blaster (BBL) - Netmap
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */


#include "bbl.h"
#include "bbl_pcap.h"
#include "bbl_rx.h"
#include "bbl_tx.h"

#ifdef BNGBLASTER_NETMAP

void
bbl_io_netmap_rx_job (timer_s *timer)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

	struct netmap_ring *ring;
	unsigned int i;

    uint8_t *eth_start;
    uint16_t eth_len;

    bbl_ethernet_header_t *eth;
    protocol_error_t decode_result;

    interface = timer->data;
    if (!interface) {
        return;
    }
    ctx = interface->ctx;

    /* Get RX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &interface->rx_timestamp);

    ring = NETMAP_RXRING(interface->io.port->nifp, 0);
    while (!nm_ring_empty(ring)) {

        i = ring->cur;
        eth_start = (uint8_t*)NETMAP_BUF(ring, ring->slot[i].buf_idx);
        eth_len = ring->slot[i].len;
        interface->stats.packets_rx++;
        interface->stats.bytes_rx += eth_len;

        /*
	     * Dump the packet into pcap file.
	     */
        if (ctx->pcap.write_buf) {
	        pcapng_push_packet_header(ctx, &interface->rx_timestamp, eth_start, eth_len,
				                      interface->pcap_index, PCAPNG_EPB_FLAGS_INBOUND);
        }

        decode_result = decode_ethernet(eth_start, eth_len, interface->ctx->sp_rx, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
#if 0
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = ring->ts.tv_sec;
            eth->timestamp.tv_nsec = ring->ts.tv_usec * 1000;
#endif
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = interface->rx_timestamp.tv_sec;
            eth->timestamp.tv_nsec = interface->rx_timestamp.tv_nsec;
            if(interface->access) {
                bbl_rx_handler_access(eth, interface);
            } else {
                bbl_rx_handler_network(eth, interface);
            }
        } else if (decode_result == UNKNOWN_PROTOCOL) {
            interface->stats.packets_rx_drop_unknown++;
        } else {
            interface->stats.packets_rx_drop_decode_error++;
        }

        ring->head = ring->cur = nm_ring_next(ring, i);
    }
    pcapng_fflush(ctx);
    ioctl(interface->io.port->fd, NIOCRXSYNC, NULL);
}

void
bbl_io_netmap_tx_job (timer_s *timer)
{
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    struct netmap_ring *ring;
	unsigned int i;

    uint8_t *buf;
    uint16_t len;
    uint16_t packets = 0;

    protocol_error_t tx_result = IGNORED;

    interface = timer->data;
    if (!interface) {
        return;
    }
    ctx = interface->ctx;

    /* Get TX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &interface->tx_timestamp);

    ring = NETMAP_TXRING(interface->io.port->nifp, 0);
    while(tx_result != EMPTY) {
        /* Check if this slot available for writing. */
        if (nm_ring_empty(ring)) {
            interface->stats.no_tx_buffer++;
            break;
        }
        i = ring->cur;
        buf = (uint8_t*)NETMAP_BUF(ring, ring->slot[i].buf_idx);

        tx_result = bbl_tx(ctx, interface, buf, &len);
        if (tx_result == PROTOCOL_SUCCESS) {
            packets++;
            interface->stats.packets_tx++;
            interface->stats.bytes_tx += len;
            ring->slot[i].len = len;
            ring->head = ring->cur = nm_ring_next(ring, i);
            /* Dump the packet into pcap file. */
            if (ctx->pcap.write_buf) {
                pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                          buf, len, interface->pcap_index,
                                          PCAPNG_EPB_FLAGS_OUTBOUND);
            }
        }
    }
    if(packets) {
        pcapng_fflush(ctx);
        ioctl(interface->io.port->fd, NIOCTXSYNC, NULL);
    }
}

/**
 * bbl_io_netmap_send
 *
 * Send single packet trough given interface.
 *
 * @param interface interface.
 * @param packet packet to be send
 * @param packet_len packet length
 */
bool
bbl_io_netmap_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len) {
    struct netmap_ring *ring;
	unsigned int i;
    uint8_t *buf;
    ring = NETMAP_TXRING(interface->io.port->nifp, 0);
    if (nm_ring_empty(ring)) {
        interface->stats.no_tx_buffer++;
        return false;
    }
    i = ring->cur;
    buf = (uint8_t*)NETMAP_BUF(ring, ring->slot[i].buf_idx);
    memcpy(buf, packet, packet_len);
    ring->slot[i].len = packet_len;
    ring->head = ring->cur = nm_ring_next(ring, i);
    return true;
}

/**
 * bbl_io_netmap_add_interface
 *
 * @param ctx global context
 * @param interface interface.
 */
bool
bbl_io_netmap_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface) {
    char timer_name[128];
    char netmap_port[128];

    snprintf(netmap_port, sizeof(netmap_port), "netmap:%s", interface->name);

    /*
     * Open netmap port.
     */
    interface->io.port = nm_open(netmap_port, NULL, NETMAP_NO_TX_POLL, NULL);
    if (interface->io.port == NULL) {
		if (!errno) {
            LOG(ERROR, "Failed to nm_open(%s): not a netmap port\n", netmap_port);
		} else {
			LOG(ERROR, "Failed to nm_open(%s): %s\n", netmap_port, strerror(errno));
		}
        return false;
	}

    /*
     * Add an periodic timer for polling I/O.
     */
    snprintf(timer_name, sizeof(timer_name), "%s TX", interface->name);
    timer_add_periodic(&ctx->timer_root, &interface->tx_job, timer_name, 0, ctx->config.tx_interval, interface, &bbl_io_netmap_tx_job);
    snprintf(timer_name, sizeof(timer_name), "%s RX", interface->name);
    timer_add_periodic(&ctx->timer_root, &interface->rx_job, timer_name, 0, ctx->config.rx_interval, interface, &bbl_io_netmap_rx_job);

    return true;
}

#endif
