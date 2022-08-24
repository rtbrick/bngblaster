/*
 * BNG Blaster (BBL) - IO
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "io.h"

/**
 * bbl_io_send
 *
 * Send single packet trough given interface.
 *
 * @param interface interface.
 * @param packet packet to be send
 * @param packet_len packet length
 */
bool
bbl_io_send(bbl_interface_t *interface, uint8_t *packet, uint16_t packet_len) {
    bbl_ctx_t *ctx = interface->ctx;
    bool result = false;

    switch (interface->io.mode) {
        case IO_MODE_PACKET_MMAP_RAW:
        case IO_MODE_RAW:
            result = bbl_io_raw_send(interface, packet, packet_len);
            break;
        case IO_MODE_PACKET_MMAP:
            result = bbl_io_packet_mmap_send(interface, packet, packet_len);
            break;
        default:
            return false;
    }

    if(result) {
        interface->stats.packets_tx++;
        interface->stats.bytes_tx += packet_len;
        /* Dump the packet into pcap file. */
        if(g_ctx->pcap.write_buf && (interface->io.ctrl || ctx->pcap.include_streams)) {
            pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                      packet, packet_len, interface->pcap_index,
                                      PCAPNG_EPB_FLAGS_OUTBOUND);
            pcapng_fflush(ctx);
        }
    }
    return result;
}