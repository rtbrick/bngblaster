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
 * @param io IO handle.
 */
bool
io_send(io_handle_s *io) {
    bool result = false;
    bbl_interface_s *interface;

    assert(io->direction == IO_EGRESS);

    switch (io->mode) {
        case IO_MODE_PACKET_MMAP_RAW:
        case IO_MODE_RAW:
            result = io_raw_send(io);
            break;
        case IO_MODE_PACKET_MMAP:
            result = io_packet_mmap_send(io);
            break;
        default:
            return false;
    }

    if(result && io->thread == NULL) {
        interface = io->interface;
        interface->stats.packets_tx++;
        interface->stats.bytes_tx += io->buf_len;
        /* Dump the packet into pcap file. */
        if(g_ctx->pcap.write_buf && (interface->io.ctrl || g_ctx->pcap.include_streams)) {
            pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                      interface->pcap_index, PCAPNG_EPB_FLAGS_INBOUND);
            pcapng_fflush();
        }
    }
    return result;
}