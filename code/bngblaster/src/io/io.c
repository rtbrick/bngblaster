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
io_send(io_handle_s *io, uint8_t *buf, uint16_t len)
{
    bool result = false;

    assert(io->direction == IO_EGRESS);

    switch(io->mode) {
        case IO_MODE_PACKET_MMAP_RAW:
        case IO_MODE_RAW:
            result = io_raw_send(io, buf, len);
            break;
        case IO_MODE_PACKET_MMAP:
            result = io_packet_mmap_send(io, buf, len);
            break;
        default:
            return false;
    }

    if(result) {
        io->stats.packets++;
        io->stats.bytes += len;
        if(g_ctx->pcap.write_buf && g_ctx->pcap.include_streams && io->thread == NULL) {
            /* Dump the packet into pcap file. */
            pcapng_push_packet_header(&io->timestamp, buf, len,
                                    io->interface->pcap_index, PCAPNG_EPB_FLAGS_OUTBOUND);
            pcapng_fflush();
        }
    }
    return result;
}