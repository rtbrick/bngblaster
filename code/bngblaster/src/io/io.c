/*
 * BNG Blaster (BBL) - IO
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "io.h"

void
io_update_stream_token_bucket(io_handle_s *io)
{
    io->stream_tokens += io->stream_rate;
    if(io->stream_tokens > io->stream_burst) {
        io->stream_tokens = io->stream_burst;
    }
}

void
io_init_stream_token_bucket()
{
    bbl_interface_s *interface;
    io_handle_s *io;
    double rate;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        io = interface->io.tx;
        while(io) {
            rate = io->stream_pps / io->interface->config->tx_interval * 1000;
            io->stream_rate = rate * 1.2; /* +20% */
            if(rate - io->stream_burst) {
                /* Roundup. */
                io->stream_rate++;
            }
            io->stream_tokens = 0;
            io->stream_burst = io->stream_rate * 3;
            io = io->next;
        }
    }
}