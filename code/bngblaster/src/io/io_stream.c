/*
 * BNG Blaster (BBL) - IO Bucket
 *
 * Christian Giese, January 2024
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

static io_bucket_s *
bucket_new(io_handle_s *io, double pps) 
{
    io_bucket_s *iter_bucket;
    io_bucket_s *io_bucket = calloc(1, sizeof(io_bucket_s));
    io_bucket->pps = pps;
    io_bucket->nsec = SEC / pps;

    iter_bucket = io->bucket_head;
    if(iter_bucket && iter_bucket->pps > pps) {
        while(iter_bucket) {
            if(iter_bucket->next && iter_bucket->pps > pps) {
                iter_bucket = iter_bucket->next;
            } else {
                io_bucket->next = iter_bucket->next;
                iter_bucket->next = io_bucket;
                break;
            }
        }
    } else {
        io_bucket->next = io->bucket_head;
        io->bucket_head = io_bucket;
        io->bucket_cur = io_bucket;
    }
    return io_bucket;
}

static void
bucket_stream_add(io_bucket_s *io_bucket, bbl_stream_s *stream)
{
    stream->io_next = io_bucket->stream_head;
    io_bucket->stream_head = stream;
    io_bucket->stream_cur = stream;
    io_bucket->stream_count++;
}

static void
bucket_smear(io_bucket_s *io_bucket, uint64_t start_nsec)
{
    uint64_t nsec = 0;
    uint64_t step_nsec = io_bucket->nsec / io_bucket->stream_count;
    bbl_stream_s *stream = io_bucket->stream_head;

    io_bucket->base = start_nsec;
    while(stream) {
        nsec += step_nsec;
        stream->expired = nsec;
        stream = stream->io_next;
    }
}

void
io_stream_add(io_handle_s *io, bbl_stream_s *stream)
{
    io_bucket_s *io_bucket = io->bucket_head;

    stream->io = io;
    io->stream_pps += stream->pps;
    io->stream_count++;
    while(io_bucket) {
        if(io_bucket->pps == stream->pps) {
            bucket_stream_add(io_bucket, stream);
            return;
        }
        io_bucket = io_bucket->next;
    }

    io_bucket = bucket_new(io, stream->pps);
    bucket_stream_add(io_bucket, stream);
}

void
io_stream_clear(io_handle_s *io)
{
    io_bucket_s *io_bucket = io->bucket_head;
    io->stream_pps = 0;
    io->stream_count = 0;
    while(io_bucket) {
        io_bucket->stream_count = 0;
        io_bucket->stream_head = NULL;
        io_bucket->stream_cur = NULL;
        io_bucket = io_bucket->next;
    }
}


void
io_stream_smear(io_handle_s *io)
{
    io_bucket_s *io_bucket = io->bucket_head;
    struct timespec now;
    uint64_t now_nsec;

    clock_gettime(CLOCK_MONOTONIC, &now);
    now_nsec = timespec_to_nsec(&now);
    while(io_bucket) {
        bucket_smear(io_bucket, now_nsec);
        io_bucket = io_bucket->next;
    }
}

void
io_stream_smear_all()
{
    bbl_interface_s *interface;
    io_handle_s *io;
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        io = interface->io.tx;
        while(io) {
            io_stream_smear(io);
            io = io->next;
        }
    }
}