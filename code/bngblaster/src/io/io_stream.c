/*
 * BNG Blaster (BBL) - IO Bucket
 *
 * Christian Giese, January 2024
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
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
    io_bucket->stream_count++;
}

static void
bucket_shuffle(io_bucket_s *io_bucket)
{
    bbl_stream_s *stream;
    bbl_stream_s *next;

    if(!io_bucket) return;

    if(io_bucket->stream_count) {
        stream = io_bucket->stream_head;
        while(stream) {
            next = stream->io_next;
            if(next && next->flow_id%3==0) {
                stream->io_next = next->io_next;
                stream = next->io_next;
                next->io_next = io_bucket->stream_head;
                io_bucket->stream_head = next;
            } else {
                stream = next;
            }
        }
    }
    io_bucket->stream_cur = NULL;
}

static void
bucket_smear(io_bucket_s *io_bucket)
{
    uint64_t nsec = 0;
    uint64_t step_nsec;
    bbl_stream_s *stream;

    if(io_bucket && io_bucket->stream_count) {
        step_nsec = io_bucket->nsec / io_bucket->stream_count;
        io_bucket->base = 0;
        io_bucket->stream_cur = NULL;
        stream = io_bucket->stream_head;
        while(stream) {
            nsec += step_nsec;
            stream->expired = nsec;
            stream = stream->io_next;
        }
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
    while(io_bucket) {
        bucket_shuffle(io_bucket);
        bucket_smear(io_bucket);
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

void
io_stream_update_pps(io_handle_s *io)
{
    io_bucket_s *io_bucket = io->bucket_head;
    bbl_stream_s *stream;
    bbl_stream_s *stream_next;
    bbl_stream_s *stream_prev;

    while(io_bucket) {
        stream_next = io_bucket->stream_head;
        stream_prev = NULL;
        while(stream_next) {
            stream = stream_next;
            stream_next = stream->io_next;
            if(stream->update_pps) {
                /* Remove stream from bucket. */
                if(stream_prev) {
                    stream_prev->io_next = stream_next;
                } else {
                    io_bucket->stream_head = stream_next;
                }
                io_bucket->stream_count--;
                io_bucket->stream_cur = io_bucket->stream_head;
                io->stream_count--;
                io->stream_pps -= stream->pps;
                stream->io_next = NULL;
                /* Add stream to new bucket. */
                if(io == stream->io) {
                    LOG(DEBUG, "Update stream %s flow-id %lu pps from %0.2lf to %0.2lf\n", 
                        stream->config->name, stream->flow_id,
                        io_bucket->pps, stream->pps);
                    io_stream_add(io, stream);
                } else {
                    LOG(DEBUG, "Update stream %s flow-id %lu IO interface from %s to %s\n", 
                        stream->config->name, stream->flow_id,
                        io->interface->name, stream->io->interface->name);
                    stream->io->update_streams = true;
                    io_stream_add(stream->io, stream);
                }
                if(stream->pps < 1.0) {
                    stream->rate_packets_rx.avg = 0;
                    stream->rate_packets_tx.avg = 0;
                }
                stream->update_pps = false;
            } else {
                stream_prev = stream;
            }
        }
        io_bucket = io_bucket->next;
    }
    io_stream_smear(io);
    io->update_streams = false;
}