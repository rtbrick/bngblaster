/*
 * BNG Blaster (BBL) - IO Bucket
 *
 * Christian Giese, January 2024
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

void
io_tocken_job(timer_s *timer)
{
    io_bucket_s *io_bucket = timer->data;
    if(io_bucket->started) {
        struct timespec time_elapsed;
        uint64_t tokens;
        timespec_sub(&time_elapsed, timer->timestamp, &io_bucket->timestamp_start);
        tokens = io_bucket->tokens_per_sec * time_elapsed.tv_sec;
        tokens += (io_bucket->tokens_per_sec * time_elapsed.tv_nsec) / SEC;
        io_bucket->tokens = tokens;
    } else {
        io_bucket->started = true;
        io_bucket->timestamp_start.tv_sec = timer->timestamp->tv_sec;
        io_bucket->timestamp_start.tv_nsec = timer->timestamp->tv_nsec;
    }
}

static io_bucket_s *
io_bucket_add(double pps) 
{
    io_bucket_s *io_bucket = calloc(1, sizeof(io_bucket_s));
    io_bucket->next = g_ctx->io_bucket;
    g_ctx->io_bucket = io_bucket;
    io_bucket->pps = pps;
    io_bucket->tokens_per_sec = pps * IO_TOKENS_PER_PACKET;
    timer_add_periodic(&g_ctx->timer_root, &io_bucket->timer, 
                       "TB", 0, 100001, io_bucket, &io_tocken_job);

    return io_bucket;
}

void
io_bucket_stream(bbl_stream_s *stream)
{
    io_bucket_s *io_bucket = g_ctx->io_bucket;
    while(io_bucket) {
        if(io_bucket->pps == stream->pps) {
            break;
        }
        io_bucket = io_bucket->next;
    }
    if(!io_bucket) {
        io_bucket = io_bucket_add(stream->pps);
    }
    stream->io_bucket = io_bucket;
}