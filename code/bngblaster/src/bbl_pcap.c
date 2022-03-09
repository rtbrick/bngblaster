/*
 * BNG Blaster (BBL) - PCAP
 * Write packets to a file in pcapng format.
 *
 * Hannes Gredler, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>

#include "bbl.h"
#include "bbl_pcap.h"

/*
 * Prototypes
 */
void pcapng_open(bbl_ctx_s *);

/*
 * Flush the write buffer
 */
void
pcapng_fflush (bbl_ctx_s *ctx)
{
    int res;

    if (!ctx->pcap.write_buf) {
        return;
    }

    if (!ctx->pcap.write_idx) {
        return;
    }

    if (ctx->pcap.fd == -1) {
        /*
         * File is not yet opened, try to open it.
         */
        pcapng_open(ctx);
        if (ctx->pcap.fd == -1) {
            /*
             * Darn, still closed.
             */

            /*
             * We may have buffered for too long.
             * Reset the buffer before it is running full.
             */
            if (ctx->pcap.write_idx >= (PCAPNG_WRITEBUFSIZE/16)*15) {
                ctx->pcap.write_idx = 0;
                ctx->pcap.wrote_header = false;
            }
            return;
        }
    }

    res = write(ctx->pcap.fd, ctx->pcap.write_buf, ctx->pcap.write_idx);

    /*
     * Blocked?
     */
    if (res == -1) {
        switch (errno) {
            case EPIPE:
                /*
                 * Our listener just went away.
                 * Restart the fifo and write a PCAP header for the next listener.
                 */
                close(ctx->pcap.fd);
                pcapng_init(ctx);
                break;
            default:
                /*
                 * Reset the buffer for unresponsive callers.
                 */
                pcapng_init(ctx);
                break;
        }
        return;
    }

    /*
     * Full write ?
     */
    if (res == (int)ctx->pcap.write_idx) {
        LOG(PCAP, "drained %u bytes buffer to pcap file %s\n",
            ctx->pcap.write_idx, ctx->pcap.filename);

        ctx->pcap.write_idx = 0;
        return;
    }

    /*
     * Partial write ?
     */
    if (res && res < (int)ctx->pcap.write_idx) {

        /*
         * Rebase the buffer.
         */
        memmove(ctx->pcap.write_buf, ctx->pcap.write_buf+res, ctx->pcap.write_idx - res);
        ctx->pcap.write_idx -= res;
    }
}

/*
 * Push data to the write buffer and update the cursor.
 */
static void
bbl_pcap_push_le_uint(bbl_ctx_s *ctx, uint32_t length, uint64_t value)
{
    /*
     * Buffer overrun protection.
     */
    if ((ctx->pcap.write_idx + length) >= PCAPNG_WRITEBUFSIZE) {
        return;
    }

    /*
     * Write the data.
     */
    write_le_uint(ctx->pcap.write_buf + ctx->pcap.write_idx, length, value);

    /*
     * Adjust the cursor.
     */
    ctx->pcap.write_idx += length;
}

/*
 * Try to open the file.
 */
void
pcapng_open (bbl_ctx_s *ctx)
{
    /*
     * Open the file.
     */
    ctx->pcap.fd = open(ctx->pcap.filename, O_WRONLY | O_CREAT | O_TRUNC | O_NONBLOCK, PCAPNG_PERMS);
    if (ctx->pcap.fd == -1) {
        switch (errno) {
            default:
                LOG(ERROR, "got ERROR %d when opening pcap-file %s\n", errno, ctx->pcap.filename);
                return;
        }
    } else {
        LOG(INFO, "opened pcap-file %s\n", ctx->pcap.filename);
    }
}

/*
 * Initialize a fresh pcap fifo writing context.
 */
void
pcapng_init (bbl_ctx_s *ctx)
{
    if (!ctx) {
        return;
    }

    if (!ctx->pcap.filename) {
        return;
    }

    /*
     * Write buffer for I/O.
     */
    if (!ctx->pcap.write_buf) {
        ctx->pcap.write_buf = calloc(1, PCAPNG_WRITEBUFSIZE);
    } else {
        ctx->pcap.write_idx = 0;
    }

    /*
     * Open the file.
     */
    pcapng_open(ctx);
}

/*
 * Free pcap related resources.
 */
void
pcapng_free (bbl_ctx_s *ctx)
{
    if (!ctx) {
        return;
    }

    pcapng_fflush(ctx);

    if (ctx->pcap.fd != -1) {
        close(ctx->pcap.fd);
        ctx->pcap.fd = -1;
        return;
    }

    if (ctx->pcap.write_buf) {
        free(ctx->pcap.write_buf);
        ctx->pcap.write_buf = NULL;
    }
}

/*
 * Calculate padding bytes.
 */
static uint32_t
calc_pad(uint32_t length)
{
    switch (length % 4) {
        case 3:
            return 1;
        case 2:
            return 2;
        case 1:
            return 3;
        case 0:
            return 0;
    }
    return 0;
}

/*
 * Write a pcapng section header block.
 */
void
pcapng_push_section_header (bbl_ctx_s *ctx)
{
    uint32_t start_idx, total_length, option_length;

    start_idx = ctx->pcap.write_idx;

    bbl_pcap_push_le_uint(ctx, 4, PCAPNG_SHB); /* block type */
    bbl_pcap_push_le_uint(ctx, 4, 0); /* block total_length */
    bbl_pcap_push_le_uint(ctx, 4, 0x1a2b3c4d); /* byte order magic */
    bbl_pcap_push_le_uint(ctx, 2, 1); /* version_major */
    bbl_pcap_push_le_uint(ctx, 2, 0); /* version_minor */
    bbl_pcap_push_le_uint(ctx, 8, 0xffffffffffffffff); /* section length */

    /*
     * Write shb_userappl option
     */
    bbl_pcap_push_le_uint(ctx, 2, PCAPNG_SHB_USERAPPL_OPTION); /* option_type */
    option_length = snprintf((char *)ctx->pcap.write_buf + ctx->pcap.write_idx + 2,
                 PCAPNG_WRITEBUFSIZE - ctx->pcap.write_idx - 2,
                 "%s", PCAPNG_SHB_USERAPPL);
    bbl_pcap_push_le_uint(ctx, 2, option_length); /* option_length */
    ctx->pcap.write_idx += option_length;
    bbl_pcap_push_le_uint(ctx, calc_pad(option_length), 0);

    /*
     * Calculate total length field. It occurs twice. Overwrite and append.
     */
    total_length = ctx->pcap.write_idx - start_idx + 4;
    write_le_uint(ctx->pcap.write_buf+start_idx+4, 4, total_length); /* block total_length */
    bbl_pcap_push_le_uint(ctx, 4, total_length); /* block total_length */
}

/*
 * Write a pcapng interface header block.
 */
void
pcapng_push_interface_header (bbl_ctx_s *ctx, uint32_t dlt, const char *if_name)
{
    uint32_t start_idx, total_length, option_length;

    start_idx = ctx->pcap.write_idx;

    bbl_pcap_push_le_uint(ctx, 4, PCAPNG_IDB); /* block type */
    bbl_pcap_push_le_uint(ctx, 4, 0); /* block total_length */
    bbl_pcap_push_le_uint(ctx, 2, dlt); /* link_type */
    bbl_pcap_push_le_uint(ctx, 2, 0); /* reserved */
    bbl_pcap_push_le_uint(ctx, 4, 9*1024); /* snaplen */

    /*
     * Write idb_ifname option
     */
    bbl_pcap_push_le_uint(ctx, 2, PCAPNG_IDB_IFNAME_OPTION); /* option_type */
    option_length = snprintf((char *)ctx->pcap.write_buf + ctx->pcap.write_idx + 2,
                 PCAPNG_WRITEBUFSIZE - ctx->pcap.write_idx - 2,
                 "%s", if_name);
    bbl_pcap_push_le_uint(ctx, 2, option_length); /* option_length */
    ctx->pcap.write_idx += option_length;
    bbl_pcap_push_le_uint(ctx, calc_pad(option_length), 0);

    /*
     * Calculate total length field. It occurs twice. Overwrite and append.
     */
    total_length = ctx->pcap.write_idx - start_idx + 4;
    write_le_uint(ctx->pcap.write_buf+start_idx+4, 4, total_length); /* block total_length */
    bbl_pcap_push_le_uint(ctx, 4, total_length); /* block total_length */
}

/*
 * Write a pcapng enhanced packet block.
 */
void
pcapng_push_packet_header (bbl_ctx_s *ctx, struct timespec *ts, u_char *data, uint32_t packet_length,
               uint32_t ifindex, uint32_t direction)
{
    bbl_interface_s *interface;
    uint32_t start_idx, total_length;
    uint64_t ts_usec;

    if (!ctx->pcap.wrote_header) {
        pcapng_push_section_header(ctx);

        /*
        * Push a list of interfaces.
        */
        CIRCLEQ_FOREACH(interface, &ctx->interface_qhead, interface_qnode) {
            pcapng_push_interface_header(ctx, DLT_EN10MB, interface->name);
        }
        ctx->pcap.wrote_header = true;
    }

    start_idx = ctx->pcap.write_idx;

    bbl_pcap_push_le_uint(ctx, 4, PCAPNG_EPB); /* block type */
    bbl_pcap_push_le_uint(ctx, 4, 0); /* block total_length */
    bbl_pcap_push_le_uint(ctx, 4, ifindex); /* interface_id */

    ts_usec = ts->tv_sec * 1000000 + ts->tv_nsec/1000;
    bbl_pcap_push_le_uint(ctx, 4, ts_usec>>32); /* timestamp usec msb */
    bbl_pcap_push_le_uint(ctx, 4, ts_usec & 0xffffffff); /* timestamp usec lsb */

    bbl_pcap_push_le_uint(ctx, 4, packet_length); /* captured packet length */
    bbl_pcap_push_le_uint(ctx, 4, packet_length); /* original packet length */

    /*
     * Copy packet
     */
    memcpy(&ctx->pcap.write_buf[ctx->pcap.write_idx], data, packet_length);
    ctx->pcap.write_idx += packet_length;
    bbl_pcap_push_le_uint(ctx, calc_pad(packet_length), 0); /* write pad bytes */

    /*
     * Write epb_flags option for storing packet direction
     */
    bbl_pcap_push_le_uint(ctx, 2, PCAPNG_EPB_FLAGS_OPTION); /* option_type */
    bbl_pcap_push_le_uint(ctx, 2, 4); /* option_length */
    bbl_pcap_push_le_uint(ctx, 4, direction & 0x3); /* direction */

    /*
     * Calculate total length field. It occurs twice. Overwrite and append.
     */
    total_length = ctx->pcap.write_idx - start_idx + 4;
    write_le_uint(ctx->pcap.write_buf+start_idx+4, 4, total_length); /* block total_length */
    bbl_pcap_push_le_uint(ctx, 4, total_length); /* block total_length */

    LOG(PCAP, "wrote %u bytes pcap packet data, buffer fill %u/%u\n",
        packet_length, ctx->pcap.write_idx, PCAPNG_WRITEBUFSIZE);

    /*
     * Buffer about to be overrun ?
     */
    if (ctx->pcap.write_idx >= (PCAPNG_WRITEBUFSIZE/16)*15) {
        pcapng_fflush(ctx);
    }
}
