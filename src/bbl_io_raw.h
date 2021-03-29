/*
 * BNG Blaster (BBL) - RAW Sockets
 *
 * Christian Giese, October 2021
 * 
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_IO_RAW_H__
#define __BBL_IO_RAW_H__

#define BBL_IO_RAW_BUFFER_LEN   2048

typedef struct bbl_io_raw_ctx_
{
    int fd_tx;
    int fd_rx;
    struct sockaddr_ll addr;
    uint8_t *buf;
} bbl_io_raw_ctx;

bool
bbl_io_raw_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len);

bool
bbl_io_raw_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface, int slots);

#endif