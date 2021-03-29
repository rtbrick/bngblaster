/*
 * BNG Blaster (BBL) - Netmap
 *
 * Christian Giese, October 2021
 *
 * Netmap is a an framework for very fast packet I/O from userspace.
 * https://github.com/luigirizzo/netmap
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_NETMAP_H__
#define __BBL_NETMAP_H__

#define LIBNETMAP_NOTHREADSAFE
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

typedef struct bbl_io_netmap_ctx_
{
    struct nm_desc *port;
} bbl_io_netmap_ctx;

bool
bbl_io_netmap_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len);

bool
bbl_io_netmap_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface, int slots);

#endif