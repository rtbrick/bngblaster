/*
 * BNG Blaster (BBL) - AF_XDP
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_AF_XDP_H__
#define __BBL_AF_XDP_H__

bool
bbl_io_af_xdp_send(bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len);

bool
bbl_io_af_xdp_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface);

#endif