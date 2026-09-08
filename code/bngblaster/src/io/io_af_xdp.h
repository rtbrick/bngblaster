/*
 * BNG Blaster (BBL) - IO AF_XDP
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_AF_XDP_H__
#define __BBL_IO_AF_XDP_H__

bool
io_af_xdp_interface_init(bbl_interface_s *interface);

void
io_af_xdp_set_max_stream_len();

#endif
