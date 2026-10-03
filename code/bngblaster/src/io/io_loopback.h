/*
 * BNG Blaster (BBL) - IO Loopback
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_LOOPBACK_H__
#define __BBL_IO_LOOPBACK_H__

bool
io_loopback_interface_init(bbl_interface_s *interface);

void
io_loopback_set_max_stream_len();

#endif
