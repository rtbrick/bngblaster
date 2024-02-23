/*
 * BNG Blaster (BBL) - IO PACKET_MMAP
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_PACKET_MMAP_H__
#define __BBL_IO_PACKET_MMAP_H__

bool
io_packet_mmap_init(io_handle_s *io);

void
io_packet_mmap_set_max_stream_len();

#endif