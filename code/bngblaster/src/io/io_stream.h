/*
 * BNG Blaster (BBL) - IO Stream
 *
 * Christian Giese, January 2024
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_STREAM_H__
#define __BBL_IO_STREAM_H__

void
io_stream_add(io_handle_s *io, bbl_stream_s *stream);

void
io_stream_clear(io_handle_s *io);

void
io_stream_smear(io_handle_s *io);

void
io_stream_smear_all();

#endif