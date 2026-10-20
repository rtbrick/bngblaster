/*
 * BNG Blaster (BBL) - IO RX Threads
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_THREAD_H__
#define __BBL_IO_THREAD_H__

void
io_thread_save_allowed_cpus();

bool
io_thread_cpu_allowed(uint16_t cpu);

void
io_thread_unlock_cpus();

bool
io_thread_init(io_handle_s *io);

bool
io_thread_start_all();

void
io_thread_stop_all();

#define IO_RX_BURST_MAX 256

io_result_t
io_thread_rx_handler(io_thread_s *thread, io_handle_s *io);

void
io_thread_rx_burst(io_thread_s *thread, io_handle_s *io,
                   uint8_t **bufs, uint16_t *lens, uint16_t count);

#endif