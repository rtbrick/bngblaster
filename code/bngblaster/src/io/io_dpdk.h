/*
 * BNG Blaster (BBL) - IO DPDK
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_DPDK_H__
#define __BBL_IO_DPDK_H__

typedef struct io_dpdk_ctx_ {
    uint16_t dev_count;
} io_dpdk_ctx_s;

bool
io_dpdk_init();

void
io_dpdk_close();

bool
io_dpdk_interface_init(bbl_interface_s *interface);

#endif