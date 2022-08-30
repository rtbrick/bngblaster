/*
 * BNG Blaster (BBL) - IO
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_H__
#define __BBL_IO_H__

#include <assert.h>

#include "../bbl.h"
#include "../bbl_pcap.h"
#include "../bbl_stream.h"
#include "../bbl_rx.h"
#include "../bbl_tx.h"
#include "../bbl_txq.h"

#include "io_def.h"
#include "io_socket.h"
#include "io_interface.h"
#include "io_thread.h"

#include "io_raw.h"
#include "io_packet_mmap.h"
#include "io_dpdk.h"

bool
io_send(io_handle_s *io, uint8_t *buf, uint16_t len);

#endif