/*
 * BNG Blaster (BBL) - BGP Main
 *
 * Christian Giese, Mach 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_H__
#define __BBL_BGP_H__

#include "../bbl.h"
#include "bgp_def.h"
#include "bgp_message.h"
#include "bgp_mrt.h"

bool
bgp_init(bbl_ctx_s *ctx);

#endif