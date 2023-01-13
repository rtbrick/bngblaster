/*
 * BNG Blaster (BBL) - BGP Main
 *
 * Christian Giese, Mach 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_H__
#define __BBL_BGP_H__

#include "../bbl.h"
#include "bgp_def.h"
#include "bgp_session.h"
#include "bgp_message.h"
#include "bgp_receive.h"
#include "bgp_raw_update.h"
#include "bgp_ctrl.h"

bool
bgp_init();

void
bgp_teardown();

#endif