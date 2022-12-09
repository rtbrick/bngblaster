/*
 * BNG Blaster (BBL) - LDP Main
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_H__
#define __BBL_LDP_H__

#include "../bbl.h"
#include "ldp_def.h"
#include "ldp_message.h"
#include "ldp_hello.h"
#include "ldp_interface.h"
#include "ldp_receive.h"
#include "ldp_session.h"

bool
ldp_init();

void
ldp_teardown();

#endif