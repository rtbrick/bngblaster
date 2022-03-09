/*
 * BNG BLaster (BBL), a tool for scale testing the control plane of BNG and BRAS devices.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_H__
#define __BBL_H__

#define NCURSES_ENABLED     1
#define NCURSES_NOMACROS    1
#include <curses.h>
#include <jansson.h>
#include <pthread.h>

#include <common_include.h>

/* Experimental NETMAP Support */
#ifdef BNGBLASTER_NETMAP
#define LIBNETMAP_NOTHREADSAFE
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif

#include "bbl_def.h"

#include "bbl_protocols.h"
#include "isis/isis_def.h"

#include "bbl_stats.h"
#include "bbl_access_line.h"
#include "bbl_config.h"
#include "bbl_l2tp.h"
#include "bbl_session.h"
#include "bbl_ctx.h"
#include "bbl_send.h"
#include "bbl_interface.h"
#include "bbl_a10nsp.h"
#include "bbl_li.h"
#include "isis/isis.h"

WINDOW *log_win;
WINDOW *stats_win;

void
enable_disable_traffic(bbl_ctx_s *ctx, bool status);

#endif