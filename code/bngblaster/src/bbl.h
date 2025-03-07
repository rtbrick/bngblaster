/*
 * BNG BLaster (BBL), a tool for scale testing the control plane of BNG and BRAS devices.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_H__
#define __BBL_H__

#define NCURSES_ENABLED     1
#define NCURSES_NOMACROS    1
#include <curses.h>
#include <jansson.h>
#include <sched.h>
#include <pthread.h>

#include <stdatomic.h>
#include <common_include.h>
#include "picohttpparser.h"

#include "bbl_def.h"

#include "bbl_protocols.h"
#include "io/io_def.h"
#include "bgp/bgp_def.h"
#include "isis/isis_def.h"
#include "ospf/ospf_def.h"
#include "ldp/ldp_def.h"

#include "bbl_ctrl.h"
#include "bbl_stats.h"
#include "bbl_access_line.h"
#include "bbl_config.h"
#include "bbl_l2tp.h"
#include "bbl_igmp.h"
#include "bbl_session.h"
#include "bbl_ctx.h"
#include "bbl_txq.h"
#include "bbl_interface.h"
#include "bbl_lag.h"
#include "bbl_access.h"
#include "bbl_network.h"
#include "bbl_a10nsp.h"
#include "bbl_li.h"
#include "bbl_cfm.h"
#include "bbl_tcp.h"
#include "bbl_arp_client.h"
#include "bbl_icmp_client.h"
#include "bbl_http_client.h"
#include "bbl_http_server.h"
#include "bbl_fragment.h"

#include "io/io.h"
#include "bgp/bgp.h"
#include "isis/isis.h"
#include "ospf/ospf.h"
#include "ldp/ldp.h"

extern bbl_ctx_s *g_ctx;
extern WINDOW *log_win;
extern WINDOW *stats_win;

void
teardown_request();

const char*
test_state();

time_t
test_duration();

void
global_traffic_enable(bool status);

#endif