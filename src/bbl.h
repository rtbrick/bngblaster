/*
 * BNG BLaster (BBL), a tool for scale testing the control plane of BNG and BRAS devices.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_H__
#define __BBL_H__

#include "config.h"

#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <signal.h>
#include <math.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>

#define NCURSES_NOMACROS 1
#include <curses.h>

/* Experimental NETMAP Support */
#ifdef BNGBLASTER_NETMAP
#define LIBNETMAP_NOTHREADSAFE
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif

#include "libdict/dict.h"
#include "bbl_def.h"
#include "bbl_protocols.h"
#include "bbl_logging.h"
#include "bbl_timer.h"
#include "bbl_utils.h"
#include "bbl_stats.h"
#include "bbl_config.h"
#include "bbl_l2tp.h"
#include "bbl_session.h"
#include "bbl_ctx.h"
#include "bbl_send.h"
#include "bbl_interface.h"
#include "bbl_a10nsp.h"
#include "bbl_li.h"

WINDOW *log_win;
WINDOW *stats_win;

#endif