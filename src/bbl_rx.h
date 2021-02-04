/*
 * BNG Blaster (BBL) - RX Job
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_RX_H__
#define __BBL_RX_H__

void
bbl_igmp_timeout(timer_s *timer);

void
bbl_rx_job (timer_s *timer);

#endif