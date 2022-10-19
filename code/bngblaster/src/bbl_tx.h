/*
 * BNG Blaster (BBL) - TX Job
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_TX_H__
#define __BBL_TX_H__

void
bbl_arp_simeout(timer_s *timer);

protocol_error_t
bbl_tx(bbl_interface_s *interface, uint8_t *buf, uint16_t *len);

#endif