/*
 * BNG Blaster (BBL) - TX Job
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */
#ifndef __BBL_TX_H__
#define __BBL_TX_H__

void
bbl_arp_timeout (timer_s *timer);

protocol_error_t
bbl_tx (bbl_ctx_s *ctx, bbl_interface_s *interface, uint8_t *buf, uint16_t *len);

#endif