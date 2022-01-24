/*
 * BNG Blaster (BBL) - IS-IS PSNP
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_PSNP_H__
#define __BBL_ISIS_PSNP_H__

void
isis_psnp_job (timer_s *timer);

void
isis_psnp_handler_rx(bbl_interface_s *interface, isis_pdu_t *pdu, uint8_t level);

#endif