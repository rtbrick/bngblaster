/*
 * BNG Blaster (BBL) - BGP Message Receive Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_RECEIVE_H__
#define __BBL_BGP_RECEIVE_H__

void 
bgp_receive_cb(void *arg, uint8_t *buf, uint16_t len);

#endif