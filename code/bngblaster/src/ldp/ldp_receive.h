/*
 * BNG Blaster (BBL) - LDP Receive Functions
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_RECEIVE_H__
#define __BBL_LDP_RECEIVE_H__

void 
ldp_receive_cb(void *arg, uint8_t *buf, uint16_t len);

#endif