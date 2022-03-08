/*
 * BNG Blaster (BBL) - IS-IS Checksum
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_CHECKSUM_H__
#define __BBL_ISIS_CHECKSUM_H__

uint16_t 
isis_checksum_fletcher16(uint8_t *buf, uint16_t len, uint16_t offset);

#endif