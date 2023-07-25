/*
 * BNG Blaster (BBL) - OSPF Checksum
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_CHECKSUM_H__
#define __BBL_OSPF_CHECKSUM_H__

uint16_t 
ospf_checksum_fletcher16(uint8_t *buf, uint16_t len, uint16_t offset);

#endif