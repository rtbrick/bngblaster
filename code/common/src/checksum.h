/*
 * Checksum Library
 *
 * Hannes Gredler, February 2024
 * Christian Giese, October 2024
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __COMMON_CHECKSUM_H__
#define __COMMON_CHECKSUM_H__
#include "common.h"

uint16_t
validate_fletcher_checksum(const uint8_t *pptr, uint length);

uint16_t
calculate_fletcher_checksum(uint8_t *pptr, uint checksum_offset, uint length);

#endif
