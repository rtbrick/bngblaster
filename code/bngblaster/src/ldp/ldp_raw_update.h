/*
 * BNG Blaster (BBL) - LDP RAW Update Functions
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_RAW_UPDATE_H__
#define __BBL_LDP_RAW_UPDATE_H__

ldp_raw_update_s *
ldp_raw_update_load(const char *file, bool decode_file);

#endif