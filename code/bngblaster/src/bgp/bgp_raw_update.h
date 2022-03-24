/*
 * BNG Blaster (BBL) - BGP RAW Update Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_RAW_UPDATE_H__
#define __BBL_BGP_RAW_UPDATE_H__

bgp_raw_update_t *
bgp_raw_update_load(bbl_ctx_s *ctx, const char *file, bool decode_file);

#endif