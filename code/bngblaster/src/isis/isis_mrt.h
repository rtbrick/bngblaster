/*
 * BNG Blaster (BBL) - IS-IS MRT Files
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_MRT_H__
#define __BBL_ISIS_MRT_H__

#define ISIS_MRT_TYPE 32

typedef struct isis_mrt_hdr_ {
    uint32_t  timestamp;
    uint16_t  type;
    uint16_t  subtype;
    uint32_t  length;
} __attribute__ ((__packed__)) isis_mrt_hdr_t;

bool
isis_mrt_load(isis_instance_s *instance, char *file_path, bool startup);

#endif