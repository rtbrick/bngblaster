/*
 * BNG Blaster (BBL) - OSPF MRT Files
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_MRT_H__
#define __BBL_OSPF_MRT_H__

#define OSPF_MRT_TYPE 32

typedef struct ospf_mrt_hdr_ {
    uint32_t  timestamp;
    uint16_t  type;
    uint16_t  subtype;
    uint32_t  length;
} __attribute__ ((__packed__)) ospf_mrt_hdr_t;

bool
ospf_mrt_load(ospf_instance_s *instance, char *file_path);

#endif