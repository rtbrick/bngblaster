/*
 * BNG Blaster (BBL) - IP Fragmentation
 *
 * Christian Giese, October 2024
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_FRAGMENT_H__
#define __BBL_FRAGMENT_H__

typedef struct bbl_fragment_ {
    uint32_t    timestamp;
    uint32_t    src;
    uint32_t    dst;
    uint16_t    id;
    uint16_t    fragments; /* Number of fragments */
    uint16_t    max_offset; /* Max offset value */
    uint16_t    max_length; /* Max length (L2) */
    uint16_t    recived;
    uint16_t    expected;

    struct bbl_fragment_ *prev;
    struct bbl_fragment_ *next;

    uint8_t     buf[4050];

} bbl_fragment_s;

void 
bbl_fragment_rx(bbl_access_interface_s *access_interface,
                bbl_network_interface_s *network_interface,
                bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4);

void
bbl_fragment_init();

#endif
