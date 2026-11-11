/*
 * BNG Blaster (BBL) - IP Fragmentation
 *
 * Christian Giese, October 2024
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_FRAGMENT_H__
#define __BBL_FRAGMENT_H__

#define BBL_FRAGMENT_BUF_LEN    4050
#define BBL_FRAGMENT_BLOCKS     ((BBL_FRAGMENT_BUF_LEN + 7) / 8)
#define BBL_FRAGMENT_HASH_SIZE  4096
#define BBL_FRAGMENT_MAX        8192 /* max packets in reassembly */

typedef struct bbl_fragment_ {
    uint32_t    timestamp;
    uint32_t    src;
    uint32_t    dst;
    uint16_t    id;
    uint8_t     protocol;
    uint16_t    fragments; /* Number of fragments */
    uint16_t    max_offset; /* Max offset value */
    uint16_t    max_length; /* Max length (L2) */
    uint16_t    received; /* received 8 byte blocks */
    uint16_t    expected; /* expected bytes, 0 until the last fragment */

    struct bbl_fragment_ *prev; /* list of all entries */
    struct bbl_fragment_ *next;
    struct bbl_fragment_ *hash_prev; /* hash bucket */
    struct bbl_fragment_ *hash_next;

    uint64_t    blocks[(BBL_FRAGMENT_BLOCKS + 63) / 64]; /* received 8 byte blocks */
    uint8_t     buf[BBL_FRAGMENT_BUF_LEN];

} bbl_fragment_s;

void
bbl_fragment_rx(bbl_access_interface_s *access_interface,
                bbl_network_interface_s *network_interface,
                bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4);

void
bbl_fragment_init();

#endif
