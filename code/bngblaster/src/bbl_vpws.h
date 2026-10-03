/*
 * BNG Blaster (BBL) - EVPN VPWS Services
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_VPWS_H__
#define __BBL_VPWS_H__

/*
 * VPWS Service Key
 *
 * Fixed layout, zero padded and compared with memcmp.
 * Services are stored per network interface.
 */
typedef struct bbl_vpws_key_ {
    uint16_t vlan; /* customer VLAN within VPWS service */
    uint16_t inner_vlan;
    uint8_t  af; /* AF_INET or AF_INET6 */
    uint8_t  ip[IPV6_ADDR_LEN]; /* stream network address */
} __attribute__ ((__packed__)) bbl_vpws_key_s;

typedef struct bbl_vpws_ {
    bbl_vpws_key_s key;
    bbl_stream_s *stream; /* first stream, next via stream->vpws_next */
} bbl_vpws_s;

bool
bbl_vpws_add(bbl_stream_s *stream);

bool
bbl_vpws_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth);

#endif
