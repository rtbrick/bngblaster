/*
 * BNG Blaster (BBL) - LDP Hello
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_HELLO_H__
#define __BBL_LDP_HELLO_H__

protocol_error_t
ldp_hello_encode(bbl_network_interface_s *interface, 
                 uint8_t *buf, uint16_t *len, 
                 bbl_ethernet_header_s *eth);

void
ldp_hello_start(ldp_adjacency_s *adjacency);

void
ldp_hello_rx(bbl_network_interface_s *interface, 
             bbl_ethernet_header_s *eth,
             bbl_ipv4_s *ipv4,
             bbl_ldp_hello_s *ldp);

#endif