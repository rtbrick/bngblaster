/*
 * BNG Blaster (BBL) - OSPF Hello
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_HELLO_H__
#define __BBL_OSPF_HELLO_H__

protocol_error_t
ospf_hello_v2_encode(bbl_network_interface_s *interface, 
                     uint8_t *buf, uint16_t *len, 
                     bbl_ethernet_header_s *eth);

protocol_error_t
ospf_hello_v3_encode(bbl_network_interface_s *interface, 
                     uint8_t *buf, uint16_t *len, 
                     bbl_ethernet_header_s *eth);

void
ospf_hello_handler_rx(bbl_network_interface_s *interface,
                      ospf_pdu_s *pdu);
                    
#endif