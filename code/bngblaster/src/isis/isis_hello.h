/*
 * BNG Blaster (BBL) - IS-IS Hello
 *
 * Christian Giese, June 2024
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_HELLO_H__
#define __BBL_ISIS_HELLO_H__

protocol_error_t
isis_hello_encode(bbl_network_interface_s *interface, 
                  uint8_t *buf, uint16_t *len, 
                  bbl_ethernet_header_s *eth,
                  uint8_t level);

void
isis_hello_handler_rx(bbl_network_interface_s *interface, 
                      bbl_ethernet_header_s *eth, 
                      isis_pdu_s *pdu, uint8_t level);

#endif