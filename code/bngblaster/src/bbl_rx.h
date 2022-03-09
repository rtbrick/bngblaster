/*
 * BNG Blaster (BBL) - RX Job
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_RX_H__
#define __BBL_RX_H__

void
bbl_rx_established_ipoe(bbl_ethernet_header_t *eth, bbl_interface_s *interface, bbl_session_s *session);

void
bbl_rx_handler_access(bbl_ethernet_header_t *eth, bbl_interface_s *interface);

void
bbl_rx_handler_network(bbl_ethernet_header_t *eth, bbl_interface_s *interface);

void
bbl_rx_handler_a10nsp(bbl_ethernet_header_t *eth, bbl_interface_s *interface);

#endif