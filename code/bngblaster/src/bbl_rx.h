/*
 * BNG Blaster (BBL) - RX
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_RX_H__
#define __BBL_RX_H__

bool
bbl_rx_thread(bbl_interface_s *interface, 
              bbl_ethernet_header_s *eth);

void
bbl_rx_handler(bbl_interface_s *interface, 
               bbl_ethernet_header_s *eth);

#endif