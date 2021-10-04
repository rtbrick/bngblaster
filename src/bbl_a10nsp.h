/*
 * BNG Blaster (BBL) - PPPoE Server Functions
 *
 * Christian Giese, September 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_A10NSP_H__
#define __BBL_A10NSP_H__

void
bbl_a10nsp_rx(bbl_interface_s *interface, 
              bbl_session_s *session, 
              bbl_ethernet_header_t *eth);

#endif