/*
 * BNG Blaster (BBL) - OSPF Main
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_H__
#define __BBL_OSPF_H__

#include "../bbl.h"
#include "ospf_def.h"
#include "ospf_utils.h"
#include "ospf_pdu.h"
#include "ospf_adjacency.h"
#include "ospf_lsa.h"
#include "ospf_ctrl.h"
#include "ospf_mrt.h"

bool
ospf_init();

void
ospf_handler_rx_ipv4(bbl_network_interface_s *interface, 
                     bbl_ethernet_header_s *eth, 
                     bbl_ipv4_s *ipv4);

void
ospf_handler_rx_ipv6(bbl_network_interface_s *interface, 
                     bbl_ethernet_header_s *eth, 
                     bbl_ipv6_s *ipv6);

void
ospf_teardown();

#endif