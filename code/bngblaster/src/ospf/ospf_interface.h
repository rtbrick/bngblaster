/*
 * BNG Blaster (BBL) - OSPF Interface
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_INTERFACE_H__
#define __BBL_OSPF_INTERFACE_H__

void
ospf_interface_neighbor_change(ospf_interface_s *ospf_interface);

bool 
ospf_interface_init(bbl_network_interface_s *interface,
                    bbl_network_config_s *network_config,
                    uint8_t version);

#endif