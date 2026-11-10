/*
 * BNG Blaster (BBL) - LDP Interface
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_INTERFACE_H__
#define __BBL_LDP_INTERFACE_H__

bool 
ldp_interface_init(bbl_network_interface_s *interface,
                   bbl_network_config_s *interface_config,
                   ldp_instance_s *instance);

char *
ldp_targeted_peer_address(ldp_adjacency_s *adjacency);

char *
ldp_targeted_local_address(ldp_adjacency_s *adjacency);

ldp_adjacency_s *
ldp_targeted_adjacency_add(ldp_instance_s *instance,
                           bbl_network_interface_s *interface,
                           ldp_targeted_neighbor_config_s *neighbor,
                           bool configured);

void
ldp_targeted_adjacency_free(ldp_adjacency_s *adjacency);

bool
ldp_targeted_init();

#endif