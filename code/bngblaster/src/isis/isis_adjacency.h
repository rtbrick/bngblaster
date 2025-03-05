/*
 * BNG Blaster (BBL) - IS-IS Adjacency
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_ADJACENCY_H__
#define __BBL_ISIS_ADJACENCY_H__

bool 
isis_adjacency_init(bbl_network_interface_s *interface,
                    bbl_network_config_s *interface_config,
                    isis_instance_s *instance);

void 
isis_adjacency_up(isis_adjacency_s *adjacency);

void
isis_adjacency_down(isis_adjacency_s *adjacency, const char *reason);

#endif