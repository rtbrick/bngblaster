/*
 * BNG Blaster (BBL) - IS-IS Adjacency
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
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

void
isis_adjacency_bfd_add(isis_adjacency_s *adjacency);

void
isis_adjacency_bfd_del(isis_adjacency_s *adjacency, uint8_t af);

void
isis_peer_bfd_update(isis_peer_s *peer);

void
isis_peer_bfd_del(isis_peer_s *peer, uint8_t af);

#endif