/*
 * BNG Blaster (BBL) - IS-IS Peer
 *
 * Christian Giese, June 2024
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_PEER_H__
#define __BBL_ISIS_PEER_H__

bool
isis_peer_dis_elect(isis_adjacency_s *adjacency);

void
isis_peer_update(isis_peer_s *peer, isis_pdu_s *pdu);

void
isis_peer_down_p2p(isis_peer_s *peer, const char *reason);

void
isis_peer_down(isis_peer_s *peer, const char *reason);

bool
isis_peer_hello_valid(isis_instance_s *instance, isis_pdu_s *pdu, uint8_t level);

isis_peer_s*
isis_peer(isis_adjacency_s *adjacency, uint8_t *mac);

#endif