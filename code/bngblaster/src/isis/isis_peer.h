/*
 * BNG Blaster (BBL) - IS-IS Peer
 *
 * Christian Giese, June 2024
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_PEER_H__
#define __BBL_ISIS_PEER_H__

bool
isis_peer_dis_elect(isis_adjacency_s *adjacency);

void
isis_peer_update(isis_peer_s *peer, isis_pdu_s *pdu);

isis_peer_s*
isis_peer(isis_adjacency_s *adjacency, uint8_t *mac);

#endif