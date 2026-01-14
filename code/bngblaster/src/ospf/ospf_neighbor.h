/*
 * BNG Blaster (BBL) - OSPF Neighbor
 *
 * Christian Giese, June 2023
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_NEIGHBOR_H__
#define __BBL_OSPF_NEIGHBOR_H__

void
ospf_neighbor_update_state(ospf_neighbor_s *neighbor, uint8_t state);

void
ospf_neighbor_update(ospf_neighbor_s *ospf_neighbor, ospf_pdu_s *pdu);

ospf_neighbor_s *
ospf_neighbor_new(ospf_interface_s *ospf_interface, ospf_pdu_s *pdu);

void
ospf_neighbor_full(ospf_neighbor_s *ospf_neighbor);

void
ospf_neighbor_adjok(ospf_neighbor_s *ospf_neighbor);

void
ospf_neighbor_dbd_rx(ospf_interface_s *ospf_interface, 
                     ospf_neighbor_s *ospf_neighbor, 
                     ospf_pdu_s *pdu);

#endif