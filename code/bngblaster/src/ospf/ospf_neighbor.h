/*
 * BNG Blaster (BBL) - OSPF Neighbor
 *
 * Christian Giese, June 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_NEIGHBOR_H__
#define __BBL_OSPF_NEIGHBOR_H__

protocol_error_t
ospf_neighbor_db_description(ospf_neighbor_s *ospf_neighbor);

void
ospf_neigbor_state(ospf_neighbor_s *neighbor, uint8_t state);

ospf_neighbor_s *
ospf_neigbor_new(ospf_interface_s *ospf_interface, ospf_pdu_s *pdu);

#endif