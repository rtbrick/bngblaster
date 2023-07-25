/*
 * BNG Blaster (BBL) - OSPF LSA
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_LSA_H__
#define __BBL_OSPF_LSA_H__

int
ospf_lsa_key_compare(void *id1, void *id2);

void
ospf_lsa_tree_entry_clear(void *key, void *ptr);

ospf_lsa_tree_entry_s *
ospf_lsa_tree_add(ospf_lsa_s *lsa, ospf_lsa_header_s *hdr, hb_tree *tree);

int
ospf_lsa_compare(ospf_lsa_header_s *hdr_a, ospf_lsa_header_s *hdr_b);

void
ospf_lsa_gc_job(timer_s *timer);

void
ospf_lsa_flood(ospf_lsa_s *lsa);

void
ospf_lsa_update_age(ospf_lsa_s *lsa, struct timespec *now);

void
ospf_lsa_purge_all_external(ospf_instance_s *instance);

bool
ospf_lsa_self_update(ospf_instance_s *ospf_instance);

void
ospf_lsa_self_update_request(ospf_instance_s *ospf_instance);

protocol_error_t
ospf_lsa_update_tx(ospf_interface_s *ospf_interface, 
                   ospf_neighbor_s *ospf_neighbor, 
                   bool retry);

protocol_error_t
ospf_lsa_req_tx(ospf_interface_s *ospf_interface, 
                ospf_neighbor_s *ospf_neighbor);

protocol_error_t
ospf_lsa_ack_tx(ospf_interface_s *ospf_interface, 
                ospf_neighbor_s *ospf_neighbor);

void
ospf_lsa_update_handler_rx(ospf_interface_s *ospf_interface, 
                           ospf_neighbor_s *ospf_neighbor, 
                           ospf_pdu_s *pdu);

void
ospf_lsa_req_handler_rx(ospf_interface_s *ospf_interface, 
                        ospf_neighbor_s *ospf_neighbor, 
                        ospf_pdu_s *pdu);

void
ospf_lsa_ack_handler_rx(ospf_interface_s *ospf_interface, 
                        ospf_neighbor_s *ospf_neighbor, 
                        ospf_pdu_s *pdu);

#endif