/*
 * BNG Blaster (BBL) - IS-IS PDU
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_PDU_H__
#define __BBL_ISIS_PDU_H__

void
isis_pdu_hdr(bbl_pdu_s *pdu, uint8_t type);

protocol_error_t
isis_pdu_load(bbl_pdu_s *pdu, uint8_t *buf, uint16_t len);

isis_tlv_s *
isis_pdu_next_tlv(bbl_pdu_s *pdu);

isis_tlv_s *
isis_pdu_first_tlv(bbl_pdu_s *pdu);

void
isis_pdu_update_len(bbl_pdu_s *pdu);

void
isis_pdu_update_lifetime(bbl_pdu_s *pdu, uint16_t lifetime);

void
isis_pdu_update_checksum(bbl_pdu_s *pdu);

void
isis_pdu_update_auth(bbl_pdu_s *pdu, char *key);

bool
isis_pdu_validate_checksum(bbl_pdu_s *pdu);

bool
isis_pdu_validate_auth(bbl_pdu_s *pdu, isis_auth_type auth, char *key);

void
isis_pdu_add_tlv(bbl_pdu_s *pdu, isis_tlv_s *tlv);

void
isis_pdu_add_tlv_area(bbl_pdu_s *pdu, isis_area_s *area, uint8_t area_count);

void
isis_pdu_add_tlv_protocols(bbl_pdu_s *pdu, bool ipv4, bool ipv6);

void
isis_pdu_add_tlv_ipv4_int_address(bbl_pdu_s *pdu, ipv4addr_t addr);

void
isis_pdu_add_tlv_te_router_id(bbl_pdu_s *pdu, ipv4addr_t addr);

void
isis_pdu_add_tlv_hostname(bbl_pdu_s *pdu, char *hostname);

void
isis_pdu_add_tlv_ipv6_int_address(bbl_pdu_s *pdu, ipv6addr_t *addr);

void
isis_pdu_add_tlv_p2p_adjacency_state(bbl_pdu_s *pdu, uint8_t state);

void
isis_pdu_add_tlv_ext_ipv4_reachability(bbl_pdu_s *pdu, ipv4_prefix *prefix, uint32_t metric, isis_sub_tlv_t *stlv);

void
isis_pdu_add_tlv_ipv6_reachability(bbl_pdu_s *pdu, ipv6_prefix *prefix, uint32_t metric);

void
isis_pdu_add_tlv_auth(bbl_pdu_s *pdu, isis_auth_type auth, char *key);

void
isis_pdu_add_tlv_ext_reachability(bbl_pdu_s *pdu, uint8_t *system_id, uint32_t metric);

void
isis_pdu_add_tlv_router_cap(bbl_pdu_s *pdu, ipv4addr_t router_id, 
                            bool ipv4, bool ipv6, 
                            uint32_t sr_base, uint32_t sr_range);

void
isis_pdu_padding(bbl_pdu_s *pdu);

#endif