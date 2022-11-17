/*
 * BNG Blaster (BBL) - IS-IS PDU
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_PDU_H__
#define __BBL_ISIS_PDU_H__

#define PDU_CURSOR(_pdu)            ((_pdu)->pdu+(_pdu)->cur)
#define PDU_CURSOR_LEN(_pdu)        (uint16_t)((_pdu)->pdu_len-(_pdu)->cur)
#define PDU_CURSOR_RST(_pdu)        ((_pdu)->cur=0)
#define PDU_CURSOR_GET(_pdu)        ((_pdu)->cur)
#define PDU_CURSOR_SET(_pdu, _off)  ((_pdu)->cur=_off)
#define PDU_CURSOR_INC(_pdu, _off)  ((_pdu)->cur+=_off)
#define PDU_OFFSET(_pdu, _off)      ((_pdu)->pdu+_off)
#define PDU_REMAINING(_pdu)         (ISIS_MAX_PDU_LEN-(_pdu)->cur)

#define PDU_BUMP_WRITE_BUFFER(_pdu, _off) \
    (_pdu)->cur+=(_off); \
    (_pdu)->pdu_len+=(_off)

protocol_error_t
isis_pdu_load(isis_pdu_s *pdu, uint8_t *buf, uint16_t len);

isis_tlv_s *
isis_pdu_next_tlv(isis_pdu_s *pdu);

isis_tlv_s *
isis_pdu_first_tlv(isis_pdu_s *pdu);

void
isis_pdu_update_len(isis_pdu_s *pdu);

void
isis_pdu_update_lifetime(isis_pdu_s *pdu, uint16_t lifetime);

void
isis_pdu_update_checksum(isis_pdu_s *pdu);

void
isis_pdu_update_auth(isis_pdu_s *pdu, char *key);

bool
isis_pdu_validate_checksum(isis_pdu_s *pdu);

bool
isis_pdu_validate_auth(isis_pdu_s *pdu, isis_auth_type auth, char *key);

void
isis_pdu_init(isis_pdu_s *pdu, uint8_t pdu_type);

void
isis_pdu_add_u8(isis_pdu_s *pdu, uint8_t value);

void
isis_pdu_add_u16(isis_pdu_s *pdu, uint16_t value);

void
isis_pdu_add_u32(isis_pdu_s *pdu, uint32_t value);

void
isis_pdu_add_u64(isis_pdu_s *pdu, uint64_t value);

void
isis_pdu_add_bytes(isis_pdu_s *pdu, uint8_t *buf, uint16_t len);

void
isis_pdu_add_tlv(isis_pdu_s *pdu, isis_tlv_s *tlv);

void
isis_pdu_add_tlv_area(isis_pdu_s *pdu, isis_area_s *area, uint8_t area_count);

void
isis_pdu_add_tlv_protocols(isis_pdu_s *pdu, bool ipv4, bool ipv6);

void
isis_pdu_add_tlv_ipv4_int_address(isis_pdu_s *pdu, ipv4addr_t addr);

void
isis_pdu_add_tlv_te_router_id(isis_pdu_s *pdu, ipv4addr_t addr);

void
isis_pdu_add_tlv_hostname(isis_pdu_s *pdu, char *hostname);

void
isis_pdu_add_tlv_ipv6_int_address(isis_pdu_s *pdu, ipv6addr_t *addr);

void
isis_pdu_add_tlv_p2p_adjacency_state(isis_pdu_s *pdu, uint8_t state);

void
isis_pdu_add_tlv_ext_ipv4_reachability(isis_pdu_s *pdu, ipv4_prefix *prefix, uint32_t metric, isis_sub_tlv_t *stlv);

void
isis_pdu_add_tlv_ipv6_reachability(isis_pdu_s *pdu, ipv6_prefix *prefix, uint32_t metric);

void
isis_pdu_add_tlv_auth(isis_pdu_s *pdu, isis_auth_type auth, char *key);

void
isis_pdu_add_tlv_ext_reachability(isis_pdu_s *pdu, uint8_t *system_id, uint32_t metric);

void
isis_pdu_add_tlv_router_cap(isis_pdu_s *pdu, ipv4addr_t router_id, 
                            bool ipv4, bool ipv6, 
                            uint32_t sr_base, uint32_t sr_range);

void
isis_pdu_padding(isis_pdu_s *pdu);

#endif