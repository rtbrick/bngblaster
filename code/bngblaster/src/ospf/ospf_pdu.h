/*
 * BNG Blaster (BBL) - OSPF PDU
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_PDU_H__
#define __BBL_OSPF_PDU_H__

#define OSPF_PDU_CURSOR(_pdu)            ((_pdu)->pdu+(_pdu)->cur)
#define OSPF_PDU_CURSOR_LEN(_pdu)        (uint16_t)((_pdu)->pdu_len-(_pdu)->cur)
#define OSPF_PDU_CURSOR_RST(_pdu)        ((_pdu)->cur=0)
#define OSPF_PDU_CURSOR_GET(_pdu)        ((_pdu)->cur)
#define OSPF_PDU_CURSOR_SET(_pdu, _off)  ((_pdu)->cur=_off)
#define OSPF_PDU_CURSOR_INC(_pdu, _off)  ((_pdu)->cur+=_off)
#define OSPF_PDU_OFFSET(_pdu, _off)      ((_pdu)->pdu+_off)

#define OSPF_PDU_BUMP_WRITE_BUFFER(_pdu, _off) \
    (_pdu)->cur+=(_off); \
    (_pdu)->pdu_len+=(_off)

protocol_error_t
ospf_pdu_load(ospf_pdu_s *pdu, uint8_t *buf, uint16_t len);

void
ospf_pdu_update_len(ospf_pdu_s *pdu);

void
ospf_pdu_update_checksum(ospf_pdu_s *pdu);

void
ospf_pdu_update_auth(ospf_pdu_s *pdu, char *key);

bool
ospf_pdu_validate_checksum(ospf_pdu_s *pdu);

bool
ospf_pdu_validate_auth(ospf_pdu_s *pdu, ospf_auth_type auth, char *key);

void
ospf_pdu_init(ospf_pdu_s *pdu, uint8_t pdu_type);

void
ospf_pdu_add_u8(ospf_pdu_s *pdu, uint8_t value);

void
ospf_pdu_add_u16(ospf_pdu_s *pdu, uint16_t value);

void
ospf_pdu_add_u32(ospf_pdu_s *pdu, uint32_t value);

void
ospf_pdu_add_u64(ospf_pdu_s *pdu, uint64_t value);

void
ospf_pdu_add_ipv4(ospf_pdu_s *pdu, uint32_t ipv4);

void
ospf_pdu_add_bytes(ospf_pdu_s *pdu, uint8_t *buf, uint16_t len);

void
ospf_pdu_zero_bytes(ospf_pdu_s *pdu, uint16_t len);

#endif