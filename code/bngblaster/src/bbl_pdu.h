/*
 * BNG Blaster (BBL) - Generic PDU
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_PDU_H__
#define __BBL_PDU_H__

#define PDU_CURSOR(_pdu)            ((_pdu)->pdu+(_pdu)->cur)
#define PDU_CURSOR_LEN(_pdu)        (uint16_t)((_pdu)->pdu_len-(_pdu)->cur)
#define PDU_CURSOR_RST(_pdu)        ((_pdu)->cur=0)
#define PDU_CURSOR_GET(_pdu)        ((_pdu)->cur)
#define PDU_CURSOR_SET(_pdu, _off)  ((_pdu)->cur=_off)
#define PDU_CURSOR_INC(_pdu, _off)  ((_pdu)->cur+=_off)
#define PDU_OFFSET(_pdu, _off)      ((_pdu)->pdu+_off)
#define PDU_REMAINING(_pdu, _max)   (_max-(_pdu)->cur)

#define PDU_BUMP_WRITE_BUFFER(_pdu, _off) \
    (_pdu)->cur+=(_off); \
    (_pdu)->pdu_len+=(_off)

typedef enum bbl_pdu_protocol_ {
    BBL_PDU_GENERIC = 0,
    BBL_PDU_ISIS    = 1,
    BBL_PDU_OSPF2   = 2,
    BBL_PDU_OSPF3   = 3,
} bbl_pdu_protocol;

/*
 * Generic PDU context
 */
typedef struct bbl_pdu_ {
    uint8_t  protocol;
    uint8_t  type;

    uint8_t  auth_type;
    uint8_t  auth_data_len;
    uint16_t auth_data_offset;

    uint16_t data_offset;

    uint16_t cur; /* current position */

    uint8_t *pdu;
    uint16_t pdu_len;
    uint16_t pdu_buf_len;
} bbl_pdu_s;

void
bbl_pdu_init(bbl_pdu_s *pdu, uint8_t protocol, uint8_t *buf, uint16_t buf_len);

void
bbl_pdu_reset(bbl_pdu_s *pdu);

void
bbl_pdu_add_u8(bbl_pdu_s *pdu, uint8_t value);

void
bbl_pdu_add_u16(bbl_pdu_s *pdu, uint16_t value);

void
bbl_pdu_add_u32(bbl_pdu_s *pdu, uint32_t value);

void
bbl_pdu_add_u64(bbl_pdu_s *pdu, uint64_t value);

void
bbl_pdu_add_bytes(bbl_pdu_s *pdu, uint8_t *buf, uint16_t len);

#endif