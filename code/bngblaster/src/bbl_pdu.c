/*
 * BNG Blaster (BBL) - Generic PDU
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

void
bbl_pdu_init(bbl_pdu_s *pdu, uint8_t protocol, uint8_t *buf, uint16_t buf_len)
{
    assert(buf);
    assert(buf_len);

    memset(pdu, 0x0, sizeof(bbl_pdu_s));
    memset(buf, 0x0, buf_len);
    pdu->protocol = protocol;
    pdu->pdu = buf;
    pdu->pdu_buf_len = buf_len;
}

void
bbl_pdu_reset(bbl_pdu_s *pdu)
{
    assert(pdu->pdu);
    assert(pdu->pdu_buf_len);

    pdu->type = 0;
    pdu->auth_type = 0;
    pdu->auth_data_len = 0;
    pdu->auth_data_offset = 0;
    pdu->data_offset = 0;
    pdu->cur = 0;
    pdu->pdu_len = 0;
}

void
bbl_pdu_add_u8(bbl_pdu_s *pdu, uint8_t value)
{
    assert(pdu->pdu);
    assert(pdu->pdu_buf_len);

    *PDU_CURSOR(pdu) = value;
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint8_t));
}

void
bbl_pdu_add_u16(bbl_pdu_s *pdu, uint16_t value)
{
    assert(pdu->pdu);
    assert(pdu->pdu_buf_len);

    *(uint16_t*)PDU_CURSOR(pdu) = htobe16(value);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint16_t));
}

void
bbl_pdu_add_u32(bbl_pdu_s *pdu, uint32_t value)
{
    assert(pdu->pdu);
    assert(pdu->pdu_buf_len);

    *(uint32_t*)PDU_CURSOR(pdu) = htobe32(value);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint32_t));
}

void
bbl_pdu_add_u64(bbl_pdu_s *pdu, uint64_t value)
{
    assert(pdu->pdu);
    assert(pdu->pdu_buf_len);

    *(uint64_t*)PDU_CURSOR(pdu) = htobe64(value);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint64_t));
}

void
bbl_pdu_add_bytes(bbl_pdu_s *pdu, uint8_t *buf, uint16_t len)
{
    assert(pdu->pdu);
    assert(pdu->pdu_buf_len);

    memcpy(PDU_CURSOR(pdu), buf, len);
    PDU_BUMP_WRITE_BUFFER(pdu, len);
}