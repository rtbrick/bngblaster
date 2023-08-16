/*
 * BNG Blaster (BBL) - OSPF PDU
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

static protocol_error_t
ospf_pdu_load_v2(ospf_pdu_s *pdu)
{
    pdu->auth_type = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_AUTH_TYPE));
    pdu->auth_data_len = OSPFV2_AUTH_DATA_LEN;
    pdu->auth_data_offset = OSPFV2_OFFSET_AUTH_DATA;
    return PROTOCOL_SUCCESS;
}

static protocol_error_t
ospf_pdu_load_v3(ospf_pdu_s *pdu)
{
    UNUSED(pdu);
    return PROTOCOL_SUCCESS;
}

protocol_error_t
ospf_pdu_load(ospf_pdu_s *pdu, uint8_t *buf, uint16_t len)
{
    protocol_error_t result;
    uint16_t pdu_len;

    if(len < OSPF_PDU_LEN_MIN) {
        return DECODE_ERROR;
    }
    pdu->pdu = buf;
    pdu->pdu_len = len;
    pdu->pdu_buf_len = len;

    /* Decode OSPF common header (12 byte) which is equal 
     * for OSPF version 2 (IPv4) and 3 (IPv6). 
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Version #   |     Type      |         Packet length         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                          Router ID                            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                           Area ID                             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-*/
    pdu->pdu_version = *OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_VERSION);
    pdu->pdu_type = *OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_TYPE);
    pdu_len = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_PACKET_LEN));
    if(pdu_len > len) {
        return DECODE_ERROR;
    }
    pdu->router_id = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_ROUTER_ID);
    pdu->area_id = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_AREA_ID);
    pdu->checksum = *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM);

    switch(pdu->pdu_version) {
        case OSPF_VERSION_2:
            result = ospf_pdu_load_v2(pdu);
            break;
        case OSPF_VERSION_3: 
            result = ospf_pdu_load_v3(pdu);
            break;
        default: 
            result = DECODE_ERROR;
            break;
    }

    /* Reset cursor and return */
    OSPF_PDU_CURSOR_RST(pdu);
    return result;
}

void
ospf_pdu_update_len(ospf_pdu_s *pdu)
{
    UNUSED(pdu);
}

void
ospf_pdu_update_lifetime(ospf_pdu_s *pdu, uint16_t lifetime)
{
    UNUSED(pdu);
    UNUSED(lifetime);
}

void
ospf_pdu_update_checksum(ospf_pdu_s *pdu)
{
    UNUSED(pdu);
}

void
ospf_pdu_update_auth(ospf_pdu_s *pdu, char *key)
{
    UNUSED(pdu);
    UNUSED(key);
}

bool
ospf_pdu_validate_checksum(ospf_pdu_s *pdu)
{
    UNUSED(pdu);
    return false;
}

bool
ospf_pdu_validate_auth(ospf_pdu_s *pdu, ospf_auth_type auth, char *key)
{
    UNUSED(pdu);
    UNUSED(auth);
    UNUSED(key);
    return false;
}

void
ospf_pdu_init(ospf_pdu_s *pdu, uint8_t pdu_type)
{
    memset(pdu, 0x0, sizeof(ospf_pdu_s));
    pdu->pdu_type = pdu_type;
}

void
ospf_pdu_add_u8(ospf_pdu_s *pdu, uint8_t value)
{
    *OSPF_PDU_CURSOR(pdu) = value;
    OSPF_PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint8_t));
}

void
ospf_pdu_add_u16(ospf_pdu_s *pdu, uint16_t value)
{
    *(uint16_t*)OSPF_PDU_CURSOR(pdu) = htobe16(value);
    OSPF_PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint16_t));
}

void
ospf_pdu_add_u32(ospf_pdu_s *pdu, uint32_t value)
{
    *(uint32_t*)OSPF_PDU_CURSOR(pdu) = htobe32(value);
    OSPF_PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint32_t));
}

void
ospf_pdu_add_u64(ospf_pdu_s *pdu, uint64_t value)
{
    *(uint64_t*)OSPF_PDU_CURSOR(pdu) = htobe64(value);
    OSPF_PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint64_t));
}

void
ospf_pdu_add_bytes(ospf_pdu_s *pdu, uint8_t *buf, uint16_t len)
{
    memcpy(OSPF_PDU_CURSOR(pdu), buf, len);
    OSPF_PDU_BUMP_WRITE_BUFFER(pdu, len);
}