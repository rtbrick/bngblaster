/*
 * BNG Blaster (BBL) - IS-IS PDU
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

protocol_error_t
isis_pdu_load(isis_pdu_s *pdu, uint8_t *buf, uint16_t len)
{
    uint16_t pdu_len;
    uint8_t  hdr_len;
    uint8_t  system_id_len;
    isis_tlv_s *tlv;

    if(len < ISIS_HDR_LEN_COMMON || len > ISIS_MAX_PDU_LEN) {
        return DECODE_ERROR;
    }
    memset(pdu, 0x0, sizeof(isis_pdu_s));
    memcpy(pdu->pdu, buf, len);
    pdu->pdu_len = len;
    
    /* Decode IS-IS common header (8 byte) */    
    hdr_len = *PDU_OFFSET(pdu, ISIS_OFFSET_HDR_LEN);
    if(hdr_len > len) {
        return DECODE_ERROR;
    }
    pdu->tlv_offset = hdr_len;
    system_id_len = *PDU_OFFSET(pdu, ISIS_OFFSET_HDR_SYSTEM_ID_LEN);
    if(!(system_id_len == 0 || system_id_len == ISIS_SYSTEM_ID_LEN)) {
        /* We do not support system-id lengths != 6 */
        return DECODE_ERROR;
    }
    pdu->pdu_type = *(buf+4) & 0x1f;
    
    /* Decode PDU type specific headers */
    switch (pdu->pdu_type) {
        case ISIS_PDU_P2P_HELLO:
            if(hdr_len != ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_P2P_HELLO) {
                return DECODE_ERROR;
            }
            pdu_len = be16toh(*(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_P2P_HELLO_LEN));
            break;
        case ISIS_PDU_L1_CSNP:
        case ISIS_PDU_L2_CSNP:
            if(hdr_len != ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_CSNP) {
                return DECODE_ERROR;
            }
            pdu_len = be16toh(*(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_CSNP_LEN));
            break;
        case ISIS_PDU_L1_PSNP:
        case ISIS_PDU_L2_PSNP:
            if(hdr_len != ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_PSNP) {
                return DECODE_ERROR;
            }
            pdu_len = be16toh(*(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_PSNP_LEN));
            break;
        case ISIS_PDU_L1_LSP:
        case ISIS_PDU_L2_LSP:
            if(hdr_len != ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_LSP) {
                return DECODE_ERROR;
            }
            pdu_len = be16toh(*(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LEN));
            break;
        default:
            return DECODE_ERROR;
    }
    if(pdu_len > len) {
        return DECODE_ERROR;
    }

    /* Check TLV section and search for authentication TLV */
    PDU_CURSOR_SET(pdu, hdr_len);
    while(PDU_CURSOR_LEN(pdu) >= sizeof(isis_tlv_s)) {
        tlv = (isis_tlv_s*)PDU_CURSOR(pdu);
        PDU_CURSOR_INC(pdu, sizeof(isis_tlv_s));
        if(tlv->len > PDU_CURSOR_LEN(pdu)) {
            return DECODE_ERROR;
        }
        switch (tlv->type) {
            case ISIS_TLV_AUTH:
                if(tlv->len < sizeof(pdu->auth_type)) {
                    return DECODE_ERROR;
                }
                pdu->auth_type = *PDU_CURSOR(pdu);
                pdu->auth_data_len = tlv->len - sizeof(pdu->auth_type);
                pdu->auth_data_offset = PDU_CURSOR_GET(pdu) + sizeof(pdu->auth_type);
                break;                
            default:
                break;
        }
        PDU_CURSOR_INC(pdu, tlv->len);
    }

    /* Reset cursor and return */
    PDU_CURSOR_RST(pdu);
    return PROTOCOL_SUCCESS;
}

isis_tlv_s *
isis_pdu_next_tlv(isis_pdu_s *pdu)
{
    isis_tlv_s *tlv;
    if(pdu->cur < pdu->tlv_offset) {
        pdu->cur = pdu->tlv_offset;
    }
    if(pdu->cur + sizeof(isis_tlv_s) > pdu->pdu_len) {
        return NULL;
    }
    tlv = (isis_tlv_s*)(pdu->pdu+pdu->cur);
    pdu->cur += sizeof(isis_tlv_s) + tlv->len;
    return tlv;
}

isis_tlv_s *
isis_pdu_first_tlv(isis_pdu_s *pdu)
{
    pdu->cur = pdu->tlv_offset;
    return isis_pdu_next_tlv(pdu);
}

void
isis_pdu_update_len(isis_pdu_s *pdu)
{
    switch (pdu->pdu_type) {
        case ISIS_PDU_P2P_HELLO:
            pdu->tlv_offset = ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_P2P_HELLO;
            *PDU_OFFSET(pdu, ISIS_OFFSET_HDR_LEN) = ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_P2P_HELLO;
            *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_P2P_HELLO_LEN) = htobe16(pdu->pdu_len);
            break;
        case ISIS_PDU_L1_CSNP:
        case ISIS_PDU_L2_CSNP:
            pdu->tlv_offset = ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_CSNP;
            *PDU_OFFSET(pdu, ISIS_OFFSET_HDR_LEN) = pdu->tlv_offset;
            *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_CSNP_LEN) = htobe16(pdu->pdu_len);
            break;
        case ISIS_PDU_L1_PSNP:
        case ISIS_PDU_L2_PSNP:
            pdu->tlv_offset = ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_PSNP;
            *PDU_OFFSET(pdu, ISIS_OFFSET_HDR_LEN) = pdu->tlv_offset;
            *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_PSNP_LEN) = htobe16(pdu->pdu_len);
            break;
        case ISIS_PDU_L1_LSP:
        case ISIS_PDU_L2_LSP:
            pdu->tlv_offset = ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_LSP;
            *PDU_OFFSET(pdu, ISIS_OFFSET_HDR_LEN) = pdu->tlv_offset;
            *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LEN) = htobe16(pdu->pdu_len);
            break;
        default:
            break;
    }
}

void
isis_pdu_update_lifetime(isis_pdu_s *pdu, uint16_t lifetime)
{
    switch (pdu->pdu_type) {
        case ISIS_PDU_L1_LSP:
        case ISIS_PDU_L2_LSP:
            *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME) = htobe16(lifetime);
            break;
        default:
            break;
    }
}

void
isis_pdu_update_checksum(isis_pdu_s *pdu)
{
    switch (pdu->pdu_type) {
        case ISIS_PDU_L1_LSP:
        case ISIS_PDU_L2_LSP:
            isis_checksum_fletcher16(
                pdu->pdu+ISIS_OFFSET_LSP_ID, 
                pdu->pdu_len-ISIS_OFFSET_LSP_ID, 
                ISIS_OFFSET_LSP_CHECKSUM-ISIS_OFFSET_LSP_ID);
            break;
        default:
            break;
    }
}

void
isis_pdu_update_auth(isis_pdu_s *pdu, char *key)
{
    uint16_t checksum;
    uint16_t lifetime;

    if(!(pdu && 
         pdu->auth_type > ISIS_AUTH_CLEARTEXT && 
         pdu->auth_data_offset && key)) {
        return;
    }

    if(pdu->pdu_type == ISIS_PDU_L1_LSP || pdu->pdu_type == ISIS_PDU_L2_LSP) {
        /* Set checksum and lifetime to zero. */
        lifetime = *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME);
        *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME) = 0;
        checksum = *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_CHECKSUM);
        *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_CHECKSUM) = 0;
    }

    switch (pdu->auth_type) {
        case ISIS_AUTH_HMAC_MD5:
            if(pdu->auth_data_len != ISIS_MD5_DIGEST_LEN) {
                return;
            }
            HMAC_CTX *hmac = HMAC_CTX_new();
            HMAC_Init_ex(hmac, key, strlen(key), EVP_md5(), NULL);
            HMAC_Update(hmac, pdu->pdu, pdu->pdu_len);
            HMAC_Final(hmac, PDU_OFFSET(pdu, pdu->auth_data_offset), NULL);
            HMAC_CTX_free(hmac);
            break;
        default:
            break;
    }

    if(pdu->pdu_type == ISIS_PDU_L1_LSP || pdu->pdu_type == ISIS_PDU_L2_LSP) {
        /* Restore checksum and lifetime. */
        *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME) = lifetime;
        *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_CHECKSUM) = checksum;
    }
}

bool
isis_pdu_validate_checksum(isis_pdu_s *pdu)
{
    uint16_t checksum;
    uint16_t checksum_orig;

    switch (pdu->pdu_type) {
        case ISIS_PDU_L1_LSP:
        case ISIS_PDU_L2_LSP:
            checksum_orig = *(uint16_t*)PDU_OFFSET(pdu, ISIS_OFFSET_LSP_CHECKSUM);
            checksum = isis_checksum_fletcher16(
                pdu->pdu+ISIS_OFFSET_LSP_ID, 
                pdu->pdu_len-ISIS_OFFSET_LSP_ID, 
                ISIS_OFFSET_LSP_CHECKSUM-ISIS_OFFSET_LSP_ID);
            break;
        default:
            return true;
    }
    if(checksum == checksum_orig) {
        return true;
    }
    return false;
}

bool
isis_pdu_validate_auth(isis_pdu_s *pdu, isis_auth_type auth, char *key)
{
    uint8_t auth_data[ISIS_MD5_DIGEST_LEN];

    if(!(pdu && pdu->auth_type == auth)) {
        return false;
    }

    if(auth == ISIS_AUTH_NONE) {
        return true;
    }

    if(!(pdu->auth_data_offset && pdu->auth_data_len && key)) {
        return false;
    }

    switch (pdu->auth_type) {
        case ISIS_AUTH_CLEARTEXT:
            if(strncmp((char*)PDU_OFFSET(pdu, pdu->auth_data_offset), key, pdu->auth_data_len) == 0) {
                return true;
            }
            break;
        case ISIS_AUTH_HMAC_MD5:
            if(pdu->auth_data_len != ISIS_MD5_DIGEST_LEN) {
                return false;
            }
            memcpy(auth_data, PDU_OFFSET(pdu, pdu->auth_data_offset), ISIS_MD5_DIGEST_LEN);
            memset(PDU_OFFSET(pdu, pdu->auth_data_offset), 0x0, ISIS_MD5_DIGEST_LEN);
            isis_pdu_update_auth(pdu, key);
            if(memcmp(PDU_OFFSET(pdu, pdu->auth_data_offset), auth_data, ISIS_MD5_DIGEST_LEN) == 0) {
                return true;
            } else {
                /* Restore wrong key. */
                memcpy(PDU_OFFSET(pdu, pdu->auth_data_offset), auth_data, ISIS_MD5_DIGEST_LEN);
            }
            break;
        default:
            break;
    }
    return false;
}

void
isis_pdu_init(isis_pdu_s *pdu, uint8_t pdu_type)
{
    memset(pdu, 0x0, sizeof(isis_pdu_s));
    pdu->pdu_type = pdu_type;
    *pdu->pdu = ISIS_PROTOCOL_IDENTIFIER;
    *(pdu->pdu+2) = 0x01;
    *(pdu->pdu+4) = pdu_type;
    *(pdu->pdu+5) = 0x01;
    pdu->cur = ISIS_HDR_LEN_COMMON;
    pdu->pdu_len = ISIS_HDR_LEN_COMMON;
}

void
isis_pdu_add_u8(isis_pdu_s *pdu, uint8_t value)
{
    *PDU_CURSOR(pdu) = value;
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint8_t));
}

void
isis_pdu_add_u16(isis_pdu_s *pdu, uint16_t value)
{
    *(uint16_t*)PDU_CURSOR(pdu) = htobe16(value);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint16_t));
}

void
isis_pdu_add_u32(isis_pdu_s *pdu, uint32_t value)
{
    *(uint32_t*)PDU_CURSOR(pdu) = htobe32(value);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint32_t));
}

void
isis_pdu_add_u64(isis_pdu_s *pdu, uint64_t value)
{
    *(uint64_t*)PDU_CURSOR(pdu) = htobe64(value);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint64_t));
}

void
isis_pdu_add_bytes(isis_pdu_s *pdu, uint8_t *buf, uint16_t len)
{
    memcpy(PDU_CURSOR(pdu), buf, len);
    PDU_BUMP_WRITE_BUFFER(pdu, len);
}

void
isis_pdu_add_tlv(isis_pdu_s *pdu, isis_tlv_s *tlv)
{
    uint16_t len = sizeof(isis_tlv_s) + tlv->len;
    isis_pdu_add_bytes(pdu, (uint8_t*)tlv, len);
}

void
isis_pdu_add_tlv_area(isis_pdu_s *pdu, isis_area_s *area, uint8_t area_count)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    uint8_t *tlv_cur = tlv->value;
    tlv->type = ISIS_TLV_AREA_ADDRESSES;
    tlv->len = 0;
    for(int i=0; i<area_count; i++) {
        *tlv_cur = area[i].len; 
        tlv_cur++; 
        tlv->len++;
        memcpy(tlv_cur, area[i].value, area[i].len);
        tlv_cur += area[i].len;
        tlv->len += area[i].len;
    }
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_protocols(isis_pdu_s *pdu, bool ipv4, bool ipv6)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    uint8_t *tlv_cur = tlv->value;
    tlv->type = ISIS_TLV_PROTOCOLS;
    tlv->len = 0;
    if(ipv4) {
        *tlv_cur = ISIS_PROTOCOL_IPV4;
        tlv_cur++; tlv->len++;
    }
    if(ipv6) {
        *tlv_cur = ISIS_PROTOCOL_IPV6;
        tlv_cur++; tlv->len++;
    }
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_ipv4_int_address(isis_pdu_s *pdu, ipv4addr_t addr)
{
    isis_tlv_s *tlv =  (isis_tlv_s *)PDU_CURSOR(pdu);
    tlv->type = ISIS_TLV_IPV4_INT_ADDRESS;
    tlv->len = sizeof(ipv4addr_t);
    *(ipv4addr_t*)tlv->value = addr;
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_te_router_id(isis_pdu_s *pdu, ipv4addr_t addr) {
    isis_tlv_s *tlv =  (isis_tlv_s *)PDU_CURSOR(pdu);
    tlv->type = ISIS_TLV_TE_ROUTER_ID;
    tlv->len = sizeof(ipv4addr_t);
    *(ipv4addr_t*)tlv->value = addr;
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_hostname(isis_pdu_s *pdu, char *hostname)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    tlv->type = ISIS_TLV_HOSTNAME;
    tlv->len = strnlen(hostname, UINT8_MAX);
    memcpy(tlv->value, hostname, tlv->len);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_ipv6_int_address(isis_pdu_s *pdu, ipv6addr_t *addr)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    tlv->type = ISIS_TLV_IPV6_INT_ADDRESS;
    tlv->len = sizeof(ipv6addr_t);
    memcpy(tlv->value, addr, sizeof(ipv6addr_t));
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_p2p_adjacency_state(isis_pdu_s *pdu, uint8_t state) 
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    tlv->type = ISIS_TLV_P2P_ADJACENCY_STATE;
    tlv->len = sizeof(state);
    *tlv->value = state;
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_ext_ipv4_reachability(isis_pdu_s *pdu, ipv4_prefix *prefix, uint32_t metric, isis_sub_tlv_t *stlv)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    uint8_t *tlv_cur = tlv->value;
    uint8_t *stlv_len = NULL;
    uint8_t prefix_bytes = BITS_TO_BYTES(prefix->len);
    tlv->type = ISIS_TLV_EXT_IPV4_REACHABILITY;
    tlv->len = sizeof(metric) + sizeof(prefix->len) + prefix_bytes;
    *(uint32_t*)tlv_cur = htobe32(metric);
    tlv_cur += sizeof(metric);
    if(stlv) {
        *tlv_cur++ = prefix->len | 0x40; 
    } else {
        *tlv_cur++ = prefix->len;
    }
    memcpy(tlv_cur, &prefix->address, prefix_bytes);
    if(stlv) {
        tlv_cur += prefix_bytes;
        stlv_len = tlv_cur++;
        *stlv_len = 0;
        while(stlv) {
            *stlv_len += 2 + stlv->len;
            *tlv_cur++ = stlv->type;
            *tlv_cur++ = stlv->len;
            memcpy(tlv_cur, stlv->value, stlv->len);
            tlv_cur += stlv->len;
            stlv = stlv->next;


        }
        tlv->len += 1 + *stlv_len;
    }
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_ipv6_reachability(isis_pdu_s *pdu, ipv6_prefix *prefix, uint32_t metric)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    uint8_t *tlv_cur = tlv->value;
    uint8_t prefix_bytes = BITS_TO_BYTES(prefix->len);
    tlv->type = ISIS_TLV_IPV6_REACHABILITY;
    tlv->len = sizeof(metric) + sizeof(uint8_t) + sizeof(prefix->len) + prefix_bytes;
    *(uint32_t*)tlv_cur = htobe32(metric);
    tlv_cur += sizeof(metric);
    *tlv_cur++ = 0;
    *tlv_cur++ = prefix->len;
    memcpy(tlv_cur, prefix->address, prefix_bytes);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_auth(isis_pdu_s *pdu, isis_auth_type auth, char *key)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    uint8_t *tlv_cur = tlv->value;
    int slen;
    tlv->type = ISIS_TLV_AUTH;
    *tlv_cur = auth;
    tlv_cur++;
    switch (auth) {
        case ISIS_AUTH_CLEARTEXT:
            slen = strnlen(key, UINT8_MAX-1);
            memcpy(tlv_cur, key, slen);
            tlv->len = sizeof(isis_auth_type) + slen;
            pdu->auth_data_len = slen;
            break;
        case ISIS_AUTH_HMAC_MD5:
            memset(tlv_cur, 0x0, ISIS_MD5_DIGEST_LEN);
            tlv->len = sizeof(isis_auth_type) + ISIS_MD5_DIGEST_LEN;
            pdu->auth_data_len = ISIS_MD5_DIGEST_LEN;
            break;
        default:
            return;
    }
    pdu->auth_type = auth;
    pdu->auth_data_offset = pdu->cur + sizeof(isis_tlv_s) + sizeof(isis_auth_type);
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_ext_reachability(isis_pdu_s *pdu, uint8_t *system_id, uint32_t metric)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    uint8_t *tlv_cur = tlv->value;
    tlv->type = ISIS_TLV_EXT_REACHABILITY;
    tlv->len = 11;
    memcpy(tlv_cur, system_id, ISIS_SYSTEM_ID_LEN);
    tlv_cur += ISIS_SYSTEM_ID_LEN; 
    *(uint32_t*)tlv_cur = htobe32(metric);
    tlv_cur += sizeof(metric);
    *tlv_cur = 0; 
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_add_tlv_router_cap(isis_pdu_s *pdu, ipv4addr_t router_id, 
                            bool ipv4, bool ipv6, 
                            uint32_t sr_base, uint32_t sr_range)
{
    isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
    uint8_t *tlv_cur = tlv->value;
    tlv->type = ISIS_TLV_ROUTER_CAPABILITY;
    tlv->len = 16;
    *(ipv4addr_t*)tlv_cur = router_id;
    tlv_cur+=sizeof(ipv4addr_t);
    *tlv_cur++ = 0;
    *tlv_cur++ = 2;
    *tlv_cur++ = 9;
    *(uint32_t*)tlv_cur = htobe32(sr_range);
    *tlv_cur = 0;
    if(ipv4) *tlv_cur |= 128;
    if(ipv6) *tlv_cur |= 64;
    tlv_cur+=sizeof(uint32_t);
    *tlv_cur++ = 1;
    *(uint32_t*)tlv_cur = htobe32(sr_base);
    *tlv_cur = 3;
    PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
}

void
isis_pdu_padding(isis_pdu_s *pdu)
{
    uint16_t remaining = ISIS_MAX_PDU_LEN - pdu->pdu_len;
    memset(PDU_CURSOR(pdu), 0x0, remaining);
    while(remaining >= sizeof(isis_tlv_s)) {
        isis_tlv_s *tlv = (isis_tlv_s *)PDU_CURSOR(pdu);
        remaining-=sizeof(isis_tlv_s);
        tlv->type = ISIS_TLV_PADDING;
        if(remaining > UINT8_MAX) {
            tlv->len = UINT8_MAX;
            remaining -= UINT8_MAX;
        } else {
            tlv->len = remaining;
            remaining = 0;
        }
        PDU_BUMP_WRITE_BUFFER(pdu, sizeof(isis_tlv_s)+tlv->len);
    }
}