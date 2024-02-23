/*
 * BNG Blaster (BBL) - OSPF PDU
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>

uint32_t g_crypt_seq = 0;

static protocol_error_t
ospf_pdu_load_v2(ospf_pdu_s *pdu)
{
    pdu->auth_type = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_AUTH_TYPE));
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
    pdu->packet_len = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_PACKET_LEN));
    if(pdu->packet_len > len) {
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
    pdu->packet_len = pdu->cur;
    *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_PACKET_LEN) = htobe16(pdu->packet_len);
}

static uint16_t
ospf_pdu_checksum_v2(ospf_pdu_s *pdu)
{
    uint16_t checksum = 0;
    uint16_t checksum_orig = 0;

    uint64_t auth_data_orig;

    if(pdu->auth_type == OSPF_AUTH_MD5) {
        return 0;
    }

    /* reset checkum/auth */
    checksum_orig = *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM);
    *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM) = 0;
    auth_data_orig = *(uint64_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_AUTH_DATA);
    *(uint64_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_AUTH_DATA) = 0;

    /* calculate checksum */
    checksum = bbl_checksum(pdu->pdu, pdu->packet_len);

    /* restore checksum/auth*/
    *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM) = checksum_orig;
    *(uint64_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_AUTH_DATA) = auth_data_orig;

    return checksum;
}

static uint16_t
ospf_pdu_checksum_v3(ospf_pdu_s *pdu)
{
    uint16_t checksum = 0;
    uint16_t checksum_orig = 0;

    if(!(pdu->source && pdu->destination)) {
        return 0;
    }

    /* reset checkum */
    checksum_orig = *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM);
    *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM) = 0;

    /* calculate checksum */
    checksum = bbl_ipv6_ospf_checksum(pdu->source, pdu->destination, pdu->pdu, pdu->packet_len);

    /* restore checksum/auth*/
    *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM) = checksum_orig;

    return checksum;
}

void
ospf_pdu_update_checksum(ospf_pdu_s *pdu)
{
    if(pdu->pdu_version == OSPF_VERSION_2) {
        *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM) = ospf_pdu_checksum_v2(pdu);
    } else {
        *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM) = ospf_pdu_checksum_v3(pdu);
    }
}

bool
ospf_pdu_validate_checksum(ospf_pdu_s *pdu)
{
    uint16_t checksum = 0;
    uint16_t checksum_orig = 0;

    if(pdu->pdu_version == OSPF_VERSION_2) {
        checksum = ospf_pdu_checksum_v2(pdu);
    } else {
        checksum = ospf_pdu_checksum_v3(pdu);
    }
    checksum_orig = *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM);

    if(checksum == checksum_orig) {
        return true;
    }
    return false;
}

static bool
ospf_pdu_update_auth_v2(ospf_pdu_s *pdu, ospf_auth_type auth, char *key)
{
    uint8_t *auth_data = OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_AUTH_DATA);
    ospf_auth_header_s *auth_hdr = (ospf_auth_header_s*)auth_data;

    EVP_MD_CTX *ctx;
    unsigned int md5_size = OSPF_MD5_DIGEST_LEN;
    uint8_t padded_key[OSPF_MD5_DIGEST_LEN+1] = {0};

    assert(pdu->pdu_len == pdu->packet_len);

    *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_AUTH_TYPE) = htobe16(auth);
    switch(auth) {
        case OSPF_AUTH_CLEARTEXT:
            memset(auth_data, 0x0, OSPFV2_AUTH_DATA_LEN);
            if(key) {
                strncpy((char*)auth_data, key, OSPFV2_AUTH_DATA_LEN);
            }
            break;
        case OSPF_AUTH_MD5:
            if(pdu->pdu_len + OSPF_MD5_DIGEST_LEN > pdu->pdu_buf_len) {
                return false;
            }
            *(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPF_OFFSET_CHECKSUM) = 0;

            auth_hdr->reserved = 0;
            auth_hdr->key_id = 1;
            auth_hdr->auth_data_len = OSPF_MD5_DIGEST_LEN;
            auth_hdr->crypt_seq = htobe32(++g_crypt_seq);

            if(key) {
                strncpy((char*)padded_key, key, OSPF_MD5_DIGEST_LEN);
            }
            ctx = EVP_MD_CTX_new();
            EVP_DigestInit(ctx, EVP_md5());
            EVP_DigestUpdate(ctx, pdu->pdu, pdu->packet_len);
            EVP_DigestUpdate(ctx, padded_key, OSPF_MD5_DIGEST_LEN);
            EVP_DigestFinal(ctx, OSPF_PDU_OFFSET(pdu, pdu->packet_len), &md5_size);
            EVP_MD_CTX_free(ctx);

            pdu->pdu_len += OSPF_MD5_DIGEST_LEN;
            break;
        default:
            break;
    }
    return true;
}

static void
ospf_pdu_update_auth_v3(ospf_pdu_s *pdu, ospf_auth_type auth, char *key)
{
    UNUSED(pdu);
    UNUSED(auth);
    UNUSED(key);
}

void
ospf_pdu_update_auth(ospf_pdu_s *pdu, ospf_auth_type auth, char *key)
{
    pdu->auth_type = auth;
    if(pdu->pdu_version == OSPF_VERSION_2) {
        ospf_pdu_update_auth_v2(pdu, auth, key);
    } else {
        ospf_pdu_update_auth_v3(pdu, auth, key);
    }
}

bool
ospf_pdu_validate_auth_v2(ospf_pdu_s *pdu, ospf_auth_type auth, char *key, ospf_neighbor_s *ospf_neighbor)
{
    uint8_t *auth_data = OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_AUTH_DATA);
    ospf_auth_header_s *auth_hdr = (ospf_auth_header_s*)auth_data;

    EVP_MD_CTX *ctx;
    unsigned int md5_size = OSPF_MD5_DIGEST_LEN;
    uint8_t md5[OSPF_MD5_DIGEST_LEN];
    uint8_t padded_key[OSPF_MD5_DIGEST_LEN+1] = {0};

    uint32_t crypt_seq;
    
    if(pdu->auth_type != auth) {
        return false;
    }
    switch(auth) {
        case OSPF_AUTH_NONE:
            return true;
        case OSPF_AUTH_CLEARTEXT:
            if(key && strncmp((const char*)auth_data, key, OSPFV2_AUTH_DATA_LEN) == 0) {
                return true;
            }
            break;
        case OSPF_AUTH_MD5:
            if(pdu->packet_len + OSPF_MD5_DIGEST_LEN > pdu->pdu_len) {
                return false;
            }
            if(key) {
                strncpy((char*)padded_key, key, OSPF_MD5_DIGEST_LEN);
            }
            ctx = EVP_MD_CTX_new();
            EVP_DigestInit(ctx, EVP_md5());
            EVP_DigestUpdate(ctx, pdu->pdu, pdu->packet_len);
            EVP_DigestUpdate(ctx, padded_key, OSPF_MD5_DIGEST_LEN);
            EVP_DigestFinal(ctx, md5, &md5_size);
            EVP_MD_CTX_free(ctx);
            if(memcmp(OSPF_PDU_OFFSET(pdu, pdu->packet_len), md5, OSPF_MD5_DIGEST_LEN) != 0) {
                return false;
            }
            if(ospf_neighbor) {
                crypt_seq = be32toh(auth_hdr->crypt_seq);
                if(crypt_seq < ospf_neighbor->rx.crypt_seq) {
                    return false;
                }
                ospf_neighbor->rx.crypt_seq = crypt_seq;
            }
            return true;
        default:
            LOG_NOARG(OSPF, "DEBUG: DEFAULT...\n");
            break;
    }
    LOG_NOARG(OSPF, "DEBUG: MISC ERROR...\n");
    return false;
}

bool
ospf_pdu_validate_auth_v3(ospf_pdu_s *pdu, ospf_auth_type auth, char *key, ospf_neighbor_s *ospf_neighbor)
{
    UNUSED(pdu);
    UNUSED(auth);
    UNUSED(key);
    UNUSED(ospf_neighbor);
    return false;
}

bool
ospf_pdu_validate_auth(ospf_pdu_s *pdu, ospf_auth_type auth, char *key, ospf_neighbor_s *ospf_neighbor)
{
    if(pdu->pdu_version == OSPF_VERSION_2) {
        return ospf_pdu_validate_auth_v2(pdu, auth, key, ospf_neighbor);
    } else {
        return ospf_pdu_validate_auth_v3(pdu, auth, key, ospf_neighbor);
    }
}

void
ospf_pdu_init(ospf_pdu_s *pdu, uint8_t pdu_type, uint8_t pdu_version)
{
    static uint8_t pdu_buf[OSPF_PDU_LEN_MAX] = {0};

    memset(pdu, 0x0, sizeof(ospf_pdu_s));
    pdu->pdu_type = pdu_type;
    pdu->pdu_version = pdu_version;
    pdu->pdu = pdu_buf;
    pdu->pdu_buf_len = OSPF_PDU_LEN_MAX;
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
ospf_pdu_add_ipv4(ospf_pdu_s *pdu, uint32_t ipv4)
{
    *(uint32_t*)OSPF_PDU_CURSOR(pdu) = ipv4;
    OSPF_PDU_BUMP_WRITE_BUFFER(pdu, sizeof(uint32_t));
}

void
ospf_pdu_add_bytes(ospf_pdu_s *pdu, uint8_t *buf, uint16_t len)
{
    memcpy(OSPF_PDU_CURSOR(pdu), buf, len);
    OSPF_PDU_BUMP_WRITE_BUFFER(pdu, len);
}

void
ospf_pdu_zero_bytes(ospf_pdu_s *pdu, uint16_t len)
{
    memset(OSPF_PDU_CURSOR(pdu), 0x0, len);
    OSPF_PDU_BUMP_WRITE_BUFFER(pdu, len);
}

static protocol_error_t
ospf_pdu_tx_fragmented(ospf_pdu_s *pdu,
                       bbl_ethernet_header_s *eth,
                       bbl_ipv4_s *ipv4,
                       bbl_ospf_s *ospf,
                       bbl_network_interface_s *interface)
{
    uint16_t pdu_send = 0;
    static uint16_t id = 1000;

    id++;
    if(id == 0 || id == UINT16_MAX) id = 1;
    ipv4->id = id;

    LOG(PACKET, "OSPFv2 TX %s fragmented on interface %s\n",
        ospf_pdu_type_string(ospf->type), interface->name);

    while(pdu_send < pdu->pdu_len) {
        ospf->pdu = pdu->pdu + pdu_send;
        ospf->pdu_len = pdu->pdu_len - pdu_send;
        ipv4->offset = pdu_send >> 3;
        if(ospf->pdu_len + 20 > interface->mtu) {
            ospf->pdu_len = interface->mtu - 20;
            ipv4->offset |= IPV4_MF;
        } else {
            ipv4->offset &= ~IPV4_MF;
        }
        pdu_send += ospf->pdu_len;

        if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
            LOG(PACKET, "OSPFv2 TX %s fragment on interface %s\n",
                ospf_pdu_type_string(ospf->type), interface->name);
        } else {
            return SEND_ERROR;
        }
    }
    return PROTOCOL_SUCCESS;
}

/**
 * ospf_pdu_tx
 * 
 * This function serves as a universal mechanism for sending 
 * OSPFv2 and v3 Protocol Data Units (PDU) via a specified 
 * OSPF interface. In the presence of an optional OSPF neighbor, 
 * the PDU is transmitted as a direct unicast message.
 * 
 * @param pdu OSPF PDU
 * @param ospf_interface OSPF interface 
 * @param ospf_neighbor OSPF neighbor (optional)
 * @return protocol_error_t (PROTOCOL_SUCCESS or SEND_ERROR)
 */
protocol_error_t
ospf_pdu_tx(ospf_pdu_s *pdu,
            ospf_interface_s *ospf_interface, 
            ospf_neighbor_s *ospf_neighbor)
{
    bbl_network_interface_s *interface = ospf_interface->interface;

    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_ospf_s ospf = {0};
    uint8_t mac[ETH_ADDR_LEN];

    ospf.version = pdu->pdu_version;
    ospf.type = pdu->pdu_type;

    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    if(ospf_interface->version == OSPF_VERSION_2) {
        eth.type = ETH_TYPE_IPV4;
        eth.next = &ipv4;
        if(pdu->pdu_type == OSPF_PDU_HELLO) {
            eth.dst = (uint8_t*)all_ospf_routers_mac;
            ipv4.dst = IPV4_MC_ALL_OSPF_ROUTERS;
        } else if(ospf_interface->state != OSPF_IFSTATE_P2P && ospf_neighbor) {
            eth.dst = ospf_neighbor->mac;
            ipv4.dst = ospf_neighbor->ipv4;
        } else if(ospf_interface->state == OSPF_IFSTATE_DR_OTHER) {
            eth.dst = (uint8_t*)all_dr_routers_mac;
            ipv4.dst = IPV4_MC_ALL_DR_ROUTERS;
        } else {
            eth.dst = (uint8_t*)all_ospf_routers_mac;
            ipv4.dst = IPV4_MC_ALL_OSPF_ROUTERS;
        }
        ipv4.src = interface->ip.address;
        ipv4.ttl = 1;
        ipv4.protocol = PROTOCOL_IPV4_OSPF;
        ipv4.next = &ospf;

        if((pdu->pdu_len + 20) > interface->mtu) {
            return ospf_pdu_tx_fragmented(pdu, &eth, &ipv4, &ospf, interface);
        }
    } else {
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
        if(pdu->pdu_type == OSPF_PDU_HELLO) {
            ipv6_multicast_mac(ipv6_multicast_ospf_routers, mac);
            eth.dst = (uint8_t*)mac;
            ipv6.dst = (void*)ipv6_multicast_ospf_routers;
        } else if(ospf_interface->state != OSPF_IFSTATE_P2P && ospf_neighbor) {
            eth.dst = ospf_neighbor->mac;
            ipv6.dst = ospf_neighbor->ipv6;
        } else if(ospf_interface->state == OSPF_IFSTATE_DR_OTHER) {
            ipv6_multicast_mac(ipv6_multicast_dr_routers, mac);
            eth.dst = (uint8_t*)mac;
            ipv6.dst = (void*)ipv6_multicast_dr_routers;
        } else {
            ipv6_multicast_mac(ipv6_multicast_ospf_routers, mac);
            eth.dst = (uint8_t*)mac;
            ipv6.dst = (void*)ipv6_multicast_ospf_routers;
        }
        ipv6.src = interface->ip6_ll;
        ipv6.ttl = 1;
        ipv6.protocol = IPV6_NEXT_HEADER_OSPF;
        ipv6.next = &ospf;

        pdu->source = ipv6.src;
        pdu->destination = ipv6.dst;
        ospf_pdu_update_checksum(pdu);
    }

    ospf.pdu = pdu->pdu;
    ospf.pdu_len = pdu->pdu_len;
    if(bbl_txq_to_buffer(interface->txq, &eth) == BBL_TXQ_OK) {
        LOG(PACKET, "OSPFv%u TX %s on interface %s\n",
            ospf_interface->version,
            ospf_pdu_type_string(ospf.type), interface->name);
        return PROTOCOL_SUCCESS;
    } else {
        return SEND_ERROR;
    }
}