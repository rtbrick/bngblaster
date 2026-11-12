/*
 * BNG Blaster (BBL) - BFD Packet Encoding and Authentication
 *
 * This file has no dependencies to the BNG Blaster
 * context and is therefore also used in unit tests.
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "../bbl_def.h"
#include "../bbl_protocols.h"
#include "bfd_def.h"
#include "bfd_packet.h"

/**
 * bfd_auth_len
 *
 * @param auth_type authentication type
 * @param key_len key length (simple password)
 * @return length of the authentication section
 */
uint8_t
bfd_auth_len(uint8_t auth_type, uint8_t key_len)
{
    switch(auth_type) {
        case BFD_AUTH_SIMPLE:
            return BFD_AUTH_HDR_LEN + key_len;
        case BFD_AUTH_KEYED_MD5:
        case BFD_AUTH_METICULOUS_KEYED_MD5:
            return BFD_AUTH_MD5_LEN;
        case BFD_AUTH_KEYED_SHA1:
        case BFD_AUTH_METICULOUS_KEYED_SHA1:
            return BFD_AUTH_SHA1_LEN;
        default:
            return 0;
    }
}

bool
bfd_auth_meticulous(uint8_t auth_type)
{
    return auth_type == BFD_AUTH_METICULOUS_KEYED_MD5 ||
           auth_type == BFD_AUTH_METICULOUS_KEYED_SHA1;
}

static const EVP_MD *
bfd_auth_md(uint8_t auth_type, uint8_t *digest_len)
{
    switch(auth_type) {
        case BFD_AUTH_KEYED_MD5:
        case BFD_AUTH_METICULOUS_KEYED_MD5:
            *digest_len = BFD_MD5_DIGEST_LEN;
            return EVP_md5();
        case BFD_AUTH_KEYED_SHA1:
        case BFD_AUTH_METICULOUS_KEYED_SHA1:
            *digest_len = BFD_SHA1_DIGEST_LEN;
            return EVP_sha1();
        default:
            *digest_len = 0;
            return NULL;
    }
}

/* Digest over the packet with the key (zero padded) in place of
 * the digest field (RFC 5880 sections 6.7.3 and 6.7.4). */
static bool
bfd_auth_digest(uint8_t *pdu, uint16_t len, uint8_t auth_type,
                const uint8_t *key, uint8_t key_len, uint8_t *digest)
{
    const EVP_MD *md;
    uint8_t digest_len;
    uint8_t *field;
    unsigned int md_len = 0;

    md = bfd_auth_md(auth_type, &digest_len);
    if(!md || len < BFD_HDR_LEN + BFD_AUTH_HDR_LEN + 5 + digest_len) {
        return false;
    }
    field = pdu + BFD_HDR_LEN + BFD_AUTH_HDR_LEN + 5;
    memset(field, 0x0, digest_len);
    memcpy(field, key, key_len < digest_len ? key_len : digest_len);
    if(!EVP_Digest(pdu, len, digest, &md_len, md, NULL)) {
        return false;
    }
    return md_len == digest_len;
}

/**
 * bfd_packet_encode
 *
 * Encode BFD control packet including authentication section.
 *
 * @param buf buffer with at least BFD_MAX_LEN bytes
 * @param bfd header fields, auth_type and auth_key_id
 * @param auth_seq authentication sequence number
 * @param key authentication key (password)
 * @param key_len authentication key length
 * @return packet length
 */
uint16_t
bfd_packet_encode(uint8_t *buf, bbl_bfd_s *bfd, uint32_t auth_seq,
                  const uint8_t *key, uint8_t key_len)
{
    uint8_t auth_len = bfd_auth_len(bfd->auth_type, key_len);
    uint8_t digest[BFD_SHA1_DIGEST_LEN];
    uint8_t digest_len;
    uint8_t len = BFD_HDR_LEN + auth_len;
    uint8_t flags = bfd->flags & ~BFD_FLAG_AUTH;

    if(auth_len) flags |= BFD_FLAG_AUTH;

    buf[0] = (BFD_VERSION << 5) | (bfd->diag & 0x1f);
    buf[1] = (bfd->state << 6) | flags;
    buf[2] = bfd->detect_mult;
    buf[3] = len;
    *(uint32_t*)(buf+4) = htobe32(bfd->my_discr);
    *(uint32_t*)(buf+8) = htobe32(bfd->your_discr);
    *(uint32_t*)(buf+12) = htobe32(bfd->desired_min_tx);
    *(uint32_t*)(buf+16) = htobe32(bfd->required_min_rx);
    *(uint32_t*)(buf+20) = htobe32(bfd->required_min_echo_rx);
    if(!auth_len) {
        return len;
    }

    buf[24] = bfd->auth_type;
    buf[25] = auth_len;
    buf[26] = bfd->auth_key_id;
    if(bfd->auth_type == BFD_AUTH_SIMPLE) {
        memcpy(buf+27, key, key_len);
        return len;
    }
    buf[27] = 0; /* reserved */
    *(uint32_t*)(buf+28) = htobe32(auth_seq);
    if(bfd_auth_digest(buf, len, bfd->auth_type, key, key_len, digest)) {
        bfd_auth_md(bfd->auth_type, &digest_len);
        memcpy(buf+32, digest, digest_len);
    }
    return len;
}

/**
 * bfd_packet_valid
 *
 * Reception checks of RFC 5880 section 6.8.6 which do
 * not depend on the session (except of authentication).
 *
 * @return true if valid
 */
bool
bfd_packet_valid(bbl_bfd_s *bfd)
{
    if(bfd->version != BFD_VERSION) return false;
    if(bfd->length < (bfd->flags & BFD_FLAG_AUTH ? BFD_HDR_LEN + 2 : BFD_HDR_LEN)) return false;
    if(bfd->length > bfd->pdu_len) return false;
    if(bfd->detect_mult == 0) return false;
    if(bfd->flags & BFD_FLAG_MULTIPOINT) return false;
    if(bfd->my_discr == 0) return false;
    if(bfd->your_discr == 0 &&
       bfd->state != BFD_STATE_DOWN && bfd->state != BFD_STATE_ADMIN_DOWN) return false;
    return true;
}

/**
 * bfd_packet_auth_verify
 *
 * Verify the authentication section of a received packet
 * (RFC 5880 sections 6.7.2, 6.7.3 and 6.7.4) except of the
 * sequence number, which is returned in seq.
 *
 * The digest field of the received packet is overwritten.
 *
 * @return true if valid
 */
bool
bfd_packet_auth_verify(bbl_bfd_s *bfd, uint8_t auth_type, uint8_t key_id,
                       const uint8_t *key, uint8_t key_len, uint32_t *seq)
{
    uint8_t received[BFD_SHA1_DIGEST_LEN];
    uint8_t digest[BFD_SHA1_DIGEST_LEN];
    uint8_t digest_len;

    if(!(bfd->flags & BFD_FLAG_AUTH) || !bfd->auth) {
        return false;
    }
    if(bfd->auth_type != auth_type || bfd->auth_key_id != key_id) {
        return false;
    }
    if(auth_type == BFD_AUTH_SIMPLE) {
        return bfd->auth_len == BFD_AUTH_HDR_LEN + key_len &&
               memcmp(bfd->auth + BFD_AUTH_HDR_LEN, key, key_len) == 0;
    }
    if(bfd->auth_len != bfd_auth_len(auth_type, key_len) ||
       bfd->length != BFD_HDR_LEN + bfd->auth_len) {
        return false;
    }
    *seq = be32toh(*(uint32_t*)(bfd->auth + 4));
    bfd_auth_md(auth_type, &digest_len);
    memcpy(received, bfd->auth + 8, digest_len);
    if(!bfd_auth_digest(bfd->pdu, bfd->length, auth_type, key, key_len, digest)) {
        return false;
    }
    return CRYPTO_memcmp(received, digest, digest_len) == 0;
}

/**
 * bfd_auth_seq_check
 *
 * Check the received sequence number against the window
 * of RFC 5880 sections 6.7.3 and 6.7.4 (modulo 2^32).
 */
bool
bfd_auth_seq_check(uint8_t auth_type, bool known, uint32_t last,
                   uint32_t seq, uint8_t detect_mult)
{
    uint32_t diff = seq - last;
    if(auth_type == BFD_AUTH_SIMPLE || !known) {
        return true;
    }
    if(bfd_auth_meticulous(auth_type)) {
        return diff >= 1 && diff <= 3U * detect_mult;
    }
    return diff <= 3U * detect_mult;
}

const char *
bfd_state_string(uint8_t state)
{
    switch(state) {
        case BFD_STATE_ADMIN_DOWN: return "AdminDown";
        case BFD_STATE_DOWN: return "Down";
        case BFD_STATE_INIT: return "Init";
        case BFD_STATE_UP: return "Up";
        default: return "Invalid";
    }
}

const char *
bfd_diag_string(uint8_t diag)
{
    switch(diag) {
        case BFD_DIAG_NONE: return "none";
        case BFD_DIAG_DETECTION_TIME_EXPIRED: return "control-detection-time-expired";
        case BFD_DIAG_ECHO_FAILED: return "echo-function-failed";
        case BFD_DIAG_NEIGHBOR_DOWN: return "neighbor-signaled-session-down";
        case BFD_DIAG_FORWARDING_PLANE_RESET: return "forwarding-plane-reset";
        case BFD_DIAG_PATH_DOWN: return "path-down";
        case BFD_DIAG_CONCATENATED_PATH_DOWN: return "concatenated-path-down";
        case BFD_DIAG_ADMIN_DOWN: return "administratively-down";
        case BFD_DIAG_REVERSE_CONCATENATED_PATH_DOWN: return "reverse-concatenated-path-down";
        default: return "unknown";
    }
}

const char *
bfd_auth_type_string(uint8_t auth_type)
{
    switch(auth_type) {
        case BFD_AUTH_NONE: return "none";
        case BFD_AUTH_SIMPLE: return "simple";
        case BFD_AUTH_KEYED_MD5: return "keyed-md5";
        case BFD_AUTH_METICULOUS_KEYED_MD5: return "meticulous-keyed-md5";
        case BFD_AUTH_KEYED_SHA1: return "keyed-sha1";
        case BFD_AUTH_METICULOUS_KEYED_SHA1: return "meticulous-keyed-sha1";
        default: return "unknown";
    }
}
