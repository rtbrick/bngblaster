/*
 * BNG Blaster (BBL) - BFD Tests
 *
 * Packet encoding and decoding, authentication (RFC 5880 6.7)
 * and reception checks (RFC 5880 6.8.6).
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <openssl/evp.h>

#include <bbl_def.h>
#include <bbl_protocols.h>
#include <bfd/bfd_def.h>
#include <bfd/bfd_packet.h>

static uint8_t g_src_mac[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t g_dst_mac[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

static void
bfd_test_header(bbl_bfd_s *bfd)
{
    memset(bfd, 0x0, sizeof(bbl_bfd_s));
    bfd->diag = BFD_DIAG_NEIGHBOR_DOWN;
    bfd->state = BFD_STATE_UP;
    bfd->flags = BFD_FLAG_POLL;
    bfd->detect_mult = 3;
    bfd->my_discr = 0x80000001;
    bfd->your_discr = 0x12345678;
    bfd->desired_min_tx = 100000;
    bfd->required_min_rx = 200000;
}

/* Encode BFD packet into Ethernet/IPv4/UDP and decode it again. */
static bbl_bfd_s *
bfd_test_roundtrip(uint8_t *buf, uint8_t *sp, uint8_t *pdu, uint16_t pdu_len, uint8_t ttl)
{
    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_udp_s udp = {0};
    bbl_bfd_s bfd = {0};
    bbl_ethernet_header_s *decoded;
    bbl_ipv4_s *decoded_ipv4;
    bbl_udp_s *decoded_udp;
    uint16_t len = 0;

    bfd.pdu = pdu;
    bfd.pdu_len = pdu_len;
    eth.dst = g_dst_mac;
    eth.src = g_src_mac;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &ipv4;
    ipv4.src = htobe32(0x0a000001);
    ipv4.dst = htobe32(0x0a000002);
    ipv4.ttl = ttl;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = 49152;
    udp.dst = BFD_UDP_PORT_SINGLE_HOP;
    udp.protocol = UDP_PROTOCOL_BFD;
    udp.next = &bfd;
    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    decoded_ipv4 = decoded->next;
    assert_int_equal(decoded_ipv4->ttl, ttl);
    decoded_udp = decoded_ipv4->next;
    assert_int_equal(decoded_udp->protocol, UDP_PROTOCOL_BFD);
    return decoded_udp->next;
}

static void
test_bfd_encode_decode(void **unused)
{
    (void) unused;
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[256];
    uint8_t pdu[BFD_MAX_LEN];
    bbl_bfd_s bfd;
    bbl_bfd_s *decoded;
    uint16_t len;

    /* RFC 5880 section 4.1 */
    static const uint8_t expected[BFD_HDR_LEN] = {
        0x23, 0xe0, 0x03, 0x18, 0x80, 0x00, 0x00, 0x01,
        0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0x86, 0xa0,
        0x00, 0x03, 0x0d, 0x40, 0x00, 0x00, 0x00, 0x00
    };

    bfd_test_header(&bfd);
    len = bfd_packet_encode(pdu, &bfd, 0, NULL, 0);
    assert_int_equal(len, BFD_HDR_LEN);
    assert_memory_equal(pdu, expected, BFD_HDR_LEN);

    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_int_equal(decoded->version, BFD_VERSION);
    assert_int_equal(decoded->diag, BFD_DIAG_NEIGHBOR_DOWN);
    assert_int_equal(decoded->state, BFD_STATE_UP);
    assert_int_equal(decoded->flags, BFD_FLAG_POLL);
    assert_int_equal(decoded->detect_mult, 3);
    assert_int_equal(decoded->length, BFD_HDR_LEN);
    assert_int_equal(decoded->my_discr, 0x80000001);
    assert_int_equal(decoded->your_discr, 0x12345678);
    assert_int_equal(decoded->desired_min_tx, 100000);
    assert_int_equal(decoded->required_min_rx, 200000);
    assert_int_equal(decoded->required_min_echo_rx, 0);
    assert_null(decoded->auth);
    assert_true(bfd_packet_valid(decoded));
    free(sp);
}

static void
test_bfd_decode_short(void **unused)
{
    (void) unused;
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[256];
    uint8_t pdu[BFD_MAX_LEN] = {0};
    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_udp_s udp = {0};
    bbl_bfd_s bfd = {0};
    bbl_ethernet_header_s *decoded;
    uint16_t len = 0;

    /* Packets shorter than the mandatory section are not decoded. */
    bfd.pdu = pdu;
    bfd.pdu_len = BFD_HDR_LEN - 1;
    eth.dst = g_dst_mac;
    eth.src = g_src_mac;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &ipv4;
    ipv4.ttl = 255;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = 49152;
    udp.dst = BFD_UDP_PORT_MULTI_HOP;
    udp.protocol = UDP_PROTOCOL_BFD;
    udp.next = &bfd;
    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_not_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    free(sp);
}

/* Digest computed independently of the implementation. */
static void
bfd_test_digest(const EVP_MD *md, uint8_t *pdu, uint16_t len, const char *key,
                uint8_t digest_len, uint8_t *digest)
{
    uint8_t copy[BFD_MAX_LEN];
    unsigned int md_len;

    memcpy(copy, pdu, len);
    memset(copy + 32, 0x0, digest_len);
    memcpy(copy + 32, key, strlen(key));
    assert_true(EVP_Digest(copy, len, digest, &md_len, md, NULL));
    assert_int_equal(md_len, digest_len);
}

static void
test_bfd_auth_type(uint8_t auth_type, const char *key)
{
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[256];
    uint8_t pdu[BFD_MAX_LEN];
    uint8_t digest[BFD_SHA1_DIGEST_LEN];
    uint8_t key_len = strlen(key);
    uint8_t auth_len = bfd_auth_len(auth_type, key_len);
    bbl_bfd_s bfd;
    bbl_bfd_s *decoded;
    uint32_t seq = 0;
    uint16_t len;

    bfd_test_header(&bfd);
    bfd.auth_type = auth_type;
    bfd.auth_key_id = 7;
    len = bfd_packet_encode(pdu, &bfd, 0xfffffffe, (const uint8_t*)key, key_len);
    assert_int_equal(len, BFD_HDR_LEN + auth_len);
    assert_int_equal(pdu[1] & BFD_FLAG_AUTH, BFD_FLAG_AUTH);
    assert_int_equal(pdu[3], len);
    assert_int_equal(pdu[24], auth_type);
    assert_int_equal(pdu[25], auth_len);
    assert_int_equal(pdu[26], 7);

    switch(auth_type) {
        case BFD_AUTH_SIMPLE:
            assert_memory_equal(pdu + 27, key, key_len);
            break;
        case BFD_AUTH_KEYED_MD5:
        case BFD_AUTH_METICULOUS_KEYED_MD5:
            assert_int_equal(auth_len, 24);
            assert_int_equal(pdu[27], 0);
            assert_int_equal(be32toh(*(uint32_t*)(pdu + 28)), 0xfffffffe);
            bfd_test_digest(EVP_md5(), pdu, len, key, BFD_MD5_DIGEST_LEN, digest);
            assert_memory_equal(pdu + 32, digest, BFD_MD5_DIGEST_LEN);
            break;
        default:
            assert_int_equal(auth_len, 28);
            assert_int_equal(be32toh(*(uint32_t*)(pdu + 28)), 0xfffffffe);
            bfd_test_digest(EVP_sha1(), pdu, len, key, BFD_SHA1_DIGEST_LEN, digest);
            assert_memory_equal(pdu + 32, digest, BFD_SHA1_DIGEST_LEN);
            break;
    }

    /* Valid packet. */
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_true(bfd_packet_valid(decoded));
    assert_int_equal(decoded->auth_type, auth_type);
    assert_int_equal(decoded->auth_key_id, 7);
    assert_true(bfd_packet_auth_verify(decoded, auth_type, 7, (const uint8_t*)key, key_len, &seq));
    if(auth_type != BFD_AUTH_SIMPLE) {
        assert_int_equal(seq, 0xfffffffe);
    }

    /* Wrong key ID. */
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_auth_verify(decoded, auth_type, 8, (const uint8_t*)key, key_len, &seq));

    /* Wrong key (same length and longer). */
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_auth_verify(decoded, auth_type, 7, (const uint8_t*)"Wrong", 5, &seq));
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_auth_verify(decoded, auth_type, 7, (const uint8_t*)"secret1", 7, &seq));

    /* Wrong authentication type. */
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_auth_verify(decoded, auth_type == BFD_AUTH_SIMPLE ? BFD_AUTH_KEYED_MD5 : BFD_AUTH_SIMPLE,
                                        7, (const uint8_t*)key, key_len, &seq));

    /* Modified packet. */
    pdu[17] ^= 0x01;
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    if(auth_type == BFD_AUTH_SIMPLE) {
        assert_true(bfd_packet_auth_verify(decoded, auth_type, 7, (const uint8_t*)key, key_len, &seq));
    } else {
        assert_false(bfd_packet_auth_verify(decoded, auth_type, 7, (const uint8_t*)key, key_len, &seq));
    }
    pdu[17] ^= 0x01;

    /* Packet without authentication. */
    bfd.auth_type = BFD_AUTH_NONE;
    len = bfd_packet_encode(pdu, &bfd, 0, NULL, 0);
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_auth_verify(decoded, auth_type, 7, (const uint8_t*)key, key_len, &seq));
    free(sp);
}

static void
test_bfd_auth_simple(void **unused)
{
    (void) unused;
    test_bfd_auth_type(BFD_AUTH_SIMPLE, "secret");
    test_bfd_auth_type(BFD_AUTH_SIMPLE, "0123456789abcdef");
}

static void
test_bfd_auth_md5(void **unused)
{
    (void) unused;
    test_bfd_auth_type(BFD_AUTH_KEYED_MD5, "secret");
    test_bfd_auth_type(BFD_AUTH_METICULOUS_KEYED_MD5, "0123456789abcdef");
}

static void
test_bfd_auth_sha1(void **unused)
{
    (void) unused;
    test_bfd_auth_type(BFD_AUTH_KEYED_SHA1, "secret");
    test_bfd_auth_type(BFD_AUTH_METICULOUS_KEYED_SHA1, "0123456789abcdef0123");
}

static void
test_bfd_auth_seq(void **unused)
{
    (void) unused;

    /* Unknown sequence number and simple password are not checked. */
    assert_true(bfd_auth_seq_check(BFD_AUTH_KEYED_MD5, false, 100, 5, 3));
    assert_true(bfd_auth_seq_check(BFD_AUTH_SIMPLE, true, 100, 5, 3));

    /* Keyed: RcvAuthSeq to RcvAuthSeq + 3 * DetectMult */
    assert_true(bfd_auth_seq_check(BFD_AUTH_KEYED_MD5, true, 100, 100, 3));
    assert_true(bfd_auth_seq_check(BFD_AUTH_KEYED_SHA1, true, 100, 109, 3));
    assert_false(bfd_auth_seq_check(BFD_AUTH_KEYED_SHA1, true, 100, 110, 3));
    assert_false(bfd_auth_seq_check(BFD_AUTH_KEYED_MD5, true, 100, 99, 3));

    /* Meticulous: RcvAuthSeq + 1 to RcvAuthSeq + 3 * DetectMult */
    assert_false(bfd_auth_seq_check(BFD_AUTH_METICULOUS_KEYED_MD5, true, 100, 100, 3));
    assert_true(bfd_auth_seq_check(BFD_AUTH_METICULOUS_KEYED_MD5, true, 100, 101, 3));
    assert_true(bfd_auth_seq_check(BFD_AUTH_METICULOUS_KEYED_SHA1, true, 100, 109, 3));
    assert_false(bfd_auth_seq_check(BFD_AUTH_METICULOUS_KEYED_SHA1, true, 100, 110, 3));

    /* Modulo 2^32 */
    assert_true(bfd_auth_seq_check(BFD_AUTH_METICULOUS_KEYED_SHA1, true, 0xffffffff, 0, 1));
    assert_true(bfd_auth_seq_check(BFD_AUTH_METICULOUS_KEYED_SHA1, true, 0xfffffffe, 1, 1));
    assert_false(bfd_auth_seq_check(BFD_AUTH_METICULOUS_KEYED_SHA1, true, 0xfffffffe, 2, 1));
    assert_true(bfd_auth_seq_check(BFD_AUTH_KEYED_MD5, true, 0xffffffff, 0xffffffff, 255));
    assert_true(bfd_auth_seq_check(BFD_AUTH_KEYED_MD5, true, 0xffffffff, 764, 255));
    assert_false(bfd_auth_seq_check(BFD_AUTH_KEYED_MD5, true, 0xffffffff, 765, 255));
}

static void
test_bfd_reception_checks(void **unused)
{
    (void) unused;
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[256];
    uint8_t pdu[BFD_MAX_LEN];
    bbl_bfd_s bfd;
    bbl_bfd_s *decoded;
    uint16_t len;

    bfd_test_header(&bfd);
    len = bfd_packet_encode(pdu, &bfd, 0, NULL, 0);

    /* Version */
    pdu[0] = (2 << 5) | (pdu[0] & 0x1f);
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    pdu[0] = (BFD_VERSION << 5) | (pdu[0] & 0x1f);

    /* Length below minimum and above the UDP payload. */
    pdu[3] = BFD_HDR_LEN - 1;
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    pdu[3] = BFD_HDR_LEN + 1;
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    pdu[3] = BFD_HDR_LEN;

    /* Length with A bit below 26. */
    pdu[1] |= BFD_FLAG_AUTH;
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    pdu[1] &= ~BFD_FLAG_AUTH;

    /* Detect multiplier zero */
    pdu[2] = 0;
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    pdu[2] = 3;

    /* Multipoint */
    pdu[1] |= BFD_FLAG_MULTIPOINT;
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    pdu[1] &= ~BFD_FLAG_MULTIPOINT;

    /* My discriminator zero */
    bfd.my_discr = 0;
    len = bfd_packet_encode(pdu, &bfd, 0, NULL, 0);
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    bfd.my_discr = 1;

    /* Your discriminator zero is valid only in state Down or AdminDown. */
    bfd.your_discr = 0;
    bfd.state = BFD_STATE_UP;
    len = bfd_packet_encode(pdu, &bfd, 0, NULL, 0);
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    bfd.state = BFD_STATE_INIT;
    len = bfd_packet_encode(pdu, &bfd, 0, NULL, 0);
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_false(bfd_packet_valid(decoded));
    bfd.state = BFD_STATE_DOWN;
    len = bfd_packet_encode(pdu, &bfd, 0, NULL, 0);
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_true(bfd_packet_valid(decoded));
    bfd.state = BFD_STATE_ADMIN_DOWN;
    len = bfd_packet_encode(pdu, &bfd, 0, NULL, 0);
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_true(bfd_packet_valid(decoded));

    /* Invalid authentication section length is not decoded. */
    bfd_test_header(&bfd);
    bfd.auth_type = BFD_AUTH_KEYED_SHA1;
    bfd.auth_key_id = 1;
    len = bfd_packet_encode(pdu, &bfd, 1, (const uint8_t*)"key", 3);
    pdu[25] = BFD_AUTH_SHA1_LEN + 1;
    decoded = bfd_test_roundtrip(buf, sp, pdu, len, 255);
    assert_null(decoded->auth);
    assert_false(bfd_packet_auth_verify(decoded, BFD_AUTH_KEYED_SHA1, 1, (const uint8_t*)"key", 3, &(uint32_t){0}));
    free(sp);
}

int
main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bfd_encode_decode),
        cmocka_unit_test(test_bfd_decode_short),
        cmocka_unit_test(test_bfd_auth_simple),
        cmocka_unit_test(test_bfd_auth_md5),
        cmocka_unit_test(test_bfd_auth_sha1),
        cmocka_unit_test(test_bfd_auth_seq),
        cmocka_unit_test(test_bfd_reception_checks),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
