/*
 * BNG Blaster (BBL) - OSPF LSA Tests
 *
 * The decision which LSA instance is more recent (RFC2328 section 13.1),
 * the OSPFv3 prefix encoding (RFC5340 A.4.1) and the flooding scope.
 *
 * Christian Giese, November 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/bbl.h"

/* Log messages are not printed, but their format is still checked. */
#undef LOG
#define LOG(log_id_, fmt_, ...) do { if(0) printf(fmt_, ##__VA_ARGS__); } while(0)
#undef LOG_NOARG
#define LOG_NOARG(log_id_, fmt_) do { if(0) printf(fmt_); } while(0)
#include "../src/ospf/ospf_lsa.c"

static ospf_lsa_header_s
test_hdr(uint32_t seq, uint16_t checksum, uint16_t age)
{
    ospf_lsa_header_s hdr = {0};
    hdr.seq = htobe32(seq);
    hdr.checksum = htobe16(checksum);
    hdr.age = htobe16(age);
    return hdr;
}

static int
test_compare(uint32_t seq_a, uint16_t age_a, uint32_t seq_b, uint16_t age_b)
{
    ospf_lsa_header_s a = test_hdr(seq_a, 0x1234, age_a);
    ospf_lsa_header_s b = test_hdr(seq_b, 0x1234, age_b);
    return ospf_lsa_compare(&a, &b);
}

static void
test_ospf_lsa_compare_seq(void **unused)
{
    (void) unused;
    assert_int_equal(test_compare(0x80000002, 0, 0x80000001, 0), 1);
    assert_int_equal(test_compare(0x80000001, 0, 0x80000002, 0), -1);
    /* The sequence number is a signed 32-bit integer. */
    assert_int_equal(test_compare(0x7ffffff0, 0, 0x80000001, 0), 1);
    assert_int_equal(test_compare(0x80000001, 0, 0x7fffffff, 0), -1);
    assert_int_equal(test_compare(0x00000001, 0, 0xffffffff, 0), 1);
}

static void
test_ospf_lsa_compare_checksum(void **unused)
{
    (void) unused;
    ospf_lsa_header_s a = test_hdr(0x80000001, 0x2000, 0);
    ospf_lsa_header_s b = test_hdr(0x80000001, 0x1000, 0);
    assert_int_equal(ospf_lsa_compare(&a, &b), 1);
    assert_int_equal(ospf_lsa_compare(&b, &a), -1);
}

static void
test_ospf_lsa_compare_age(void **unused)
{
    (void) unused;
    assert_int_equal(test_compare(0x80000001, 10, 0x80000001, 10), 0);
    /* Differences up to MaxAgeDiff are the same instance. */
    assert_int_equal(test_compare(0x80000001, 910, 0x80000001, 10), 0);
    /* The instance with the smaller age is more recent. */
    assert_int_equal(test_compare(0x80000001, 1000, 0x80000001, 10), -1);
    assert_int_equal(test_compare(0x80000001, 10, 0x80000001, 1000), 1);
    /* MaxAge is always more recent. */
    assert_int_equal(test_compare(0x80000001, OSPF_LSA_MAX_AGE, 0x80000001, 10), 1);
    assert_int_equal(test_compare(0x80000001, 0xffff, 0x80000001, 10), 1);
    assert_int_equal(test_compare(0x80000001, 10, 0x80000001, OSPF_LSA_MAX_AGE), -1);
}

static void
test_lsa_init(ospf_lsa_s *lsa, uint8_t *buf, uint16_t buf_len)
{
    memset(lsa, 0x0, sizeof(ospf_lsa_s));
    memset(buf, 0xff, buf_len);
    lsa->lsa = buf;
    lsa->lsa_buf_len = buf_len;
    lsa->lsa_len = OSPF_LSA_HDR_LEN;
}

static void
test_ospf_lsa_prefix_v3(void **unused)
{
    (void) unused;
    static uint8_t buf[256];
    ospf_lsa_s lsa;
    ipv6addr_t address = {0xfc, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t *prefix;

    test_lsa_init(&lsa, buf, sizeof(buf));

    /* /48 uses two words, the remaining bytes are zero. */
    prefix = lsa.lsa+lsa.lsa_len;
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, 0, 48, 0, 10, address), 1);
    assert_int_equal(lsa.lsa_len, OSPF_LSA_HDR_LEN+4+8);
    assert_int_equal(prefix[0], 48);
    assert_int_equal(prefix[1], 0);
    assert_int_equal(be16toh(*(uint16_t*)(prefix+2)), 10);
    assert_memory_equal(prefix+4, ((uint8_t[]){0xfc, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00}), 8);

    /* /126 uses four words with the host bits cleared. */
    prefix = lsa.lsa+lsa.lsa_len;
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, 0, 126, 0, 0, address), 1);
    assert_int_equal(lsa.lsa_len, OSPF_LSA_HDR_LEN+12+20);
    assert_int_equal(prefix[19], 0xfc);
    assert_int_equal(prefix[18], 0xff);

    /* /0 has no address. */
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, 0, 0, 0, 0, address), 1);
    assert_int_equal(lsa.lsa_len, OSPF_LSA_HDR_LEN+32+4);

    /* /56 has the same 32-bit words as /48 but is another prefix. */
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, OSPF_LSA_HDR_LEN, 56, 0, 0, address), 1);
    assert_int_equal(lsa.lsa_len, OSPF_LSA_HDR_LEN+36+12);

    /* Duplicates are skipped with check, host bits are ignored. */
    address[15] = 0xfe;
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, OSPF_LSA_HDR_LEN, 126, 0, 0, address), 0);
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, OSPF_LSA_HDR_LEN, 48, 0, 0, address), 0);
    assert_int_equal(lsa.lsa_len, OSPF_LSA_HDR_LEN+48);

    /* Invalid prefix length */
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, 0, 129, 0, 0, address), 0);

    /* No space left */
    lsa.lsa_buf_len = lsa.lsa_len + 4 + 12;
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, 0, 128, 0, 0, address), 0);
    assert_int_equal(ospf_lsa_add_prefix_v3(&lsa, 0, 96, 0, 0, address), 1);
}

static void
test_ospf_lsa_link_scope(void **unused)
{
    (void) unused;
    ospf_lsa_header_s hdr = {0};

    hdr.type = OSPF_LSA_TYPE_9;
    assert_true(ospf_lsa_link_scope(OSPF_VERSION_2, &hdr));
    hdr.type = OSPF_LSA_TYPE_10;
    assert_false(ospf_lsa_link_scope(OSPF_VERSION_2, &hdr));

    /* OSPFv3 Link LSA */
    hdr.options = OSPFV3_FSCOPE_LL;
    hdr.type = OSPF_LSA_TYPE_8;
    assert_true(ospf_lsa_link_scope(OSPF_VERSION_3, &hdr));
    /* OSPFv3 Router LSA */
    hdr.options = OSPFV3_FSCOPE_AREA;
    hdr.type = OSPF_LSA_TYPE_1;
    assert_false(ospf_lsa_link_scope(OSPF_VERSION_3, &hdr));
    /* OSPFv3 unknown with U-bit clear is link-local. */
    hdr.options = OSPFV3_FSCOPE_AS;
    hdr.type = OSPF_LSA_TYPE_20;
    assert_true(ospf_lsa_link_scope(OSPF_VERSION_3, &hdr));
    hdr.options = OSPFV3_U_BIT|OSPFV3_FSCOPE_AS;
    assert_false(ospf_lsa_link_scope(OSPF_VERSION_3, &hdr));
    /* OSPFv3 router information LSA */
    hdr.options = OSPFV3_U_BIT|OSPFV3_FSCOPE_AREA;
    hdr.type = OSPF_LSA_TYPE_12;
    assert_false(ospf_lsa_link_scope(OSPF_VERSION_3, &hdr));
}

int
main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ospf_lsa_compare_seq),
        cmocka_unit_test(test_ospf_lsa_compare_checksum),
        cmocka_unit_test(test_ospf_lsa_compare_age),
        cmocka_unit_test(test_ospf_lsa_prefix_v3),
        cmocka_unit_test(test_ospf_lsa_link_scope),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
