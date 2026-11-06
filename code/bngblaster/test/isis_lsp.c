/*
 * BNG Blaster (BBL) - ISIS LSP Tests
 *
 * The decision whether a received LSP is newer than the stored one
 * (ISO 10589 7.3.16) is tested with stored LSPs of all source types.
 *
 * Christian Giese, October 2026
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
#include "../src/isis/isis_lsp.c"
#include "../src/isis/isis_pdu.c"

#define TEST_SEQ        3
#define TEST_LIFETIME   1200
#define TEST_CHECKSUM   0x1234
#define TEST_PDU_LEN    (ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_LSP)

static void
test_pdu(isis_pdu_s *pdu, uint8_t *buf, uint32_t seq, uint16_t lifetime, uint16_t checksum)
{
    memset(pdu, 0x0, sizeof(isis_pdu_s));
    pdu->pdu = buf;
    pdu->size = TEST_PDU_LEN;
    *(uint16_t*)ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME) = htobe16(lifetime);
    *(uint32_t*)ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_LSP_SEQ) = htobe32(seq);
    *(uint16_t*)ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_LSP_CHECKSUM) = htobe16(checksum);
}

static void
test_lsp(isis_lsp_s *lsp, isis_lsp_source source, bool expired)
{
    static uint8_t buf[TEST_PDU_LEN];

    memset(lsp, 0x0, sizeof(isis_lsp_s));
    lsp->source.type = source;
    lsp->seq = TEST_SEQ;
    lsp->lifetime = expired ? 0 : TEST_LIFETIME;
    lsp->expired = expired;
    test_pdu(&lsp->pdu, buf, TEST_SEQ, lsp->lifetime, TEST_CHECKSUM);
}

static bool
test_newer(isis_lsp_s *lsp, uint32_t seq, uint16_t lifetime, uint16_t checksum)
{
    static uint8_t buf[TEST_PDU_LEN];
    static isis_pdu_s pdu;
    test_pdu(&pdu, buf, seq, lifetime, checksum);
    return isis_lsp_rx_newer(lsp, &pdu, seq);
}

static const isis_lsp_source sources[] = {
    ISIS_SOURCE_SELF, ISIS_SOURCE_ADJACENCY, ISIS_SOURCE_EXTERNAL
};

static void
test_isis_lsp_seq(void **unused)
{
    static isis_lsp_s lsp;
    size_t i;
    (void)unused;

    for(i = 0; i < sizeof(sources)/sizeof(sources[0]); i++) {
        test_lsp(&lsp, sources[i], false);
        assert_true(test_newer(&lsp, TEST_SEQ+1, TEST_LIFETIME, TEST_CHECKSUM));
        assert_true(test_newer(&lsp, TEST_SEQ+1, 0, 0));
        assert_false(test_newer(&lsp, TEST_SEQ-1, TEST_LIFETIME, TEST_CHECKSUM));
        assert_false(test_newer(&lsp, TEST_SEQ-1, 0, 0));
        /* Same LSP (e.g. flooded back) */
        assert_false(test_newer(&lsp, TEST_SEQ, TEST_LIFETIME, TEST_CHECKSUM));
    }
}

/* A purge with the same sequence number is newer than a not purged LSP,
 * e.g. the purge of a previous BNG Blaster instance after restart. */
static void
test_isis_lsp_purge(void **unused)
{
    static isis_lsp_s lsp;
    size_t i;
    (void)unused;

    for(i = 0; i < sizeof(sources)/sizeof(sources[0]); i++) {
        test_lsp(&lsp, sources[i], false);
        assert_true(test_newer(&lsp, TEST_SEQ, 0, 0));
        /* The own purge is flooded back (e.g. during teardown). */
        test_lsp(&lsp, sources[i], true);
        assert_false(test_newer(&lsp, TEST_SEQ, 0, 0));
    }
}

/* The same sequence number with a different checksum is newer for self
 * originated and external LSPs only, which are re-originated then. */
static void
test_isis_lsp_checksum(void **unused)
{
    static isis_lsp_s lsp;
    (void)unused;

    test_lsp(&lsp, ISIS_SOURCE_SELF, false);
    assert_true(test_newer(&lsp, TEST_SEQ, TEST_LIFETIME, TEST_CHECKSUM+1));
    test_lsp(&lsp, ISIS_SOURCE_EXTERNAL, false);
    assert_true(test_newer(&lsp, TEST_SEQ, TEST_LIFETIME, TEST_CHECKSUM+1));
    test_lsp(&lsp, ISIS_SOURCE_ADJACENCY, false);
    assert_false(test_newer(&lsp, TEST_SEQ, TEST_LIFETIME, TEST_CHECKSUM+1));
}

/* Stored PDUs are sized per LSP and keep their buffer on copy. */
static void
test_isis_pdu_copy(void **unused)
{
    uint8_t src_buf[ISIS_JUMBO_MAX_PDU_SIZE];
    isis_pdu_s src = {.pdu = src_buf, .size = sizeof(src_buf)};
    isis_pdu_s dst = {0};
    uint8_t *small;
    (void)unused;

    memset(src_buf, 0xaa, sizeof(src_buf));
    src.pdu_type = ISIS_PDU_L2_LSP;
    src.pdu_len = 100;
    isis_pdu_copy(&dst, &src);
    assert_int_equal(dst.size, 100);
    assert_int_equal(dst.pdu_len, 100);
    assert_int_equal(dst.pdu_type, ISIS_PDU_L2_LSP);
    assert_ptr_not_equal(dst.pdu, src.pdu);
    assert_memory_equal(dst.pdu, src_buf, 100);

    /* Smaller PDUs fit in the existing buffer. */
    small = dst.pdu;
    src.pdu_len = 50;
    isis_pdu_copy(&dst, &src);
    assert_ptr_equal(dst.pdu, small);
    assert_int_equal(dst.size, 100);
    assert_int_equal(dst.pdu_len, 50);

    src.pdu_len = sizeof(src_buf);
    isis_pdu_copy(&dst, &src);
    assert_int_equal(dst.size, sizeof(src_buf));
    assert_memory_equal(dst.pdu, src_buf, sizeof(src_buf));
    free(dst.pdu);
}

/* PDUs larger than the buffer size (RX limit) are rejected. */
static void
test_isis_pdu_load_limit(void **unused)
{
    uint8_t buf[ISIS_PDU_BUF_LEN] = {0};
    uint8_t pdu_buf[ISIS_PDU_BUF_LEN];
    isis_pdu_s pdu = {.pdu = pdu_buf, .size = ISIS_DEFAULT_MAX_PDU_LEN_RX};
    uint16_t len = ISIS_DEFAULT_MAX_PDU_LEN_RX;
    (void)unused;

    buf[0] = ISIS_PROTOCOL_IDENTIFIER;
    buf[1] = ISIS_HDR_LEN_COMMON+ISIS_HDR_LEN_LSP;
    buf[3] = 0;
    buf[4] = ISIS_PDU_L2_LSP;

    *(uint16_t*)(buf+ISIS_OFFSET_LSP_LEN) = htobe16(len);
    assert_int_equal(isis_pdu_load(&pdu, buf, len), PROTOCOL_SUCCESS);
    assert_int_equal(pdu.pdu_len, len);
    assert_ptr_equal(pdu.pdu, pdu_buf);
    assert_int_equal(isis_pdu_load(&pdu, buf, len+1), DECODE_ERROR);

    pdu.size = ISIS_PDU_BUF_LEN;
    *(uint16_t*)(buf+ISIS_OFFSET_LSP_LEN) = htobe16(ISIS_PDU_BUF_LEN);
    assert_int_equal(isis_pdu_load(&pdu, buf, ISIS_PDU_BUF_LEN), PROTOCOL_SUCCESS);
    assert_int_equal(pdu.pdu_len, ISIS_PDU_BUF_LEN);

    /* Only the default keeps the margin up to 1500 byte frames. */
    assert_int_equal(ISIS_MAX_PDU_LEN_RX(ISIS_DEFAULT_MAX_PDU_SIZE), 1497);
    assert_int_equal(ISIS_MAX_PDU_LEN_RX(1497), 1497);
    assert_int_equal(ISIS_MAX_PDU_LEN_RX(8997), 8997);
}

/* Hello padding fills exactly up to the PDU size. */
static void
test_isis_pdu_padding(void **unused)
{
    uint8_t pdu_buf[ISIS_PDU_BUF_LEN];
    isis_pdu_s pdu = {.pdu = pdu_buf};
    (void)unused;

    for(uint16_t size = ISIS_DEFAULT_MAX_PDU_SIZE; size <= ISIS_JUMBO_MAX_PDU_SIZE; size++) {
        pdu.size = size;
        isis_pdu_init(&pdu, ISIS_PDU_P2P_HELLO);
        assert_ptr_equal(pdu.pdu, pdu_buf);
        assert_int_equal(pdu.size, size);
        isis_pdu_padding(&pdu);
        assert_int_equal(pdu.pdu_len, size);
    }
}

void
timer_del(timer_s *timer)
{
    (void)timer;
}

static int
test_lsp_id_compare(const void *id1, const void *id2)
{
    const uint64_t a = *(const uint64_t*)id1;
    const uint64_t b = *(const uint64_t*)id2;
    return (a > b) - (a < b);
}

static void
test_gc_lsp_add(hb_tree *lsdb, uint64_t id, bool deleted)
{
    isis_lsp_s *lsp = calloc(1, sizeof(isis_lsp_s));
    dict_insert_result result;

    lsp->id = id;
    lsp->deleted = deleted;
    result = hb_tree_insert(lsdb, &lsp->id);
    assert_true(result.inserted);
    *result.datum_ptr = lsp;
}

static void
test_gc_lsp_free(void *key, void *datum)
{
    (void)key;
    free(datum);
}

static void
test_gc_lsdb_free(hb_tree *lsdb)
{
    hb_tree_free(lsdb, test_gc_lsp_free);
}

/* Deleted LSPs are removed per level, without touching LSPs
 * with the same LSP ID in the other level. */
static void
test_isis_lsp_gc(void **unused)
{
    isis_instance_s instance = {0};
    timer_s timer = {0};
    uint64_t id = 1;
    (void)unused;

    timer.data = &instance;
    instance.level[0].lsdb = hb_tree_new(test_lsp_id_compare);
    instance.level[1].lsdb = hb_tree_new(test_lsp_id_compare);

    test_gc_lsp_add(instance.level[0].lsdb, id, true);
    test_gc_lsp_add(instance.level[1].lsdb, id, false);
    isis_lsp_gc_job(&timer);
    assert_int_equal(hb_tree_count(instance.level[0].lsdb), 0);
    assert_int_equal(hb_tree_count(instance.level[1].lsdb), 1);
    test_gc_lsdb_free(instance.level[1].lsdb);
    instance.level[1].lsdb = hb_tree_new(test_lsp_id_compare);

    /* The delete list is limited per run and level. */
    for(id = 1; id <= ISIS_LSP_GC_DELETE_MAX + 1; id++) {
        test_gc_lsp_add(instance.level[0].lsdb, id, true);
        test_gc_lsp_add(instance.level[1].lsdb, id, true);
    }
    isis_lsp_gc_job(&timer);
    assert_int_equal(hb_tree_count(instance.level[0].lsdb), 1);
    assert_int_equal(hb_tree_count(instance.level[1].lsdb), 1);

    test_gc_lsdb_free(instance.level[0].lsdb);
    test_gc_lsdb_free(instance.level[1].lsdb);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_isis_lsp_seq),
        cmocka_unit_test(test_isis_pdu_copy),
        cmocka_unit_test(test_isis_pdu_load_limit),
        cmocka_unit_test(test_isis_pdu_padding),
        cmocka_unit_test(test_isis_lsp_purge),
        cmocka_unit_test(test_isis_lsp_checksum),
        cmocka_unit_test(test_isis_lsp_gc),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
