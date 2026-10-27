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

#define TEST_SEQ        3
#define TEST_LIFETIME   1200
#define TEST_CHECKSUM   0x1234

static void
test_pdu(isis_pdu_s *pdu, uint32_t seq, uint16_t lifetime, uint16_t checksum)
{
    memset(pdu, 0x0, sizeof(isis_pdu_s));
    *(uint16_t*)ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_LSP_LIFETIME) = htobe16(lifetime);
    *(uint32_t*)ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_LSP_SEQ) = htobe32(seq);
    *(uint16_t*)ISIS_PDU_OFFSET(pdu, ISIS_OFFSET_LSP_CHECKSUM) = htobe16(checksum);
}

static void
test_lsp(isis_lsp_s *lsp, isis_lsp_source source, bool expired)
{
    memset(lsp, 0x0, sizeof(isis_lsp_s));
    lsp->source.type = source;
    lsp->seq = TEST_SEQ;
    lsp->lifetime = expired ? 0 : TEST_LIFETIME;
    lsp->expired = expired;
    test_pdu(&lsp->pdu, TEST_SEQ, lsp->lifetime, TEST_CHECKSUM);
}

static bool
test_newer(isis_lsp_s *lsp, uint32_t seq, uint16_t lifetime, uint16_t checksum)
{
    static isis_pdu_s pdu;
    test_pdu(&pdu, seq, lifetime, checksum);
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
        cmocka_unit_test(test_isis_lsp_purge),
        cmocka_unit_test(test_isis_lsp_checksum),
        cmocka_unit_test(test_isis_lsp_gc),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
