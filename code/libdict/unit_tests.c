/* unit_tests.c
 * Copyright (C) 2012 Farooq Mela. All rights reserved. */

#include <assert.h>
#include <float.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "dict.h"
#include "util.h"
#include "src/hashtable_common.h"   /* For dict_prime_geq() */

#define TEST_FUNC(func) { (char *)#func, func }

struct key_info {
    char *key, *value, *alt;
};

struct closest_lookup_info {
    const char *key;
    const char *le_key, *le_val;
    const char *lt_key, *lt_val;
    const char *ge_key, *ge_val;
    const char *gt_key, *gt_val;
};

void test_basic(dict *dct, const struct key_info *keys, const unsigned nkeys, bool keys_sorted);
void test_basic_hashtable_1bucket(void);
void test_basic_hashtable2_1bucket(void);
void test_basic_hashtable_nbuckets(void);
void test_basic_hashtable2_nbuckets(void);
void test_basic_height_balanced_tree(void);
void test_basic_path_reduction_tree(void);
void test_basic_red_black_tree(void);
void test_basic_skiplist(void);
void test_basic_splay_tree(void);
void test_basic_treap(void);
void test_basic_weight_balanced_tree(void);
void test_search(dict *dct, dict_itor *itor, const char *key, const char *value);
void test_closest_lookup(dict *dct, unsigned nkeys, bool keys_sorted);
void test_primes_geq(void);
void test_version_string(void);

static CU_TestInfo basic_tests[] = {
    TEST_FUNC(test_basic_hashtable_1bucket),
    TEST_FUNC(test_basic_hashtable2_1bucket),
    TEST_FUNC(test_basic_hashtable_nbuckets),
    TEST_FUNC(test_basic_hashtable2_nbuckets),
    TEST_FUNC(test_basic_height_balanced_tree),
    TEST_FUNC(test_basic_path_reduction_tree),
    TEST_FUNC(test_basic_red_black_tree),
    TEST_FUNC(test_basic_skiplist),
    TEST_FUNC(test_basic_splay_tree),
    TEST_FUNC(test_basic_treap),
    TEST_FUNC(test_basic_weight_balanced_tree),
    TEST_FUNC(test_primes_geq),
    TEST_FUNC(test_version_string),
    CU_TEST_INFO_NULL
};

#define TEST_SUITE(suite) { .pName = (char *)#suite, .pTests = suite }

static CU_SuiteInfo test_suites[] = {
    TEST_SUITE(basic_tests),
    CU_SUITE_INFO_NULL
};

static size_t bytes_malloced = 0;

static void*
custom_malloc(size_t n)
{
    size_t* p = malloc(sizeof(size_t) + n);
    assert(p);
    bytes_malloced += n;
    p[0] = n;
    return &p[1];
}

static void
custom_free(void* p)
{
    assert(p);
    size_t* sp = p;
    bytes_malloced -= sp[-1];
    free(sp - 1);
}

int
main()
{
    dict_malloc_func = custom_malloc;
    dict_free_func = custom_free;

    if (CU_initialize_registry() != CUE_SUCCESS ||
	CU_register_suites(test_suites) != CUE_SUCCESS) {
	fprintf(stderr, "Failed to initialize tests!\n");
	exit(EXIT_FAILURE);
    }
    CU_basic_set_mode(CU_BRM_SILENT);
    if (CU_basic_run_tests() != CUE_SUCCESS) {
	fprintf(stderr, "Failed to run tests!\n");
	exit(EXIT_FAILURE);
    }
    unsigned failures = 0;
    for (const CU_FailureRecord *f = CU_get_failure_list(); f; f = f->pNext) {
	fprintf(stderr, "%u: %s (%s:%u): %s\n",
		++failures, f->pTest->pName, f->strFileName, f->uiLineNumber, f->strCondition);
    }
    CU_cleanup_registry();
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}

static const struct key_info unsorted_keys[] = {
    { "d", "D", "d" },
    { "b", "B", "b" },
    { "a", "A", "a" },
    { "c", "C", "c" },
    { "g", "G", "g" },
    { "f", "F", "f" },
    { "h", "H", "h" },
    { "y", "Y", "y" },
    { "z", "Z", "z" },
    { "x", "X", "x" },
    { "j", "J", "j" },
    { "r", "R", "r" },
    { "q", "Q", "q" },
    { "p", "P", "p" },
    { "l", "L", "l" },
    { "m", "M", "m" },
    { "s", "S", "s" },
    { "t", "T", "t" },
    { "u", "U", "u" },
    { "da", "DA", "da" },
    { "ba", "BA", "ba" },
    { "aa", "AA", "aa" },
    { "ca", "CA", "ca" },
    { "ga", "GA", "ga" },
    { "fa", "FA", "fa" },
    { "ha", "HA", "ha" },
    { "ya", "YA", "ya" },
    { "za", "ZA", "za" },
    { "xa", "XA", "xa" },
    { "ja", "JA", "ja" },
    { "ra", "RA", "ra" },
    { "qa", "QA", "qa" },
    { "pa", "PA", "pa" },
    { "la", "LA", "la" },
    { "ma", "MA", "ma" },
    { "sa", "SA", "sa" },
    { "ta", "TA", "ta" },
    { "ua", "UA", "ua" },
};
#define NUM_UNSORTED_KEYS (sizeof(unsorted_keys) / sizeof(unsorted_keys[0]))

static const struct key_info sorted_keys[] = {
    { "a", "A", "a" },
    { "aa", "AA", "aa" },
    { "b", "B", "b" },
    { "ba", "BA", "ba" },
    { "c", "C", "c" },
    { "ca", "CA", "ca" },
    { "d", "D", "d" },
    { "da", "DA", "da" },
    { "f", "F", "f" },
    { "fa", "FA", "fa" },
    { "g", "G", "g" },
    { "ga", "GA", "ga" },
    { "h", "H", "h" },
    { "ha", "HA", "ha" },
    { "j", "J", "j" },
    { "ja", "JA", "ja" },
    { "l", "L", "l" },
    { "la", "LA", "la" },
    { "m", "M", "m" },
    { "ma", "MA", "ma" },
    { "p", "P", "p" },
    { "pa", "PA", "pa" },
    { "q", "Q", "q" },
    { "qa", "QA", "qa" },
    { "r", "R", "r" },
    { "ra", "RA", "ra" },
    { "s", "S", "s" },
    { "sa", "SA", "sa" },
    { "t", "T", "t" },
    { "ta", "TA", "ta" },
    { "u", "U", "u" },
    { "ua", "UA", "ua" },
    { "x", "X", "x" },
    { "xa", "XA", "xa" },
    { "y", "Y", "y" },
    { "ya", "YA", "ya" },
    { "z", "Z", "z" },
    { "za", "ZA", "za" },
};
#define NUM_SORTED_KEYS (sizeof(sorted_keys) / sizeof(sorted_keys[0]))

static_assert(NUM_SORTED_KEYS == NUM_UNSORTED_KEYS, "sorted keys and unsorted keys count mismatch");

static const struct closest_lookup_info closest_lookup_infos[] = {
    {.key = "_",
     .ge_key = "a", .ge_val = "A",
     .gt_key = "a", .gt_val = "A"},
    {.key = "a",
     .le_key = "a", .le_val = "A",
     .ge_key = "a", .ge_val = "A",
     .gt_key = "aa", .gt_val = "AA"},
    {.key = "aa",
     .le_key = "aa", .le_val = "AA",
     .lt_key = "a", .lt_val = "A",
     .ge_key = "aa", .ge_val = "AA",
     .gt_key = "b", .gt_val = "B"},
    {.key = "ab",
     .le_key = "aa", .le_val = "AA",
     .lt_key = "aa", .lt_val = "AA",
     .ge_key = "b", .ge_val = "B",
     .gt_key = "b", .gt_val = "B"},
    {.key = "m",
     .le_key = "m", .le_val = "M",
     .lt_key = "la", .lt_val = "LA",
     .ge_key = "m", .ge_val = "M",
     .gt_key = "ma", .gt_val = "MA"},
    {.key = "n",
     .le_key = "ma", .le_val = "MA",
     .lt_key = "ma", .lt_val = "MA",
     .ge_key = "p", .ge_val = "P",
     .gt_key = "p", .gt_val = "P"},
    {.key = "za",
     .le_key = "za", .le_val = "ZA",
     .lt_key = "z", .lt_val = "Z",
     .ge_key = "za", .ge_val = "ZA"},
    {.key = "zb",
     .le_key = "za", .le_val = "ZA",
     .lt_key = "za", .lt_val = "ZA"},
};

#define NUM_CLOSEST_LOOKUP_INFOS (sizeof(closest_lookup_infos) / sizeof(closest_lookup_infos[0]))

void
test_search(dict *dct, dict_itor *itor, const char *key, const char *value)
{
    void **search = dict_search(dct, key);
    if (value == NULL) {
	CU_ASSERT_PTR_NULL(search);
    } else {
	CU_ASSERT_PTR_NOT_NULL(search);
	CU_ASSERT_EQUAL(*search, value);
    }

    if (itor != NULL) {
	if (value == NULL) {
	    CU_ASSERT_FALSE(dict_itor_search(itor, key));
	    CU_ASSERT_FALSE(dict_itor_valid(itor));
	} else {
	    CU_ASSERT_TRUE(dict_itor_search(itor, key));
	    CU_ASSERT_TRUE(dict_itor_valid(itor));
	    CU_ASSERT_EQUAL(dict_itor_key(itor), key);
	    CU_ASSERT_PTR_NOT_NULL(dict_itor_datum(itor));
	    CU_ASSERT_EQUAL(*dict_itor_datum(itor), value);
	}
    }
}

void
test_closest_lookup(dict *dct, unsigned nkeys, bool keys_sorted)
{
    if (dict_is_sorted(dct) && keys_sorted) {
	for (unsigned i = 0; i < nkeys; ++i) {
	    const void* key = NULL;
	    void* datum = NULL;
	    if (dct->_vtable->select) {
		CU_ASSERT_TRUE(dict_select(dct, i, &key, &datum));
		CU_ASSERT_EQUAL(key, sorted_keys[i].key);
		CU_ASSERT_EQUAL(datum, sorted_keys[i].value);
	    }
	}
	const void* key = NULL;
	void* datum = NULL;
	CU_ASSERT_FALSE(dict_select(dct, nkeys, &key, &datum));
	CU_ASSERT_EQUAL(key, (const void*)NULL);
	CU_ASSERT_PTR_NULL(datum);
    }

    dict_itor* itor = dict_itor_new(dct);
    for (unsigned i = 0; i < NUM_CLOSEST_LOOKUP_INFOS; i++) {
	const struct closest_lookup_info* const info = &closest_lookup_infos[i];
	if (!dict_is_sorted(dct)) {
	    CU_ASSERT_PTR_NULL(dct->_vtable->search_le);
	    CU_ASSERT_PTR_NULL(dct->_vtable->search_lt);
	    CU_ASSERT_PTR_NULL(dct->_vtable->search_ge);
	    CU_ASSERT_PTR_NULL(dct->_vtable->search_gt);
	    CU_ASSERT_PTR_NULL(itor->_vtable->search_le);
	    CU_ASSERT_PTR_NULL(itor->_vtable->search_lt);
	    CU_ASSERT_PTR_NULL(itor->_vtable->search_ge);
	    CU_ASSERT_PTR_NULL(itor->_vtable->search_gt);
	    const void* key = NULL;
	    void* datum = NULL;
	    CU_ASSERT_FALSE(dict_select(dct, i, &key, &datum));
	    CU_ASSERT_EQUAL(key, (const void*)NULL);
	    CU_ASSERT_PTR_NULL(datum);
	    CU_ASSERT_PTR_NULL(dict_search_le(dct, info->key));
	    CU_ASSERT_PTR_NULL(dict_search_lt(dct, info->key));
	    CU_ASSERT_PTR_NULL(dict_search_ge(dct, info->key));
	    CU_ASSERT_PTR_NULL(dict_search_gt(dct, info->key));
	    continue;
	}
	if (nkeys < NUM_SORTED_KEYS)
	    continue;
	if (info->le_key) {
	    if (dct->_vtable->search_le) {
		CU_ASSERT_PTR_NOT_NULL(dict_search_le(dct, info->key));
		void **datum = dict_search_le(dct, info->key);
		CU_ASSERT_TRUE(datum != NULL && *datum != NULL && strcmp(*datum, info->le_val) == 0);
	    }
	    if (itor->_vtable->search_le) {
		CU_ASSERT_TRUE(dict_itor_search_le(itor, info->key));
		CU_ASSERT_TRUE(dict_itor_valid(itor));
		CU_ASSERT_STRING_EQUAL(dict_itor_key(itor), info->le_key);
		void **datum = dict_itor_datum(itor);
		CU_ASSERT_TRUE(datum != NULL && *datum != NULL && strcmp(*datum, info->le_val) == 0);
	    }
	} else {
	    CU_ASSERT_PTR_NULL(dict_search_le(dct, info->key));
	    CU_ASSERT_FALSE(dict_itor_search_le(itor, info->key));
	    CU_ASSERT_FALSE(dict_itor_valid(itor));
	    CU_ASSERT_PTR_NULL(dict_itor_key(itor));
	    CU_ASSERT_PTR_NULL(dict_itor_datum(itor));
	}
	if (info->lt_key) {
	    if (dct->_vtable->search_lt) {
		CU_ASSERT_PTR_NOT_NULL(dict_search_lt(dct, info->key));
		void** datum = dict_search_lt(dct, info->key);
		CU_ASSERT_TRUE(datum != NULL && *datum != NULL && strcmp(*datum, info->lt_val) == 0);
	    }
	    if (itor->_vtable->search_lt) {
		CU_ASSERT_TRUE(dict_itor_search_lt(itor, info->key));
		CU_ASSERT_TRUE(dict_itor_valid(itor));
		CU_ASSERT_STRING_EQUAL(dict_itor_key(itor), info->lt_key);
		void** datum = dict_itor_datum(itor);
		CU_ASSERT_TRUE(datum != NULL && *datum != NULL && strcmp(*datum, info->lt_val) == 0);
	    }
	} else {
	    CU_ASSERT_PTR_NULL(dict_search_lt(dct, info->key));
	    CU_ASSERT_FALSE(dict_itor_search_lt(itor, info->key));
	    CU_ASSERT_FALSE(dict_itor_valid(itor));
	    CU_ASSERT_PTR_NULL(dict_itor_key(itor));
	    CU_ASSERT_PTR_NULL(dict_itor_datum(itor));
	}
	if (info->ge_key) {
	    if (dct->_vtable->search_ge) {
		CU_ASSERT_PTR_NOT_NULL(dict_search_ge(dct, info->key));
		void** datum = dict_search_ge(dct, info->key);
		CU_ASSERT_TRUE(datum != NULL && *datum != NULL && strcmp(*datum, info->ge_val) == 0);
	    }
	    if (itor->_vtable->search_ge) {
		CU_ASSERT_TRUE(dict_itor_search_ge(itor, info->key));
		CU_ASSERT_TRUE(dict_itor_valid(itor));
		CU_ASSERT_STRING_EQUAL(dict_itor_key(itor), info->ge_key);
		void** datum = dict_itor_datum(itor);
		CU_ASSERT_TRUE(datum != NULL && *datum != NULL && strcmp(*datum, info->ge_val) == 0);
	    }
	} else {
	    CU_ASSERT_PTR_NULL(dict_search_ge(dct, info->key));
	    CU_ASSERT_FALSE(dict_itor_search_ge(itor, info->key));
	    CU_ASSERT_FALSE(dict_itor_valid(itor));
	    CU_ASSERT_PTR_NULL(dict_itor_key(itor));
	    CU_ASSERT_PTR_NULL(dict_itor_datum(itor));
	}
	if (info->gt_key) {
	    if (dct->_vtable->search_gt) {
		CU_ASSERT_PTR_NOT_NULL(dict_search_gt(dct, info->key));
		void** datum = dict_search_gt(dct, info->key);
		CU_ASSERT_TRUE(datum != NULL && *datum != NULL && strcmp(*datum, info->gt_val) == 0);
	    }
	    if (itor->_vtable->search_gt) {
		CU_ASSERT_TRUE(dict_itor_search_gt(itor, info->key));
		CU_ASSERT_TRUE(dict_itor_valid(itor));
		CU_ASSERT_STRING_EQUAL(dict_itor_key(itor), info->gt_key);
		void** datum = dict_itor_datum(itor);
		CU_ASSERT_TRUE(datum != NULL && *datum != NULL && strcmp(*datum, info->gt_val) == 0);
	    }
	} else {
	    CU_ASSERT_PTR_NULL(dict_search_gt(dct, info->key));
	    CU_ASSERT_FALSE(dict_itor_search_gt(itor, info->key));
	    CU_ASSERT_FALSE(dict_itor_valid(itor));
	    CU_ASSERT_PTR_NULL(dict_itor_key(itor));
	    CU_ASSERT_PTR_NULL(dict_itor_datum(itor));
	}
    }
    dict_itor_free(itor);
}

void test_basic(dict *dct, const struct key_info *keys, const unsigned nkeys, bool keys_sorted)
{
    CU_ASSERT_TRUE(dict_verify(dct));

    dict_itor *itor = dict_itor_new(dct);
    CU_ASSERT_PTR_NOT_NULL(itor);
    CU_ASSERT_FALSE(dict_itor_valid(itor));

    CU_ASSERT_FALSE(dict_itor_next(itor));
    CU_ASSERT_FALSE(dict_itor_valid(itor));

    CU_ASSERT_FALSE(dict_itor_prev(itor));
    CU_ASSERT_FALSE(dict_itor_valid(itor));

    for (unsigned i = 0; i < nkeys; ++i) {
	dict_insert_result result = dict_insert(dct, keys[i].key);
	CU_ASSERT_TRUE(result.inserted);
	CU_ASSERT_PTR_NOT_NULL(result.datum_ptr);
	CU_ASSERT_PTR_NULL(*result.datum_ptr);
	*result.datum_ptr = keys[i].value;

	CU_ASSERT_TRUE(dict_verify(dct));

	for (unsigned j = 0; j <= i; ++j)
	    test_search(dct, itor, keys[j].key, keys[j].value);
	for (unsigned j = i + 1; j < nkeys; ++j)
	    test_search(dct, itor, keys[j].key, NULL);
    }
    CU_ASSERT_EQUAL(dict_count(dct), nkeys);

    if (dct->_vtable->insert == (dict_insert_func)hashtable_insert ||
	dct->_vtable->insert == (dict_insert_func)hashtable2_insert) {
	/* Verify that hashtable_resize works as expected. */
	if (dct->_vtable->insert == (dict_insert_func)hashtable_insert) {
	    CU_ASSERT_TRUE(hashtable_resize(dict_private(dct), 3));
	} else {
	    CU_ASSERT_TRUE(hashtable2_resize(dict_private(dct),
					     dict_prime_geq(nkeys * 5)));
	}
	CU_ASSERT_TRUE(dict_verify(dct));
	CU_ASSERT_EQUAL(dict_count(dct), nkeys);
	for (unsigned j = 0; j < nkeys; ++j)
	    test_search(dct, NULL, keys[j].key, keys[j].value);
    }

    for (unsigned i = 0; i < nkeys; ++i)
	test_search(dct, itor, keys[i].key, keys[i].value);

    for (unsigned i = 0; i < nkeys; ++i) {
	dict_insert_result result = dict_insert(dct, keys[i].key);
	CU_ASSERT_FALSE(result.inserted);
	CU_ASSERT_PTR_NOT_NULL(result.datum_ptr);
	CU_ASSERT_EQUAL(*result.datum_ptr, keys[i].value);

	CU_ASSERT_TRUE(dict_verify(dct));
    }
    CU_ASSERT_EQUAL(dict_count(dct), nkeys);

    dict_itor *first = dict_itor_new(dct);
    CU_ASSERT_PTR_NOT_NULL(first);
    CU_ASSERT_FALSE(dict_itor_valid(first));
    if (nkeys > 0) {
	CU_ASSERT_TRUE(dict_itor_first(first));
	CU_ASSERT_TRUE(dict_itor_valid(first));
    } else {
	CU_ASSERT_FALSE(dict_itor_first(first));
	CU_ASSERT_FALSE(dict_itor_valid(first));
    }

    dict_itor *last = dict_itor_new(dct);
    CU_ASSERT_PTR_NOT_NULL(last);
    CU_ASSERT_FALSE(dict_itor_valid(last));
    if (nkeys > 0) {
	CU_ASSERT_TRUE(dict_itor_last(last));
	CU_ASSERT_TRUE(dict_itor_valid(last));
    } else {
	CU_ASSERT_FALSE(dict_itor_last(last));
	CU_ASSERT_FALSE(dict_itor_valid(last));
    }
    if (dict_is_sorted(dct)) {
	if (nkeys <= 1) {
	    CU_ASSERT_TRUE(dict_itor_compare(first, last) == 0);
	    CU_ASSERT_TRUE(dict_itor_compare(last, first) == 0);
	} else {
	    CU_ASSERT_TRUE(dict_itor_compare(first, last) < 0);
	    CU_ASSERT_TRUE(dict_itor_compare(last, first) > 0);
	}
    }

    char *last_key = NULL;
    unsigned n = 0;
    for (dict_itor_first(itor); dict_itor_valid(itor); dict_itor_next(itor)) {
	CU_ASSERT_PTR_NOT_NULL(dict_itor_key(itor));
	CU_ASSERT_PTR_NOT_NULL(dict_itor_datum(itor));
	CU_ASSERT_PTR_NOT_NULL(*dict_itor_datum(itor));
	if (dict_is_sorted(dct)) {
	    CU_ASSERT_TRUE(dict_itor_compare(itor, itor) == 0);
	    if (n == 0) {
		CU_ASSERT_TRUE(dict_itor_compare(itor, first) == 0);
		CU_ASSERT_TRUE(dict_itor_compare(first, itor) == 0);
	    } else {
		CU_ASSERT_TRUE(dict_itor_compare(itor, first) > 0);
		CU_ASSERT_TRUE(dict_itor_compare(first, itor) < 0);
	    }
	    if (n == nkeys - 1) {
		CU_ASSERT_TRUE(dict_itor_compare(itor, last) == 0);
		CU_ASSERT_TRUE(dict_itor_compare(last, itor) == 0);
	    } else {
		CU_ASSERT_TRUE(dict_itor_compare(itor, last) < 0);
		CU_ASSERT_TRUE(dict_itor_compare(last, itor) > 0);
	    }
	    if (keys_sorted) {
		CU_ASSERT_EQUAL(dict_itor_key(itor), keys[n].key);
		CU_ASSERT_EQUAL(*dict_itor_datum(itor), keys[n].value);
	    }
	}
	unsigned keys_matched = 0;
	for (unsigned i = 0; i < nkeys; ++i) {
	    if (dict_itor_key(itor) == keys[i].key) {
		CU_ASSERT_EQUAL(*dict_itor_datum(itor), keys[i].value);
		keys_matched++;
	    } else {
		CU_ASSERT_NOT_EQUAL(*dict_itor_datum(itor), keys[i].value);
	    }
	}
	CU_ASSERT_EQUAL(keys_matched, 1);

	if (dict_is_sorted(dct)) {
	    if (last_key) {
		CU_ASSERT_TRUE(strcmp(last_key, dict_itor_key(itor)) < 0);
	    }
	    last_key = dict_itor_key(itor);
	}

	++n;
    }
    CU_ASSERT_EQUAL(n, nkeys);
    last_key = NULL;
    n = 0;
    for (dict_itor_last(itor); dict_itor_valid(itor); dict_itor_prev(itor)) {
	CU_ASSERT_PTR_NOT_NULL(dict_itor_key(itor));
	CU_ASSERT_PTR_NOT_NULL(dict_itor_datum(itor));
	CU_ASSERT_PTR_NOT_NULL(*dict_itor_datum(itor));

	if (dict_is_sorted(dct) && keys_sorted) {
	    CU_ASSERT_EQUAL(dict_itor_key(itor), keys[nkeys - 1 - n].key);
	    CU_ASSERT_EQUAL(*dict_itor_datum(itor), keys[nkeys - 1 - n].value);
	}
	unsigned keys_matched = 0;
	for (unsigned i = 0; i < nkeys; ++i) {
	    if (dict_itor_key(itor) == keys[i].key) {
		CU_ASSERT_EQUAL(*dict_itor_datum(itor), keys[i].value);
		keys_matched++;
	    } else {
		CU_ASSERT_NOT_EQUAL(*dict_itor_datum(itor), keys[i].value);
	    }
	}
	CU_ASSERT_EQUAL(keys_matched, 1);

	if (dict_is_sorted(dct)) {
	    if (last_key) {
		CU_ASSERT_TRUE(strcmp(last_key, dict_itor_key(itor)) > 0);
	    }
	    last_key = dict_itor_key(itor);
	}

	++n;
    }
    CU_ASSERT_EQUAL(n, nkeys);

    for (unsigned i = 0; i < nkeys; ++i) {
	dict_insert_result result = dict_insert(dct, keys[i].key);
	CU_ASSERT_FALSE(result.inserted);
	CU_ASSERT_PTR_NOT_NULL(result.datum_ptr);
	CU_ASSERT_PTR_NOT_NULL(*result.datum_ptr);
	*result.datum_ptr = keys[i].alt;

	CU_ASSERT_TRUE(dict_verify(dct));
    }
    CU_ASSERT_EQUAL(dict_count(dct), nkeys);

    for (unsigned i = 0; i < nkeys; ++i)
	test_search(dct, itor, keys[i].key, keys[i].alt);

    for (unsigned i = 0; i < nkeys; ++i) {
	test_search(dct, itor, keys[i].key, keys[i].alt);

	dict_remove_result result = dict_remove(dct, keys[i].key);
	CU_ASSERT_TRUE(result.removed);
	CU_ASSERT_EQUAL(result.key, keys[i].key);
	CU_ASSERT_EQUAL(result.datum, keys[i].alt);
	CU_ASSERT_TRUE(dict_verify(dct));

	result = dict_remove(dct, keys[i].key);
	CU_ASSERT_FALSE(result.removed);
	CU_ASSERT_PTR_NULL(result.key);
	CU_ASSERT_PTR_NULL(result.datum);
	for (unsigned j = 0; j <= i; ++j) {
	    test_search(dct, itor, keys[j].key, NULL);
	}
	for (unsigned j = i + 1; j < nkeys; ++j) {
	    test_search(dct, itor, keys[j].key, keys[j].alt);
	}
    }

    for (unsigned i = 0; i < nkeys; ++i) {
	dict_insert_result result = dict_insert(dct, keys[i].key);
	CU_ASSERT_TRUE(result.inserted);
	CU_ASSERT_PTR_NOT_NULL(result.datum_ptr);
	CU_ASSERT_PTR_NULL(*result.datum_ptr);
	*result.datum_ptr = keys[i].value;

	CU_ASSERT_TRUE(dict_verify(dct));
    }
    CU_ASSERT_EQUAL(dict_count(dct), nkeys);
    CU_ASSERT_EQUAL(dict_clear(dct, NULL), nkeys);
    CU_ASSERT_TRUE(dict_verify(dct));
    CU_ASSERT_EQUAL(dict_count(dct), 0);

    for (unsigned i = 0; i < nkeys; ++i) {
	test_search(dct, itor, keys[i].key, NULL);

	dict_insert_result result = dict_insert(dct, keys[i].key);
	CU_ASSERT_TRUE(result.inserted);
	CU_ASSERT_PTR_NOT_NULL(result.datum_ptr);
	CU_ASSERT_PTR_NULL(*result.datum_ptr);
	*result.datum_ptr = keys[i].value;

	CU_ASSERT_TRUE(dict_verify(dct));
    }
    CU_ASSERT_EQUAL(dict_count(dct), nkeys);

    test_closest_lookup(dct, nkeys, keys_sorted);

    for (unsigned i = 0; i < nkeys; ++i) {
	CU_ASSERT_TRUE(dict_itor_search(itor, keys[i].key));
	CU_ASSERT_TRUE(dict_itor_valid(itor));
	CU_ASSERT_EQUAL(dict_itor_key(itor), keys[i].key);
	CU_ASSERT_PTR_NOT_NULL(dict_itor_datum(itor));
	CU_ASSERT_EQUAL(*dict_itor_datum(itor), keys[i].value);

	CU_ASSERT_TRUE(dict_itor_remove(itor));
	CU_ASSERT_FALSE(dict_itor_valid(itor));

	CU_ASSERT_FALSE(dict_itor_search(itor, keys[i].key));
	CU_ASSERT_FALSE(dict_itor_valid(itor));
    }
    CU_ASSERT_EQUAL(dict_count(dct), 0);

    for (unsigned i = 0; i < nkeys; ++i) {
	test_search(dct, itor, keys[i].key, NULL);

	dict_insert_result result = dict_insert(dct, keys[i].key);
	CU_ASSERT_TRUE(result.inserted);
	CU_ASSERT_PTR_NOT_NULL(result.datum_ptr);
	CU_ASSERT_PTR_NULL(*result.datum_ptr);
	*result.datum_ptr = keys[i].value;

	CU_ASSERT_TRUE(dict_verify(dct));
    }
    CU_ASSERT_EQUAL(dict_count(dct), nkeys);

    dict_itor_free(itor);
    dict_itor_free(first);
    dict_itor_free(last);
    CU_ASSERT_EQUAL(dict_count(dct), nkeys);
    CU_ASSERT_EQUAL(dict_free(dct, NULL), nkeys);
}

void test_basic_hashtable_1bucket()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hashtable_dict_new(dict_str_cmp, dict_str_hash, 1), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hashtable_dict_new(dict_str_cmp, dict_str_hash, 1), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_hashtable2_1bucket()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hashtable2_dict_new(dict_str_cmp, dict_str_hash, 1), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hashtable2_dict_new(dict_str_cmp, dict_str_hash, 1), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_hashtable_nbuckets()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hashtable_dict_new(dict_str_cmp, dict_str_hash, 7), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hashtable_dict_new(dict_str_cmp, dict_str_hash, 7), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_hashtable2_nbuckets()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hashtable2_dict_new(dict_str_cmp, dict_str_hash, 7), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hashtable2_dict_new(dict_str_cmp, dict_str_hash, 7), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_height_balanced_tree()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hb_dict_new(dict_str_cmp), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(hb_dict_new(dict_str_cmp), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_path_reduction_tree()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(pr_dict_new(dict_str_cmp), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(pr_dict_new(dict_str_cmp), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_red_black_tree()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(rb_dict_new(dict_str_cmp), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(rb_dict_new(dict_str_cmp), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_skiplist()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(skiplist_dict_new(dict_str_cmp, 13), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(skiplist_dict_new(dict_str_cmp, 13), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_splay_tree()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(sp_dict_new(dict_str_cmp), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(sp_dict_new(dict_str_cmp), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_treap()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(tr_dict_new(dict_str_cmp, NULL), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(tr_dict_new(dict_str_cmp, NULL), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_basic_weight_balanced_tree()
{
    for (unsigned n = 0; n <= NUM_SORTED_KEYS; ++n) {
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(wb_dict_new(dict_str_cmp), unsorted_keys, n, false);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
	test_basic(wb_dict_new(dict_str_cmp), sorted_keys, n, true);
	CU_ASSERT_EQUAL(bytes_malloced, 0);
    }
}

void test_primes_geq()
{
    CU_ASSERT_TRUE(is_prime(2));
    CU_ASSERT_TRUE(is_prime(3));
    CU_ASSERT_FALSE(is_prime(4));
    CU_ASSERT_TRUE(is_prime(5));
    CU_ASSERT_FALSE(is_prime(6));
    CU_ASSERT_TRUE(is_prime(7));

    unsigned value = 0;
    do {
	const unsigned prime_geq_value = dict_prime_geq(value+1);
	CU_ASSERT_TRUE(prime_geq_value >= value+1);
	CU_ASSERT_TRUE(is_prime(prime_geq_value));
	CU_ASSERT_TRUE(dict_prime_geq(prime_geq_value) == prime_geq_value);
	value = prime_geq_value;
    } while (value != 4294967291U);
}

void test_version_string()
{
    char version_string[32];
    snprintf(version_string, sizeof(version_string), "%d.%d.%d",
	     DICT_VERSION_MAJOR, DICT_VERSION_MINOR, DICT_VERSION_PATCH);
    CU_ASSERT_STRING_EQUAL(kDictVersionString, version_string);
}
