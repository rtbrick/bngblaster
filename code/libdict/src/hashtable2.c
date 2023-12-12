/*
 * libdict -- chained hash-table, with chains sorted by hash, implementation.
 *
 * Copyright (c) 2001-2014, Farooq Mela
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * cf. [Gonnet 1984], [Knuth 1998]
 */

#include "hashtable2.h"

#include <string.h> /* For memset() */
#include "dict_private.h"
#include "hashtable_common.h"

/* TODO: make this configurable in the constructor methods */
#define LOADFACTOR_NUMERATOR	2
#define LOADFACTOR_DENOMINATOR	3
#if LOADFACTOR_NUMERATOR > LOADFACTOR_DENOMINATOR
# error LOADFACTOR_NUMERATOR must be less than LOADFACTOR_DENOMINATOR
#endif

typedef struct hash_node hash_node;

struct hash_node {
    void*		    key;
    void*		    datum;
    unsigned		    hash;	/* Untruncated hash value; 0 iff unoccupied. */
};

struct hashtable2 {
    size_t		    count;
    dict_compare_func	    cmp_func;
    dict_hash_func	    hash_func;
    hash_node*		    table;
    unsigned		    size;
};

struct hashtable2_itor {
    hashtable2*		    table;
    int			    slot;
};

static const dict_vtable hashtable2_vtable = {
    false,
    (dict_inew_func)	    hashtable2_dict_itor_new,
    (dict_dfree_func)	    hashtable2_free,
    (dict_insert_func)	    hashtable2_insert,
    (dict_search_func)	    hashtable2_search,
    (dict_search_func)	    NULL,/* search_le: not supported */
    (dict_search_func)	    NULL,/* search_lt: not supported */
    (dict_search_func)	    NULL,/* search_ge: not supported */
    (dict_search_func)	    NULL,/* search_gt: not supported */
    (dict_remove_func)	    hashtable2_remove,
    (dict_clear_func)	    hashtable2_clear,
    (dict_traverse_func)    hashtable2_traverse,
    (dict_select_func)	    NULL,
    (dict_count_func)	    hashtable2_count,
    (dict_verify_func)	    hashtable2_verify,
};

static const itor_vtable hashtable2_itor_vtable = {
    (dict_ifree_func)	    hashtable2_itor_free,
    (dict_valid_func)	    hashtable2_itor_valid,
    (dict_invalidate_func)  hashtable2_itor_invalidate,
    (dict_next_func)	    hashtable2_itor_next,
    (dict_prev_func)	    hashtable2_itor_prev,
    (dict_nextn_func)	    hashtable2_itor_nextn,
    (dict_prevn_func)	    hashtable2_itor_prevn,
    (dict_first_func)	    hashtable2_itor_first,
    (dict_last_func)	    hashtable2_itor_last,
    (dict_key_func)	    hashtable2_itor_key,
    (dict_datum_func)	    hashtable2_itor_datum,
    (dict_isearch_func)	    hashtable2_itor_search,
    (dict_isearch_func)	    NULL,/* itor_search_le: not supported */
    (dict_isearch_func)	    NULL,/* itor_search_lt: not supported */
    (dict_isearch_func)	    NULL,/* itor_search_ge: not supported */
    (dict_isearch_func)	    NULL,/* itor_search_gt: not supported */
    (dict_iremove_func)	    hashtable2_itor_remove,
    (dict_icompare_func)    NULL,/* hashtable2_itor_compare not implemented yet */
};

hashtable2*
hashtable2_new(dict_compare_func cmp_func, dict_hash_func hash_func, unsigned initial_size)
{
    ASSERT(cmp_func != NULL);
    ASSERT(hash_func != NULL);
    ASSERT(initial_size > 0);

    hashtable2* table = MALLOC(sizeof(*table));
    if (table) {
	table->size = dict_prime_geq(initial_size);
	table->table = MALLOC(table->size * sizeof(hash_node));
	if (!table->table) {
	    FREE(table);
	    return NULL;
	}
	memset(table->table, 0, table->size * sizeof(hash_node));
	table->cmp_func = cmp_func;
	table->hash_func = hash_func;
	table->count = 0;
    }
    return table;
}

dict*
hashtable2_dict_new(dict_compare_func cmp_func, dict_hash_func hash_func, unsigned initial_size)
{
    ASSERT(hash_func != NULL);
    ASSERT(initial_size > 0);

    dict* dct = MALLOC(sizeof(*dct));
    if (dct) {
	dct->_object = hashtable2_new(cmp_func, hash_func, initial_size);
	if (!dct->_object) {
	    FREE(dct);
	    return NULL;
	}
	dct->_vtable = &hashtable2_vtable;
    }
    return dct;
}

size_t
hashtable2_free(hashtable2* table, dict_delete_func delete_func)
{
    size_t count = hashtable2_clear(table, delete_func);
    FREE(table->table);
    FREE(table);
    return count;
}

static inline dict_insert_result
insert(hashtable2* table, void *key, unsigned hash)
{
    hash_node* const first = table->table + (hash % table->size);
    hash_node* const table_end = table->table + table->size;
    hash_node* node = first;
    do {
	if (!node->hash) {
	    node->hash = hash;
	    node->key = key;
	    ASSERT(node->datum == NULL);
	    return (dict_insert_result) { &node->datum, true };
	}

	if (node->hash == hash && table->cmp_func(key, node->key) == 0)
	    return (dict_insert_result) { &node->datum, false };

	if (++node == table_end)
	    node = table->table;
    } while (node != first);
    /* No room for new element! */
    return (dict_insert_result) { NULL, false };
}

static inline unsigned
nonzero_hash(dict_hash_func hash_func, const void *key)
{
    const unsigned hash = hash_func(key);
    return hash ? hash : ~(unsigned)0;
}

dict_insert_result
hashtable2_insert(hashtable2* table, void* key)
{
    if (LOADFACTOR_DENOMINATOR * table->count >= LOADFACTOR_NUMERATOR * table->size) {
	/* Load factor too high: increase the table size. */
	if (!hashtable2_resize(table, table->size + 1)) {
	    /* No memory for a bigger table, but let the insert proceed anyway. */
	}
    }
    const unsigned hash = nonzero_hash(table->hash_func, key);
    dict_insert_result result = insert(table, key, hash);
    if (result.inserted)
	table->count++;
    return result;
}

void**
hashtable2_search(hashtable2* table, const void* key)
{
    const unsigned hash = nonzero_hash(table->hash_func, key);
    hash_node* const first = table->table + (hash % table->size);
    hash_node* const table_end = table->table + table->size;
    hash_node* node = first;
    do {
	if (!node->hash) /* Not occupied. */
	    break;

	if (node->hash == hash && table->cmp_func(key, node->key) == 0)
	    return &node->datum;

	if (++node == table_end)
	    node = table->table;
    } while (node != first);
    return NULL;
}

#if 0
static int
index_of_node_to_shift(hashtable2* table, unsigned truncated_hash, unsigned index)
{
    int last_index = -1;
    do {
	hash_node* node = &table->table[index];
	if (!node->hash) {
	    break;
	}
	if (node->hash % table->size == truncated_hash) {
	    last_index = index;
	}
	if (++index == table->size) {
	    index = 0;
	}
    } while (index != truncated_hash);
    return last_index;
}
#endif

static void
remove_cleanup(hashtable2* table, hash_node* const first, hash_node* node)
{
    hash_node* const table_end = table->table + table->size;
    do {
	const unsigned hash = node->hash;
	if (!hash) /* Not occupied. */
	    break;

	void* const datum = node->datum;
	node->datum = NULL;
	node->hash = 0;

	dict_insert_result result = insert(table, node->key, hash);
	ASSERT(result.inserted);
	ASSERT(result.datum_ptr != NULL);
	ASSERT(*result.datum_ptr == NULL);
	*result.datum_ptr = datum;

	if (++node == table_end)
	    node = table->table;
    } while (node != first);
}

static void
remove_node(hashtable2* table, hash_node* first, hash_node* node)
{
    ASSERT(node->hash != 0);

    node->key = node->datum = NULL;
    node->hash = 0;
    table->count--;

    if (++node == table->table + table->size)
	node = table->table;
    remove_cleanup(table, first, node);
}

dict_remove_result
hashtable2_remove(hashtable2* table, const void* key)
{
    const unsigned hash = nonzero_hash(table->hash_func, key);
    hash_node* const first = table->table + (hash % table->size);
    hash_node* const table_end = table->table + table->size;
    hash_node* node = first;
    do {
	if (!node->hash) /* Not occupied. */
	    break;

	if (node->hash == hash && table->cmp_func(key, node->key) == 0) {
	    dict_remove_result result = { node->key, node->datum, true };
	    remove_node(table, first, node);
	    return result;
	}

	if (++node == table_end)
	    node = table->table;
    } while (node != first);
    return (dict_remove_result) { NULL, NULL, false };
}

size_t
hashtable2_clear(hashtable2* table, dict_delete_func delete_func)
{
    hash_node *node = table->table;
    hash_node *const end = table->table + table->size;
    for (; node != end; ++node) {
	if (node->hash) {
	    if (delete_func)
		delete_func(node->key, node->datum);
	    node->key = node->datum = NULL;
	    node->hash = 0;
	}
    }

    const size_t count = table->count;
    table->count = 0;
    return count;
}

size_t
hashtable2_traverse(hashtable2* table, dict_visit_func visit, void* user_data)
{
    size_t count = 0;
    hash_node *node = table->table;
    for (hash_node *const end = table->table + table->size; node != end; ++node) {
	if (node->hash) {
	    ++count;
	    if (!visit(node->key, node->datum, user_data))
		break;
	}
    }
    return count;
}

size_t
hashtable2_count(const hashtable2* table)
{
    return table->count;
}

size_t
hashtable2_size(const hashtable2* table)
{
    return table->size;
}

size_t
hashtable2_slots_used(const hashtable2* table)
{
    return table->count;
}

bool
hashtable2_resize(hashtable2* table, unsigned new_size)
{
    ASSERT(new_size > 0);

    new_size = dict_prime_geq(new_size);
    if (table->size == new_size)
	return true;

    if (table->count > new_size) {
	/* The number of records already in hashtable will not fit (must be a reduction in size). */
	return false;
    }

    const unsigned old_size = table->size;
    const size_t old_count = table->count;
    hash_node* const old_table = table->table;

    table->table = MALLOC(new_size * sizeof(hash_node));
    if (!table->table) {
	table->table = old_table;
	return false;
    }
    memset(table->table, 0, new_size * sizeof(hash_node));
    table->size = new_size;

    for (unsigned i = 0; i < old_size; ++i) {
	if (old_table[i].hash) {
	    dict_insert_result result =
		insert(table, old_table[i].key, old_table[i].hash);
	    if (!result.inserted || !result.datum_ptr) {
		FREE(table->table);
		table->table = old_table;
		table->size = old_size;
		table->count = old_count;
		return false;
	    }
	    *result.datum_ptr = old_table[i].datum;
	}
    }
    FREE(old_table);
    return true;
}

bool
hashtable2_verify(const hashtable2* table)
{
    size_t count = 0;
    const hash_node *node = table->table;
    const hash_node *end = table->table + table->size;
    for (; node != end; ++node) {
	if (node->hash) {
	    ++count;
	} else {
	    VERIFY(node->datum == NULL);
	}
    }
    VERIFY(table->count == count);
    return true;
}

hashtable2_itor*
hashtable2_itor_new(hashtable2* table)
{
    hashtable2_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	itor->table = table;
	itor->slot = -1;
    }
    return itor;
}

dict_itor*
hashtable2_dict_itor_new(hashtable2* table)
{
    dict_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	if (!(itor->_itor = hashtable2_itor_new(table))) {
	    FREE(itor);
	    return NULL;
	}
	itor->_vtable = &hashtable2_itor_vtable;
    }
    return itor;
}

void
hashtable2_itor_free(hashtable2_itor* itor)
{
    FREE(itor);
}

bool
hashtable2_itor_valid(const hashtable2_itor* itor)
{
    if (itor->slot < 0)
	return false;
    ASSERT(itor->table->table[itor->slot].hash != 0);
    return true;
}

void
hashtable2_itor_invalidate(hashtable2_itor* itor)
{
    itor->slot = -1;
}

bool
hashtable2_itor_next(hashtable2_itor* itor)
{
    if (itor->slot < 0)
	return false;

    while (++itor->slot < (int) itor->table->size) {
	if (itor->table->table[itor->slot].hash)
	    return true;
    }
    itor->slot = -1;
    return false;
}

bool
hashtable2_itor_prev(hashtable2_itor* itor)
{
    if (itor->slot < 0)
	return false;

    while (itor->slot-- > 0) {
	if (itor->table->table[itor->slot].hash)
	    return true;
    }
    ASSERT(itor->slot == -1);
    return false;
}

bool
hashtable2_itor_nextn(hashtable2_itor* itor, size_t count)
{
    while (count--)
	if (!hashtable2_itor_next(itor))
	    return false;
    return itor->slot >= 0;
}

bool
hashtable2_itor_prevn(hashtable2_itor* itor, size_t count)
{
    while (count--)
	if (!hashtable2_itor_prev(itor))
	    return false;
    return itor->slot >= 0;
}

bool
hashtable2_itor_first(hashtable2_itor* itor)
{
    for (unsigned slot = 0; slot < itor->table->size; ++slot) {
	if (itor->table->table[slot].hash) {
	    itor->slot = (int) slot;
	    return true;
	}
    }
    itor->slot = -1;
    return false;
}

bool
hashtable2_itor_last(hashtable2_itor* itor)
{
    for (unsigned slot = itor->table->size; slot > 0;) {
	if (itor->table->table[--slot].hash) {
	    itor->slot = (int) slot;
	    return true;
	}
    }
    itor->slot = -1;
    return false;
}

bool
hashtable2_itor_search(hashtable2_itor* itor, const void* key)
{
    const unsigned hash = nonzero_hash(itor->table->hash_func, key);
    const unsigned truncated_hash = hash % itor->table->size;
    unsigned index = truncated_hash;
    do {
	hash_node *node = &itor->table->table[index];
	if (!node->hash)
	    break;
	if (node->hash == hash && itor->table->cmp_func(key, node->key) == 0) {
	    itor->slot = (int) index;
	    return true;
	}
	if (++index == itor->table->size)
	    index = 0;
    } while (index != truncated_hash);
    itor->slot = -1;
    return NULL;
}

const void*
hashtable2_itor_key(const hashtable2_itor* itor)
{
    return (itor->slot >= 0) ? itor->table->table[itor->slot].key : NULL;
}

void**
hashtable2_itor_datum(hashtable2_itor* itor)
{
    return (itor->slot >= 0) ? &itor->table->table[itor->slot].datum : NULL;
}

bool
hashtable2_itor_remove(hashtable2_itor* itor)
{
    if (itor->slot < 0)
	return false;
    remove_node(itor->table,
		itor->table->table + itor->table->table[itor->slot].hash % itor->table->size,
		itor->table->table + itor->slot);
    itor->slot = -1;
    return true;
}

