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

#include "hashtable.h"

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
    hash_node*		    next;
    /* Only because iterators are bidirectional: */
    hash_node*		    prev;
    unsigned		    hash;	/* Untruncated hash value. */
};

struct hashtable {
    hash_node**		    table;
    dict_compare_func	    cmp_func;
    dict_hash_func	    hash_func;
    size_t		    count;
    unsigned		    size;
};

struct hashtable_itor {
    hashtable*		    table;
    hash_node*		    node;
    unsigned		    slot;
};

static const dict_vtable hashtable_vtable = {
    false,
    (dict_inew_func)	    hashtable_dict_itor_new,
    (dict_dfree_func)	    hashtable_free,
    (dict_insert_func)	    hashtable_insert,
    (dict_search_func)	    hashtable_search,
    (dict_search_func)	    NULL,/* search_le: not supported */
    (dict_search_func)	    NULL,/* search_lt: not supported */
    (dict_search_func)	    NULL,/* search_ge: not supported */
    (dict_search_func)	    NULL,/* search_gt: not supported */
    (dict_remove_func)	    hashtable_remove,
    (dict_clear_func)	    hashtable_clear,
    (dict_traverse_func)    hashtable_traverse,
    (dict_select_func)	    NULL,
    (dict_count_func)	    hashtable_count,
    (dict_verify_func)	    hashtable_verify,
};

static const itor_vtable hashtable_itor_vtable = {
    (dict_ifree_func)	    hashtable_itor_free,
    (dict_valid_func)	    hashtable_itor_valid,
    (dict_invalidate_func)  hashtable_itor_invalidate,
    (dict_next_func)	    hashtable_itor_next,
    (dict_prev_func)	    hashtable_itor_prev,
    (dict_nextn_func)	    hashtable_itor_nextn,
    (dict_prevn_func)	    hashtable_itor_prevn,
    (dict_first_func)	    hashtable_itor_first,
    (dict_last_func)	    hashtable_itor_last,
    (dict_key_func)	    hashtable_itor_key,
    (dict_datum_func)	    hashtable_itor_datum,
    (dict_isearch_func)	    hashtable_itor_search,
    (dict_isearch_func)	    NULL,/* itor_search_le: not supported */
    (dict_isearch_func)	    NULL,/* itor_search_lt: not supported */
    (dict_isearch_func)	    NULL,/* itor_search_ge: not supported */
    (dict_isearch_func)	    NULL,/* itor_search_gt: not supported */
    (dict_iremove_func)	    hashtable_itor_remove,/* hashtable_itor_remove not implemented yet */
    (dict_icompare_func)    NULL,/* hashtable_itor_compare not implemented yet */
};

hashtable*
hashtable_new(dict_compare_func cmp_func, dict_hash_func hash_func, unsigned size)
{
    ASSERT(cmp_func != NULL);
    ASSERT(hash_func != NULL);
    ASSERT(size > 0);

    hashtable* table = MALLOC(sizeof(*table));
    if (table) {
	table->size = dict_prime_geq(size);
	table->table = MALLOC(table->size * sizeof(hash_node*));
	if (!table->table) {
	    FREE(table);
	    return NULL;
	}
	memset(table->table, 0, table->size * sizeof(hash_node*));
	table->cmp_func = cmp_func;
	table->hash_func = hash_func;
	table->count = 0;
    }
    return table;
}

dict*
hashtable_dict_new(dict_compare_func cmp_func, dict_hash_func hash_func, unsigned size)
{
    ASSERT(hash_func != NULL);
    ASSERT(size > 0);

    dict* dct = MALLOC(sizeof(*dct));
    if (dct) {
	dct->_object = hashtable_new(cmp_func, hash_func, size);
	if (!dct->_object) {
	    FREE(dct);
	    return NULL;
	}
	dct->_vtable = &hashtable_vtable;
    }
    return dct;
}

size_t
hashtable_free(hashtable* table, dict_delete_func delete_func)
{
    ASSERT(table != NULL);

    size_t count = hashtable_clear(table, delete_func);
    FREE(table->table);
    FREE(table);
    return count;
}

dict_insert_result
hashtable_insert(hashtable* table, void* key)
{
    if (LOADFACTOR_DENOMINATOR * table->count >= LOADFACTOR_NUMERATOR * table->size) {
	/* Load factor too high. */
	hashtable_resize(table, table->size + 1);
    }

    const unsigned hash = table->hash_func(key);
    const unsigned mhash = hash % table->size;
    hash_node* node = table->table[mhash];
    hash_node* prev = NULL;
    while (node && hash >= node->hash) {
	if (hash == node->hash && table->cmp_func(key, node->key) == 0)
	    return (dict_insert_result) { &node->datum, false };
	prev = node;
	node = node->next;
    }

    hash_node* add = MALLOC(sizeof(*add));
    if (!add)
	return (dict_insert_result) { NULL, false };

    add->key = key;
    add->datum = NULL;
    add->hash = hash;
    add->prev = prev;
    if (prev)
	prev->next = add;
    else
	table->table[mhash] = add;
    add->next = node;
    if (node)
	node->prev = add;

    table->count++;
    return (dict_insert_result) { &add->datum, true };
}

void**
hashtable_search(hashtable* table, const void* key)
{
    const unsigned hash = table->hash_func(key);
    hash_node* node = table->table[hash % table->size];
    while (node && hash >= node->hash) {
	if (hash == node->hash && table->cmp_func(key, node->key) == 0)
	    return &node->datum;
	node = node->next;
    }
    return NULL;
}

static void
remove_node(hashtable* table, hash_node* node, unsigned mhash)
{
    if (node->prev)
	node->prev->next = node->next;
    else
	table->table[mhash] = node->next;

    if (node->next)
	node->next->prev = node->prev;

    FREE(node);
    table->count--;
}

dict_remove_result
hashtable_remove(hashtable* table, const void* key)
{
    const unsigned hash = table->hash_func(key);
    const unsigned mhash = hash % table->size;

    hash_node* node = table->table[mhash];
    while (node && hash >= node->hash) {
	if (hash == node->hash && table->cmp_func(key, node->key) == 0) {
	    dict_remove_result result = { node->key, node->datum, true };
	    remove_node(table, node, mhash);
	    return result;
	}
	node = node->next;
    }
    return (dict_remove_result) { NULL, NULL, false };
}

size_t
hashtable_clear(hashtable* table, dict_delete_func delete_func)
{
    for (unsigned slot = 0; slot < table->size; slot++) {
	hash_node* node = table->table[slot];
	while (node != NULL) {
	    hash_node* next = node->next;
	    if (delete_func)
		delete_func(node->key, node->datum);
	    FREE(node);
	    node = next;
	}
	table->table[slot] = NULL;
    }

    const size_t count = table->count;
    table->count = 0;
    return count;
}

size_t
hashtable_traverse(hashtable* table, dict_visit_func visit, void* user_data)
{
    size_t count = 0;
    for (unsigned i = 0; i < table->size; i++)
	for (hash_node* node = table->table[i]; node; node = node->next) {
	    ++count;
	    if (!visit(node->key, node->datum, user_data))
		return count;
	}
    return count;
}

size_t
hashtable_count(const hashtable* table)
{
    return table->count;
}

size_t
hashtable_size(const hashtable* table)
{
    return table->size;
}

size_t
hashtable_slots_used(const hashtable* table)
{
    size_t count = 0;
    for (unsigned i = 0; i < table->size; i++)
	if (table->table[i])
	    count++;
    return count;
}

bool
hashtable_resize(hashtable* table, unsigned new_size)
{
    ASSERT(new_size > 0);

    new_size = dict_prime_geq(new_size);
    if (table->size == new_size)
	return true;

    /* TODO: investigate whether using realloc would be advantageous. */
    hash_node** ntable = MALLOC(new_size * sizeof(hash_node*));
    if (!ntable)
	return false;
    memset(ntable, 0, new_size * sizeof(hash_node*));

    for (unsigned i = 0; i < table->size; i++) {
	for (hash_node* node = table->table[i]; node;) {
	    hash_node* const next = node->next;
	    const unsigned mhash = node->hash % new_size;

	    hash_node* search = ntable[mhash];
	    hash_node* prev = NULL;
	    while (search && node->hash >= search->hash) {
		prev = search;
		search = search->next;
	    }
	    if ((node->next = search) != NULL)
		search->prev = node;
	    if ((node->prev = prev) != NULL)
		prev->next = node;
	    else
		ntable[mhash] = node;

	    node = next;
	}
    }

    FREE(table->table);
    table->table = ntable;
    table->size = new_size;
    return true;
}

bool
hashtable_verify(const hashtable* table)
{
    for (unsigned slot = 0; slot < table->size; ++slot) {
	for (hash_node* n = table->table[slot]; n; n = n->next) {
	    if (n == table->table[slot]) {
		VERIFY(n->prev == NULL);
	    } else {
		VERIFY(n->prev != NULL);
		VERIFY(n->prev->next == n);
	    }
	    if (n->next) {
		VERIFY(n->next->prev == n);
		VERIFY(n->hash <= n->next->hash);
	    }
	    VERIFY(n->hash % table->size == slot);
	}
    }
    return true;
}

hashtable_itor*
hashtable_itor_new(hashtable* table)
{
    hashtable_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	itor->table = table;
	itor->node = NULL;
	itor->slot = 0;
    }
    return itor;
}

dict_itor*
hashtable_dict_itor_new(hashtable* table)
{
    dict_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	if (!(itor->_itor = hashtable_itor_new(table))) {
	    FREE(itor);
	    return NULL;
	}
	itor->_vtable = &hashtable_itor_vtable;
    }
    return itor;
}

void
hashtable_itor_free(hashtable_itor* itor)
{
    FREE(itor);
}

bool
hashtable_itor_valid(const hashtable_itor* itor)
{
    return itor->node != NULL;
}

void
hashtable_itor_invalidate(hashtable_itor* itor)
{
    itor->node = NULL;
    itor->slot = 0;
}

bool
hashtable_itor_next(hashtable_itor* itor)
{
    if (!itor->node)
	return false;

    if ((itor->node = itor->node->next) != NULL)
	return true;

    unsigned slot = itor->slot;
    while (++slot < itor->table->size) {
	if (itor->table->table[slot]) {
	    itor->node = itor->table->table[slot];
	    itor->slot = slot;
	    return true;
	}
    }
    itor->node = NULL;
    itor->slot = 0;
    return itor->node != NULL;
}

bool
hashtable_itor_prev(hashtable_itor* itor)
{
    if (!itor->node)
	return false;

    if ((itor->node = itor->node->prev) != NULL)
	return true;

    unsigned slot = itor->slot;
    while (slot > 0) {
	hash_node* node = itor->table->table[--slot];
	if (node) {
	    while (node->next)
		node = node->next;
	    itor->node = node;
	    itor->slot = slot;
	    return true;
	}
    }
    itor->node = NULL;
    itor->slot = 0;
    return false;
}

bool
hashtable_itor_nextn(hashtable_itor* itor, size_t count)
{
    while (count--)
	if (!hashtable_itor_next(itor))
	    return false;
    return itor->node != NULL;
}

bool
hashtable_itor_prevn(hashtable_itor* itor, size_t count)
{
    while (count--)
	if (!hashtable_itor_prev(itor))
	    return false;
    return itor->node != NULL;
}

bool
hashtable_itor_first(hashtable_itor* itor)
{
    for (unsigned slot = 0; slot < itor->table->size; ++slot)
	if (itor->table->table[slot]) {
	    itor->node = itor->table->table[slot];
	    itor->slot = slot;
	    return true;
	}
    itor->node = NULL;
    itor->slot = 0;
    return false;
}

bool
hashtable_itor_last(hashtable_itor* itor)
{
    for (unsigned slot = itor->table->size; slot > 0;)
	if (itor->table->table[--slot]) {
	    hash_node* node = itor->table->table[slot];
	    while (node->next)
		node = node->next;
	    itor->node = node;
	    itor->slot = slot;
	    return true;
	}
    itor->node = NULL;
    itor->slot = 0;
    return false;
}

bool
hashtable_itor_search(hashtable_itor* itor, const void* key)
{
    const unsigned hash = itor->table->hash_func(key);
    const unsigned mhash = hash % itor->table->size;
    hash_node* node = itor->table->table[mhash];
    while (node && hash >= node->hash) {
	if (hash == node->hash && itor->table->cmp_func(key, node->key) == 0) {
	    itor->node = node;
	    itor->slot = mhash;
	    return true;
	}
	node = node->next;
    }
    itor->node = NULL;
    itor->slot = 0;
    return false;
}

const void*
hashtable_itor_key(const hashtable_itor* itor)
{
    return itor->node ? itor->node->key : NULL;
}

void**
hashtable_itor_datum(hashtable_itor* itor)
{
    return itor->node ? &itor->node->datum : NULL;
}

bool
hashtable_itor_remove(hashtable_itor* itor)
{
    if (!itor->node)
	return false;
    remove_node(itor->table, itor->node, itor->node->hash % itor->table->size);
    itor->node = NULL;
    return true;
}
