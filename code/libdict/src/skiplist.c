/*
 * libdict -- skiplist implementation.
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
 * cf. [Pugh 1990], [Sedgewick 1998]
 */

#include "skiplist.h"

#include <string.h>	    /* For memset() */
#include "dict_private.h"

typedef struct skip_node skip_node;

struct skip_node {
    void*		    key;
    void*		    datum;
    skip_node*		    prev;
    unsigned		    link_count;
    skip_node*		    link[];
};

#define MAX_LINK	    32

struct skiplist {
    skip_node*		    head;
    unsigned		    max_link;
    unsigned		    top_link;
    dict_compare_func	    cmp_func;
    size_t		    count;
};

struct skiplist_itor {
    skiplist*		    list;
    skip_node*		    node;
};

static const dict_vtable skiplist_vtable = {
    true,
    (dict_inew_func)	    skiplist_dict_itor_new,
    (dict_dfree_func)	    skiplist_free,
    (dict_insert_func)	    skiplist_insert,
    (dict_search_func)	    skiplist_search,
    (dict_search_func)	    skiplist_search_le,
    (dict_search_func)	    skiplist_search_lt,
    (dict_search_func)	    skiplist_search_ge,
    (dict_search_func)	    skiplist_search_gt,
    (dict_remove_func)	    skiplist_remove,
    (dict_clear_func)	    skiplist_clear,
    (dict_traverse_func)    skiplist_traverse,
    (dict_select_func)	    NULL,
    (dict_count_func)	    skiplist_count,
    (dict_verify_func)	    skiplist_verify,
};

static const itor_vtable skiplist_itor_vtable = {
    (dict_ifree_func)	    skiplist_itor_free,
    (dict_valid_func)	    skiplist_itor_valid,
    (dict_invalidate_func)  skiplist_itor_invalidate,
    (dict_next_func)	    skiplist_itor_next,
    (dict_prev_func)	    skiplist_itor_prev,
    (dict_nextn_func)	    skiplist_itor_nextn,
    (dict_prevn_func)	    skiplist_itor_prevn,
    (dict_first_func)	    skiplist_itor_first,
    (dict_last_func)	    skiplist_itor_last,
    (dict_key_func)	    skiplist_itor_key,
    (dict_datum_func)	    skiplist_itor_datum,
    (dict_isearch_func)	    skiplist_itor_search,
    (dict_isearch_func)	    skiplist_itor_search_le,
    (dict_isearch_func)	    skiplist_itor_search_lt,
    (dict_isearch_func)	    skiplist_itor_search_ge,
    (dict_isearch_func)	    skiplist_itor_search_gt,
    (dict_iremove_func)	    skiplist_itor_remove,
    (dict_icompare_func)    skiplist_itor_compare,
};

static inline skip_node*   node_new(void* key, unsigned link_count);
static inline void	   node_insert(skiplist* list, skip_node* x, skip_node** update);
static inline skip_node*   node_search(skiplist* list, const void* key);
static inline skip_node*   node_search_le(skiplist* list, const void* key);
static inline skip_node*   node_search_lt(skiplist* list, const void* key);
static inline skip_node*   node_search_ge(skiplist* list, const void* key);
static inline skip_node*   node_search_gt(skiplist* list, const void* key);
static inline unsigned	   rand_link_count(skiplist* list);

skiplist*
skiplist_new(dict_compare_func cmp_func, unsigned max_link)
{
    ASSERT(cmp_func != NULL);
    ASSERT(max_link > 0);

    if (max_link > MAX_LINK)
	max_link = MAX_LINK;

    skiplist* list = MALLOC(sizeof(*list));
    if (list) {
	if (!(list->head = node_new(NULL, max_link))) {
	    FREE(list);
	    return NULL;
	}

	list->max_link = max_link;
	list->top_link = 0;
	list->cmp_func = cmp_func;
	list->count = 0;
    }
    return list;
}

dict*
skiplist_dict_new(dict_compare_func cmp_func, unsigned max_link)
{
    dict* dct = MALLOC(sizeof(*dct));
    if (dct) {
	if (!(dct->_object = skiplist_new(cmp_func, max_link))) {
	    FREE(dct);
	    return NULL;
	}
	dct->_vtable = &skiplist_vtable;
    }
    return dct;
}

size_t
skiplist_free(skiplist* list, dict_delete_func delete_func)
{
    size_t count = skiplist_clear(list, delete_func);
    FREE(list->head);
    FREE(list);
    return count;
}

static inline void
node_insert(skiplist* list, skip_node* x, skip_node** update)
{
    const unsigned nlinks = x->link_count;
    ASSERT(nlinks < list->max_link);

    if (list->top_link < nlinks) {
	for (unsigned k = list->top_link+1; k <= nlinks; k++) {
	    ASSERT(!update[k]);
	    update[k] = list->head;
	}
	list->top_link = nlinks;
    }

    x->prev = (update[0] == list->head) ? NULL : update[0];
    if (update[0]->link[0])
	update[0]->link[0]->prev = x;
    for (unsigned k = 0; k < nlinks; k++) {
	ASSERT(update[k]->link_count > k);
	x->link[k] = update[k]->link[k];
	update[k]->link[k] = x;
    }
    ++list->count;
}

dict_insert_result
skiplist_insert(skiplist* list, void* key)
{
    skip_node* x = list->head;
    skip_node* update[MAX_LINK] = { 0 };
    for (unsigned k = list->top_link+1; k-->0; ) {
	ASSERT(x->link_count > k);
	for (;;) {
	    skip_node* const y = x->link[k];
	    if (!y)
		break;
	    const int cmp = list->cmp_func(key, y->key);
	    if (cmp < 0) {
		while (k > 0 && x->link[k - 1] == y)
		    update[k--] = x;
		break;
	    } else if (cmp == 0)
		return (dict_insert_result) { &y->datum, false };
	    x = y;
	}
	update[k] = x;
    }

    x = node_new(key, rand_link_count(list));
    if (!x)
	return (dict_insert_result) { NULL, false };
    node_insert(list, x, update);
    return (dict_insert_result) { &x->datum, true };
}

static inline skip_node*
node_search(skiplist* list, const void* key)
{
    skip_node* x = list->head;
    for (unsigned k = list->top_link+1; k-->0;) {
	for (;;) {
	    skip_node* const y = x->link[k];
	    if (!y)
		break;
	    const int cmp = list->cmp_func(key, y->key);
	    if (cmp < 0) {
		while (k > 0 && x->link[k - 1] == y)
		    k--;
		break;
	    } else if (cmp == 0)
		return y;
	    x = y;
	}
    }
    return NULL;
}

static inline skip_node*
node_search_le(skiplist* list, const void* key)
{
    skip_node* x = list->head;
    for (unsigned k = list->top_link+1; k-->0;) {
	for (;;) {
	    skip_node* const y = x->link[k];
	    if (!y)
		break;
	    const int cmp = list->cmp_func(key, y->key);
	    if (cmp < 0) {
		while (k > 0 && x->link[k - 1] == y)
		    k--;
		break;
	    } else if (cmp == 0)
		return y;
	    x = y;
	}
    }
    return x == list->head ? NULL : x;
}

static inline skip_node*
node_search_lt(skiplist* list, const void* key)
{
    skip_node* x = list->head;
    for (unsigned k = list->top_link+1; k-->0;) {
	for (;;) {
	    skip_node* const y = x->link[k];
	    if (!y)
		break;
	    const int cmp = list->cmp_func(key, y->key);
	    if (cmp < 0) {
		while (k > 0 && x->link[k - 1] == y)
		    k--;
		break;
	    } else if (cmp == 0)
		return y->prev;
	    x = y;
	}
    }
    return x == list->head ? NULL : x;
}

static inline skip_node*
node_search_ge(skiplist* list, const void* key)
{
    skip_node* x = list->head;
    skip_node* ret = NULL;
    for (unsigned k = list->top_link+1; k-->0;) {
	for (;;) {
	    skip_node* const y = x->link[k];
	    if (!y)
		break;
	    const int cmp = list->cmp_func(key, y->key);
	    if (cmp < 0) {
		ret = y;
		while (k > 0 && x->link[k - 1] == y)
		    k--;
		break;
	    } else if (cmp == 0)
		return y;
	    x = y;
	}
    }
    return ret;
}

static inline skip_node*
node_search_gt(skiplist* list, const void* key)
{
    skip_node* x = list->head;
    skip_node* ret = NULL;
    for (unsigned k = list->top_link+1; k-->0;) {
	for (;;) {
	    skip_node* const y = x->link[k];
	    if (!y)
		break;
	    const int cmp = list->cmp_func(key, y->key);
	    if (cmp < 0) {
		ret = y;
		while (k > 0 && x->link[k - 1] == y)
		    k--;
		break;
	    } else if (cmp == 0)
		return y->link[0];
	    x = y;
	}
    }
    return ret;
}

void**
skiplist_search(skiplist* list, const void* key)
{
    skip_node* x = node_search(list, key);
    return x ? &x->datum : NULL;
}

void**
skiplist_search_le(skiplist* list, const void* key)
{
    skip_node* x = node_search_le(list, key);
    return x ? &x->datum : NULL;
}

void**
skiplist_search_lt(skiplist* list, const void* key)
{
    skip_node* x = node_search_lt(list, key);
    return x ? &x->datum : NULL;
}

void**
skiplist_search_ge(skiplist* list, const void* key)
{
    skip_node* x = node_search_ge(list, key);
    return x ? &x->datum : NULL;
}

void**
skiplist_search_gt(skiplist* list, const void* key)
{
    skip_node* x = node_search_gt(list, key);
    return x ? &x->datum : NULL;
}

dict_remove_result
skiplist_remove(skiplist* list, const void* key)
{
    skip_node* x = list->head;
    skip_node* update[MAX_LINK] = { 0 };
    bool found = false;
    for (unsigned k = list->top_link+1; k-->0;) {
	ASSERT(x->link_count > k);
	for (;;) {
	    skip_node* const y = x->link[k];
	    if (!y)
		break;
	    const int cmp = list->cmp_func(key, y->key);
	    if (cmp > 0)
		x = y;
	    else {
		while (k > 0 && x->link[k - 1] == y)
		    update[k--] = x;
		if (cmp == 0)
		    found = true;
		break;
	    }
	}
	update[k] = x;
    }
    if (!found)
	return (dict_remove_result) { NULL, NULL, false };
    x = x->link[0];
    for (unsigned k = 0; k <= list->top_link; k++) {
	ASSERT(update[k] != NULL);
	ASSERT(update[k]->link_count > k);
	if (update[k]->link[k] != x)
	    break;
	update[k]->link[k] = x->link[k];
    }
    if (x->prev)
	x->prev->link[0] = x->link[0];
    if (x->link[0])
	x->link[0]->prev = x->prev;
    dict_remove_result result = { x->key, x->datum, true };
    FREE(x);
    while (list->top_link > 0 && !list->head->link[list->top_link-1])
	list->top_link--;
    list->count--;
    return result;
}

size_t
skiplist_clear(skiplist* list, dict_delete_func delete_func)
{
    skip_node* node = list->head->link[0];
    while (node) {
	skip_node* next = node->link[0];
	if (delete_func)
	    delete_func(node->key, node->datum);
	FREE(node);
	node = next;
    }

    const size_t count = list->count;
    list->count = 0;
    list->head->link[list->top_link] = NULL;
    while (list->top_link)
	list->head->link[--list->top_link] = NULL;

    return count;
}

size_t
skiplist_traverse(skiplist* list, dict_visit_func visit, void* user_data)
{
    size_t count = 0;
    for (skip_node* node = list->head->link[0]; node; node = node->link[0]) {
	++count;
	if (!visit(node->key, node->datum, user_data))
	    break;
    }
    return count;
}

size_t
skiplist_count(const skiplist* list)
{
    return list->count;
}

bool
skiplist_verify(const skiplist* list)
{
    if (list->count == 0) {
	VERIFY(list->top_link == 0);
    } else {
	VERIFY(list->top_link > 0);
    }
    VERIFY(list->top_link < list->max_link);
    for (unsigned i = 0; i < list->top_link; ++i) {
	VERIFY(list->head->link[i] != NULL);
    }
    for (unsigned i = list->top_link; i < list->max_link; ++i) {
	VERIFY(list->head->link[i] == NULL);
    }
    unsigned observed_top_link = 0;

    skip_node* prev = NULL;
    skip_node* node = list->head->link[0];
    while (node) {
	if (observed_top_link < node->link_count)
	    observed_top_link = node->link_count;

	VERIFY(node->prev == prev);
	VERIFY(node->link_count >= 1);
	VERIFY(node->link_count <= list->top_link);
	for (unsigned k = 0; k < node->link_count; k++) {
	    if (node->link[k]) {
		VERIFY(node->link[k]->link_count >= k);
	    }
	}

	prev = node;
	node = node->link[0];
    }
    VERIFY(list->top_link == observed_top_link);
    return true;
}

size_t
skiplist_link_count_histogram(const skiplist* list, size_t counts[], size_t ncounts)
{
    for (size_t i = 0; i < ncounts; ++i)
	counts[i] = 0;

    size_t max_num_links = 0;
    for (const skip_node* node = list->head->link[0]; node; node = node->link[0]) {
	if (max_num_links < node->link_count)
	    max_num_links = node->link_count;
	if (ncounts > node->link_count)
	    counts[node->link_count]++;
    }
    return max_num_links;
}

skiplist_itor*
skiplist_itor_new(skiplist* list)
{
    skiplist_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	itor->list = list;
	itor->node = NULL;
    }
    return itor;
}

dict_itor*
skiplist_dict_itor_new(skiplist* list)
{
    dict_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	if (!(itor->_itor = skiplist_itor_new(list))) {
	    FREE(itor);
	    return NULL;
	}
	itor->_vtable = &skiplist_itor_vtable;
    }
    return itor;
}

void
skiplist_itor_free(skiplist_itor* itor)
{
    FREE(itor);
}

bool
skiplist_itor_valid(const skiplist_itor* itor)
{
    return itor->node != NULL;
}

void
skiplist_itor_invalidate(skiplist_itor* itor)
{
    itor->node = NULL;
}

bool
skiplist_itor_next(skiplist_itor* itor)
{
    if (itor->node)
	itor->node = itor->node->link[0];
    return itor->node != NULL;
}

bool
skiplist_itor_prev(skiplist_itor* itor)
{
    if (itor->node)
	itor->node = itor->node->prev;
    return itor->node != NULL;
}

bool
skiplist_itor_nextn(skiplist_itor* itor, size_t count)
{
    while (count--)
	if (!skiplist_itor_next(itor))
	    return false;
    return itor->node != NULL;
}

bool
skiplist_itor_prevn(skiplist_itor* itor, size_t count)
{
    while (count--)
	if (!skiplist_itor_prev(itor))
	    return false;
    return itor->node != NULL;
}

bool
skiplist_itor_first(skiplist_itor* itor)
{
    return (itor->node = itor->list->head->link[0]) != NULL;
}

bool
skiplist_itor_last(skiplist_itor* itor)
{
    skip_node* x = itor->list->head;
    for (unsigned k = itor->list->top_link; k-->0;) {
	while (x->link[k])
	    x = x->link[k];
    }
    if (x == itor->list->head) {
	itor->node = NULL;
	return false;
    } else {
	itor->node = x;
	return true;
    }
}

bool
skiplist_itor_search(skiplist_itor* itor, const void* key)
{
    return (itor->node = node_search(itor->list, key)) != NULL;
}

bool
skiplist_itor_search_le(skiplist_itor* itor, const void* key)
{
    return (itor->node = node_search_le(itor->list, key)) != NULL;
}

bool
skiplist_itor_search_lt(skiplist_itor* itor, const void* key)
{
    return (itor->node = node_search_lt(itor->list, key)) != NULL;
}

bool
skiplist_itor_search_ge(skiplist_itor* itor, const void* key)
{
    return (itor->node = node_search_ge(itor->list, key)) != NULL;
}

bool
skiplist_itor_search_gt(skiplist_itor* itor, const void* key)
{
    return (itor->node = node_search_gt(itor->list, key)) != NULL;
}

const void*
skiplist_itor_key(const skiplist_itor* itor)
{
    return itor->node ? itor->node->key : NULL;
}

void**
skiplist_itor_datum(skiplist_itor* itor)
{
    return itor->node ? &itor->node->datum : NULL;
}

int
skiplist_itor_compare(const skiplist_itor* itor1, const skiplist_itor* itor2)
{
    ASSERT(itor1->list == itor2->list);
    if (!itor1->node)
	return !itor2->node ? 0 : -1;
    if (!itor2->node)
	return 1;
    return itor1->list->cmp_func(itor1->node->key, itor2->node->key);
}

bool
skiplist_itor_remove(skiplist_itor* itor)
{
    if (!itor->node)
	return false;
    /* XXX make this smarter */
    dict_remove_result result = skiplist_remove(itor->list, itor->node->key);
    ASSERT(result.removed);
    itor->node = NULL;
    return true;
}

static inline skip_node*
node_new(void* key, unsigned link_count)
{
    ASSERT(link_count >= 1);

    skip_node* node = MALLOC(sizeof(*node) +
			     sizeof(node->link[0]) * link_count);
    if (node) {
	node->key = key;
	node->datum = NULL;
	node->prev = NULL;
	node->link_count = link_count;
	memset(node->link, 0, sizeof(node->link[0]) * link_count);
    }
    return node;
}

static inline unsigned
rand_link_count(skiplist* list)
{
    unsigned count = (unsigned) __builtin_ctz(dict_rand()) / 2 + 1;
    return (count >= list->max_link) ? list->max_link - 1 : count;
}
