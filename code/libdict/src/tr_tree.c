/*
 * libdict -- treap implementation.
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
 * cf. [Aragon and Seidel, 1996], [Knuth 1998]
 *
 * A treap is a randomized data structure in which each node of tree has an
 * associated key and priority. The priority is chosen at random when the node
 * is inserted into the tree. Each node is inserted so that the lexicographic
 * order of the keys is preserved, and the priority of any node is less than
 * the priority of either of its child nodes; in this way the treap is a
 * combination of a tree and a min-heap. In this implementation, this is
 * accomplished by first inserting the node according to lexigraphical order of
 * keys as in a normal binary tree, and then, if needed, sifting the node
 * upwards using a series of rotations until the heap property of the tree is
 * restored.
 */

#include "tr_tree.h"

#include <limits.h>
#include "dict_private.h"
#include "tree_common.h"

typedef struct tr_node tr_node;
struct tr_node {
    TREE_NODE_FIELDS(tr_node);
    uint32_t		    prio;
};

struct tr_tree {
    TREE_FIELDS(tr_node);
    dict_prio_func	    prio_func;
};

struct tr_itor {
    TREE_ITERATOR_FIELDS(tr_tree, tr_node);
};

static const dict_vtable tr_tree_vtable = {
    true,
    (dict_inew_func)	    tr_dict_itor_new,
    (dict_dfree_func)	    tree_free,
    (dict_insert_func)	    tr_tree_insert,
    (dict_search_func)	    tree_search,
    (dict_search_func)	    tree_search_le,
    (dict_search_func)	    tree_search_lt,
    (dict_search_func)	    tree_search_ge,
    (dict_search_func)	    tree_search_gt,
    (dict_remove_func)	    tr_tree_remove,
    (dict_clear_func)	    tree_clear,
    (dict_traverse_func)    tree_traverse,
    (dict_select_func)	    tree_select,
    (dict_count_func)	    tree_count,
    (dict_verify_func)	    tr_tree_verify,
};

static const itor_vtable tr_tree_itor_vtable = {
    (dict_ifree_func)	    tree_iterator_free,
    (dict_valid_func)	    tree_iterator_valid,
    (dict_invalidate_func)  tree_iterator_invalidate,
    (dict_next_func)	    tree_iterator_next,
    (dict_prev_func)	    tree_iterator_prev,
    (dict_nextn_func)	    tree_iterator_nextn,
    (dict_prevn_func)	    tree_iterator_prevn,
    (dict_first_func)	    tree_iterator_first,
    (dict_last_func)	    tree_iterator_last,
    (dict_key_func)	    tree_iterator_key,
    (dict_datum_func)	    tree_iterator_datum,
    (dict_isearch_func)	    tree_iterator_search,
    (dict_isearch_func)	    tree_iterator_search_le,
    (dict_isearch_func)	    tree_iterator_search_lt,
    (dict_isearch_func)	    tree_iterator_search_ge,
    (dict_isearch_func)	    tree_iterator_search_gt,
    (dict_iremove_func)	    tr_itor_remove,
    (dict_icompare_func)    tree_iterator_compare,
};

static tr_node*	node_new(void* key);

tr_tree*
tr_tree_new(dict_compare_func cmp_func, dict_prio_func prio_func)
{
    ASSERT(cmp_func != NULL);

    tr_tree* tree = MALLOC(sizeof(*tree));
    if (tree) {
	tree->root = NULL;
	tree->count = 0;
	tree->cmp_func = cmp_func;
	tree->rotation_count = 0;
	tree->prio_func = prio_func;
    }
    return tree;
}

dict*
tr_dict_new(dict_compare_func cmp_func, dict_prio_func prio_func)
{
    dict* dct = MALLOC(sizeof(*dct));
    if (dct) {
	if (!(dct->_object = tr_tree_new(cmp_func, prio_func))) {
	    FREE(dct);
	    return NULL;
	}
	dct->_vtable = &tr_tree_vtable;
    }
    return dct;
}

size_t tr_tree_free(tr_tree* tree, dict_delete_func delete_func) { return tree_free(tree, delete_func); }
size_t tr_tree_clear(tr_tree* tree, dict_delete_func delete_func) { return tree_clear(tree, delete_func); }

dict_insert_result
tr_tree_insert(tr_tree* tree, void* key)
{
    int cmp = 0;
    tr_node* node = tree->root;
    tr_node* parent = NULL;
    while (node) {
	cmp = tree->cmp_func(key, node->key);
	if (cmp < 0) {
	    parent = node; node = node->llink;
	} else if (cmp > 0) {
	    parent = node; node = node->rlink;
	} else
	    return (dict_insert_result) { &node->datum, false };
    }

    if (!(node = node_new(key)))
	return (dict_insert_result) { NULL, false };
    node->prio = tree->prio_func ? tree->prio_func(key) : dict_rand();

    if (!(node->parent = parent)) {
	ASSERT(tree->root == NULL);
	ASSERT(tree->count == 0);
	tree->root = node;
    } else {
	if (cmp < 0)
	    parent->llink = node;
	else
	    parent->rlink = node;

	unsigned rotations = 0;
	while (parent->prio < node->prio) {
	    ++rotations;
	    if (parent->llink == node)
		tree_node_rot_right(tree, parent);
	    else
		tree_node_rot_left(tree, parent);
	    if (!(parent = node->parent))
		break;
	}
	tree->rotation_count += rotations;
    }
    tree->count++;
    return (dict_insert_result) { &node->datum, true };
}

static void
remove_node(tr_tree* tree, tr_node* node)
{
    unsigned rotations = 0;
    while (node->llink && node->rlink) {
	++rotations;
	if (node->llink->prio > node->rlink->prio)
	    tree_node_rot_right(tree, node);
	else
	    tree_node_rot_left(tree, node);
    }
    tree->rotation_count += rotations;

    tr_node* const out = node->llink ? node->llink : node->rlink;
    tr_node* const parent = node->parent;
    if (out)
	out->parent = parent;
    *(parent ? (parent->llink == node ? &parent->llink : &parent->rlink) : &tree->root) = out;

    FREE(node);
    tree->count--;
}

dict_remove_result
tr_tree_remove(tr_tree* tree, const void* key)
{
    tr_node* node = tree_search_node(tree, key);
    if (!node)
	return (dict_remove_result) { NULL, NULL, false };
    dict_remove_result result = { node->key, node->datum, true };
    remove_node(tree, node);
    return result;
}

void** tr_tree_search(tr_tree* tree, const void* key) { return tree_search(tree, key); }
void** tr_tree_search_le(tr_tree* tree, const void* key) { return tree_search_le(tree, key); }
void** tr_tree_search_lt(tr_tree* tree, const void* key) { return tree_search_lt(tree, key); }
void** tr_tree_search_ge(tr_tree* tree, const void* key) { return tree_search_ge(tree, key); }
void** tr_tree_search_gt(tr_tree* tree, const void* key) { return tree_search_gt(tree, key); }
size_t tr_tree_traverse(tr_tree* tree, dict_visit_func visit, void* user_data) { return tree_traverse(tree, visit, user_data); }
bool tr_tree_select(tr_tree* tree, size_t n, const void** key, void** datum) { return tree_select(tree, n, key, datum); }
size_t tr_tree_count(const tr_tree* tree) { return tree_count(tree); }
size_t tr_tree_min_path_length(const tr_tree* tree) { return tree_min_path_length(tree); }
size_t tr_tree_max_path_length(const tr_tree* tree) { return tree_max_path_length(tree); }
size_t tr_tree_total_path_length(const tr_tree* tree) { return tree_total_path_length(tree); }

static tr_node*
node_new(void* key)
{
    tr_node* node = MALLOC(sizeof(*node));
    if (node) {
	node->key = key;
	node->datum = NULL;
	node->parent = NULL;
	node->llink = NULL;
	node->rlink = NULL;
    }
    return node;
}

static bool
node_verify(const tr_tree* tree, const tr_node* parent, const tr_node* node)
{
    if (!parent) {
	VERIFY(tree->root == node);
    } else {
	VERIFY(parent->llink == node || parent->rlink == node);
    }
    if (node) {
	VERIFY(node->parent == parent);
	if (parent) {
	    VERIFY(node->prio <= parent->prio);
	    if (parent->llink == node) {
		VERIFY(tree->cmp_func(parent->key, node->key) > 0);
	    } else {
		ASSERT(parent->rlink == node);
		VERIFY(tree->cmp_func(parent->key, node->key) < 0);
	    }
	}
	if (!node_verify(tree, node, node->llink) ||
	    !node_verify(tree, node, node->rlink))
	    return false;
    }
    return true;
}

bool
tr_tree_verify(const tr_tree* tree)
{
    if (tree->root) {
	VERIFY(tree->count > 0);
    } else {
	VERIFY(tree->count == 0);
    }
    return node_verify(tree, NULL, tree->root);
}

tr_itor*
tr_itor_new(tr_tree* tree)
{
    tr_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	itor->tree = tree;
	itor->node = NULL;
    }
    return itor;
}

dict_itor*
tr_dict_itor_new(tr_tree* tree)
{
    dict_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	if (!(itor->_itor = tr_itor_new(tree))) {
	    FREE(itor);
	    return NULL;
	}
	itor->_vtable = &tr_tree_itor_vtable;
    }
    return itor;
}

void tr_itor_free(tr_itor* itor) { tree_iterator_free(itor); }
bool tr_itor_valid(const tr_itor* itor) { return tree_iterator_valid(itor); }
void tr_itor_invalidate(tr_itor* itor) { tree_iterator_invalidate(itor); }
bool tr_itor_next(tr_itor* itor) { return tree_iterator_next(itor); }
bool tr_itor_prev(tr_itor* itor) { return tree_iterator_prev(itor); }
bool tr_itor_nextn(tr_itor* itor, size_t count) { return tree_iterator_nextn(itor, count); }
bool tr_itor_prevn(tr_itor* itor, size_t count) { return tree_iterator_prevn(itor, count); }
bool tr_itor_first(tr_itor* itor) { return tree_iterator_first(itor); }
bool tr_itor_last(tr_itor* itor) { return tree_iterator_last(itor); }
bool tr_itor_search(tr_itor* itor, const void* key) { return tree_iterator_search(itor, key); }
bool tr_itor_search_le(tr_itor* itor, const void* key) { return tree_iterator_search_le(itor, key); }
bool tr_itor_search_lt(tr_itor* itor, const void* key) { return tree_iterator_search_lt(itor, key); }
bool tr_itor_search_ge(tr_itor* itor, const void* key) { return tree_iterator_search_ge(itor, key); }
bool tr_itor_search_gt(tr_itor* itor, const void* key) { return tree_iterator_search_gt(itor, key); }
const void* tr_itor_key(const tr_itor* itor) { return tree_iterator_key(itor); }
void** tr_itor_datum(tr_itor* itor) { return tree_iterator_datum(itor); }
int tr_itor_compare(const tr_itor* i1, const tr_itor* i2) { return tree_iterator_compare(i1, i2); }

bool
tr_itor_remove(tr_itor* it)
{
    if (!it->node)
	return false;
    remove_node(it->tree, it->node);
    it->node = NULL;
    return true;
}
