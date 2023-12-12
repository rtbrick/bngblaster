/*
 * libdict -- weight-balanced tree implementation.
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
 * cf. [Gonnet 1984], [Nievergelt and Reingold 1973]
 */

#include "wb_tree.h"

#include <limits.h>
#include "dict_private.h"
#include "tree_common.h"

/* A tree BB[alpha] is said to be of weighted balance alpha if every node in
 * the tree has a balance p(n) such that alpha <= p(n) <= 1 - alpha. The
 * balance of a node is defined as the number of nodes in its left subtree
 * divided by the number of nodes in either subtree. The weight of a node is
 * defined as the number of external nodes in its subtrees.
 *
 * Legal values for alpha are 0 <= alpha <= 1/2. BB[0] is a normal, unbalanced
 * binary tree, and BB[1/2] includes only completely balanced binary search
 * trees of 2^height - 1 nodes. A higher value of alpha specifies a more
 * stringent balance requirement.
 *
 * Values for alpha in the range 2/11 <= alpha <= 1 - sqrt(2)/2 are interesting
 * because a tree can be brought back into weighted balance after an insertion or
 * deletion using at most one rotation per level (thus the number of rotations
 * after insertion or deletion is O(lg N)).
 *
 * These are the parameters for alpha = 1 - sqrt(2)/2 == .292893, as
 * recommended in [Gonnet 1984]. */

/* These constants are approximated by integer fractions in the code to
 * eliminate floating point arithmetic. */
#if 0
# define ALPHA_0	    .292893f	/* 1 - sqrt(2)/2    */
# define ALPHA_1	    .707106f	/* sqrt(2)/2	    */
# define ALPHA_2	    .414213f	/* sqrt(2) - 1	    */
# define ALPHA_3	    .585786f	/* 2 - sqrt(2)	    */
#endif

typedef struct wb_node wb_node;
struct wb_node {
    TREE_NODE_FIELDS(wb_node);
    uint32_t weight;
};

#define WEIGHT(n)	((n) ? (n)->weight : 1U)

struct wb_tree {
    TREE_FIELDS(wb_node);
};

struct wb_itor {
    TREE_ITERATOR_FIELDS(wb_tree, wb_node);
};

static const dict_vtable wb_tree_vtable = {
    true,
    (dict_inew_func)	    wb_dict_itor_new,
    (dict_dfree_func)	    tree_free,
    (dict_insert_func)	    wb_tree_insert,
    (dict_search_func)	    tree_search,
    (dict_search_func)	    tree_search_le,
    (dict_search_func)	    tree_search_lt,
    (dict_search_func)	    tree_search_ge,
    (dict_search_func)	    tree_search_gt,
    (dict_remove_func)	    wb_tree_remove,
    (dict_clear_func)	    tree_clear,
    (dict_traverse_func)    tree_traverse,
    (dict_select_func)	    wb_tree_select,
    (dict_count_func)	    tree_count,
    (dict_verify_func)	    wb_tree_verify,
};

static const itor_vtable wb_tree_itor_vtable = {
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
    (dict_iremove_func)	    wb_itor_remove,
    (dict_icompare_func)    tree_iterator_compare,
};

static wb_node*	node_new(void* key);

wb_tree*
wb_tree_new(dict_compare_func cmp_func)
{
    ASSERT(cmp_func != NULL);

    wb_tree* tree = MALLOC(sizeof(*tree));
    if (tree) {
	tree->root = NULL;
	tree->count = 0;
	tree->cmp_func = cmp_func;
	tree->rotation_count = 0;
    }
    return tree;
}

dict*
wb_dict_new(dict_compare_func cmp_func)
{
    dict* dct = MALLOC(sizeof(*dct));
    if (dct) {
	if (!(dct->_object = wb_tree_new(cmp_func))) {
	    FREE(dct);
	    return NULL;
	}
	dct->_vtable = &wb_tree_vtable;
    }
    return dct;
}

void** wb_tree_search(wb_tree* tree, const void* key) { return tree_search(tree, key); }
void** wb_tree_search_le(wb_tree* tree, const void* key) { return tree_search_le(tree, key); }
void** wb_tree_search_lt(wb_tree* tree, const void* key) { return tree_search_lt(tree, key); }
void** wb_tree_search_ge(wb_tree* tree, const void* key) { return tree_search_ge(tree, key); }
void** wb_tree_search_gt(wb_tree* tree, const void* key) { return tree_search_gt(tree, key); }

static inline unsigned
fixup(wb_tree* tree, wb_node* n)
{
    unsigned rotations = 0;
    unsigned weight = WEIGHT(n->llink);
    if (weight * 1000U < n->weight * 293U) {
	wb_node* nr = n->rlink;
	ASSERT(nr != NULL);
	wb_node* nrl = nr->llink;
	if (WEIGHT(nrl) * 1000U < nr->weight * 586U) {	/* LL */
	    /* Rotate |n| left. */
	    tree_node_rot_left(tree, n);
	    nr->weight = (n->weight = WEIGHT(n->llink) + WEIGHT(n->rlink)) +
			 WEIGHT(nr->rlink);
	    rotations += 1;
	} else {					/* RL */
	    /* Rotate |nr| right, then |n| left. */
	    ASSERT(nrl != NULL);
	    wb_node* const p = n->parent;
	    nrl->parent = p;
	    *(p ? (p->llink == n ? &p->llink : &p->rlink) : &tree->root) = nrl;

	    wb_node* const a = nrl->llink;
	    nrl->llink = n;
	    n->parent = nrl;
	    if ((n->rlink = a) != NULL)
		a->parent = n;

	    wb_node* const b = nrl->rlink;
	    nrl->rlink = nr;
	    nr->parent = nrl;
	    if ((nr->llink = b) != NULL)
		b->parent = nr;

	    nrl->weight = (n->weight = WEIGHT(n->llink) + WEIGHT(a)) +
			  (nr->weight = WEIGHT(b) + WEIGHT(nr->rlink));
	    rotations += 2;
	}
    } else if (weight * 1000U > n->weight * 707U) {
	wb_node* nl = n->llink;
	ASSERT(nl != NULL);
	weight = WEIGHT(nl->llink);
	if (weight * 1000U > nl->weight * 414U) {	/* RR */
	    tree_node_rot_right(tree, n);

	    n->weight = WEIGHT(n->llink) + WEIGHT(n->rlink);
	    nl->weight = weight + n->weight;
	    rotations += 1;
	} else {					/* LR */
	    /* Rotate |nl| left, then |n| right. */
	    wb_node* nlr = nl->rlink;
	    ASSERT(nlr != NULL);
	    wb_node* const p = n->parent;
	    nlr->parent = p;
	    *(p ? (p->llink == n ? &p->llink : &p->rlink) : &tree->root) = nlr;

	    wb_node* const a = nlr->llink;
	    nlr->llink = nl;
	    nl->parent = nlr;
	    if ((nl->rlink = a) != NULL)
		a->parent = nl;

	    wb_node* const b = nlr->rlink;
	    nlr->rlink = n;
	    n->parent = nlr;
	    if ((n->llink = b) != NULL)
		b->parent = n;

	    nlr->weight = (n->weight = WEIGHT(b) + WEIGHT(n->rlink)) +
			  (nl->weight = WEIGHT(nl->llink) + WEIGHT(a));
	    rotations += 2;
	}
    }
    return rotations;
}

dict_insert_result
wb_tree_insert(wb_tree* tree, void* key)
{
    int cmp = 0;

    wb_node* node = tree->root;
    wb_node* parent = NULL;
    while (node) {
	cmp = tree->cmp_func(key, node->key);
	if (cmp < 0) {
	    parent = node; node = node->llink;
	} else if (cmp) {
	    parent = node; node = node->rlink;
	} else
	    return (dict_insert_result) { &node->datum, false };
    }

    wb_node* const add = node = node_new(key);
    if (!add)
	return (dict_insert_result) { NULL, false };

    if (!(node->parent = parent)) {
	ASSERT(tree->count == 0);
	ASSERT(tree->root == NULL);
	tree->root = node;
    } else {
	if (cmp < 0)
	    parent->llink = node;
	else
	    parent->rlink = node;

	unsigned rotations = 0;
	while ((node = parent) != NULL) {
	    parent = node->parent;
	    ++node->weight;
	    rotations += fixup(tree, node);
	}
	tree->rotation_count += rotations;
    }
    tree->count++;
    return (dict_insert_result) { &add->datum, true };
}

static void
remove_node(wb_tree* tree, wb_node* node)
{
    if (node->llink && node->rlink) {
	wb_node* out;
	if (node->llink->weight > node->rlink->weight) {
	    out = tree_node_max(node->llink);
	} else {
	    out = tree_node_min(node->rlink);
	}
	void* tmp;
	SWAP(node->key, out->key, tmp);
	SWAP(node->datum, out->datum, tmp);
	node = out;
    }
    ASSERT(!node->llink || !node->rlink);
    /* Splice in the successor, if any. */
    wb_node* child = node->llink ? node->llink : node->rlink;
    wb_node* parent = node->parent;
    if (child)
	child->parent = parent;
    *(parent ? (parent->llink == node ? &parent->llink : &parent->rlink) : &tree->root) = child;
    FREE(node);
    tree->count--;
    /* Now move up the tree, decrementing weights. */
    unsigned rotations = 0;
    while (parent) {
	--parent->weight;
	wb_node* up = parent->parent;
	rotations += fixup(tree, parent);
	parent = up;
    }
    tree->rotation_count += rotations;
}

dict_remove_result
wb_tree_remove(wb_tree* tree, const void* key)
{
    wb_node* node = tree_search_node(tree, key);
    if (!node)
	return (dict_remove_result) { NULL, NULL, false };
    dict_remove_result result = { node->key, node->datum, true };
    remove_node(tree, node);
    return result;
}

size_t wb_tree_free(wb_tree* tree, dict_delete_func delete_func) { return tree_free(tree, delete_func); }
size_t wb_tree_clear(wb_tree* tree, dict_delete_func delete_func) { return tree_clear(tree, delete_func); }
size_t wb_tree_traverse(wb_tree* tree, dict_visit_func visit, void* user_data) { return tree_traverse(tree, visit, user_data); }

bool
wb_tree_select(wb_tree* tree, size_t n, const void** key, void** datum)
{
    if (n >= tree->count) {
	if (key)
	    *key = NULL;
	if (datum)
	    *datum = NULL;
	return false;
    }
    wb_node* node = tree->root;
    for (;;) {
	const unsigned nw = WEIGHT(node->llink);
	if (n + 1 >= nw) {
	    if (n + 1 == nw) {
		if (key)
		    *key = node->key;
		if (datum)
		    *datum = node->datum;
		return true;
	    }
	    n -= nw;
	    node = node->rlink;
	} else {
	    node = node->llink;
	}
    }
}

size_t wb_tree_count(const wb_tree* tree) { return tree_count(tree); }
size_t wb_tree_min_path_length(const wb_tree* tree) { return tree_min_path_length(tree); }
size_t wb_tree_max_path_length(const wb_tree* tree) { return tree_max_path_length(tree); }
size_t wb_tree_total_path_length(const wb_tree* tree) { return tree_total_path_length(tree); }

static wb_node*
node_new(void* key)
{
    wb_node* node = MALLOC(sizeof(*node));
    if (node) {
	node->key = key;
	node->datum = NULL;
	node->parent = NULL;
	node->llink = NULL;
	node->rlink = NULL;
	node->weight = 2;
    }
    return node;
}

static bool
node_verify(const wb_tree* tree, const wb_node* parent, const wb_node* node,
	    unsigned *weight)
{
    if (!parent) {
	VERIFY(tree->root == node);
    } else {
	VERIFY(parent->llink == node || parent->rlink == node);
    }
    if (node) {
	VERIFY(node->parent == parent);
	if (parent) {
	    if (parent->llink == node) {
		VERIFY(tree->cmp_func(parent->key, node->key) > 0);
	    } else {
		ASSERT(parent->rlink == node);
		VERIFY(tree->cmp_func(parent->key, node->key) < 0);
	    }
	}
	unsigned lweight, rweight;
	if (!node_verify(tree, node, node->llink, &lweight) ||
	    !node_verify(tree, node, node->rlink, &rweight))
	    return false;
	VERIFY(WEIGHT(node->llink) == lweight);
	VERIFY(WEIGHT(node->rlink) == rweight);
	VERIFY(node->weight == lweight + rweight);
	VERIFY(lweight * 1000U >= node->weight * 292U);
	VERIFY(lweight * 1000U <= node->weight * 708U);
	*weight = lweight + rweight;
    } else {
	*weight = 1;
    }
    return true;
}

bool
wb_tree_verify(const wb_tree* tree)
{
    if (tree->root) {
	VERIFY(tree->count > 0);
	VERIFY(tree->count + 1 == tree->root->weight);
    } else {
	VERIFY(tree->count == 0);
    }
    unsigned root_weight;
    return node_verify(tree, NULL, tree->root, &root_weight);
}

wb_itor*
wb_itor_new(wb_tree* tree)
{
    wb_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	itor->tree = tree;
	itor->node = NULL;
    }
    return itor;
}

dict_itor*
wb_dict_itor_new(wb_tree* tree)
{
    dict_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	if (!(itor->_itor = wb_itor_new(tree))) {
	    FREE(itor);
	    return NULL;
	}
	itor->_vtable = &wb_tree_itor_vtable;
    }
    return itor;
}

void wb_itor_free(wb_itor* itor) { tree_iterator_free(itor); }
bool wb_itor_valid(const wb_itor* itor) { return tree_iterator_valid(itor); }
void wb_itor_invalidate(wb_itor* itor) { tree_iterator_invalidate(itor); }
bool wb_itor_next(wb_itor* itor) { return tree_iterator_next(itor); }
bool wb_itor_prev(wb_itor* itor) { return tree_iterator_prev(itor); }
bool wb_itor_nextn(wb_itor* itor, size_t count) { return tree_iterator_nextn(itor, count); } /* TODO: speed up */
bool wb_itor_prevn(wb_itor* itor, size_t count) { return tree_iterator_prevn(itor, count); } /* TODO: speed up */
bool wb_itor_first(wb_itor* itor) { return tree_iterator_first(itor); }
bool wb_itor_last(wb_itor* itor) { return tree_iterator_last(itor); }
bool wb_itor_search(wb_itor* itor, const void* key) { return tree_iterator_search(itor, key); }
bool wb_itor_search_le(wb_itor* itor, const void* key) { return tree_iterator_search_le(itor, key); }
bool wb_itor_search_lt(wb_itor* itor, const void* key) { return tree_iterator_search_lt(itor, key); }
bool wb_itor_search_ge(wb_itor* itor, const void* key) { return tree_iterator_search_ge(itor, key); }
bool wb_itor_search_gt(wb_itor* itor, const void* key) { return tree_iterator_search_gt(itor, key); }
const void* wb_itor_key(const wb_itor* itor) { return tree_iterator_key(itor); }
void** wb_itor_datum(wb_itor* itor) { return tree_iterator_datum(itor); }
int wb_itor_compare(const wb_itor* i1, const wb_itor* i2) { return tree_iterator_compare(i1, i2); }

bool
wb_itor_remove(wb_itor* itor)
{
    if (!itor->node)
	return false;
    remove_node(itor->tree, itor->node);
    itor->node = NULL;
    return true;
}
