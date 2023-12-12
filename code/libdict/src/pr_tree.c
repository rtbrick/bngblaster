/*
 * libdict -- internal path reduction tree implementation.
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
 * cf. [Gonnet 1983], [Gonnet 1984]
 */

#include "pr_tree.h"

#include "dict_private.h"
#include "tree_common.h"

typedef struct pr_node pr_node;
struct pr_node {
    TREE_NODE_FIELDS(pr_node);
    unsigned weight;
};

#define WEIGHT(n)	((n) ? (n)->weight : 1)

struct pr_tree {
    TREE_FIELDS(pr_node);
};

struct pr_itor {
    TREE_ITERATOR_FIELDS(pr_tree, pr_node);
};

static const dict_vtable pr_tree_vtable = {
    true,
    (dict_inew_func)	    pr_dict_itor_new,
    (dict_dfree_func)	    tree_free,
    (dict_insert_func)	    pr_tree_insert,
    (dict_search_func)	    tree_search,
    (dict_search_func)	    tree_search_le,
    (dict_search_func)	    tree_search_lt,
    (dict_search_func)	    tree_search_ge,
    (dict_search_func)	    tree_search_gt,
    (dict_remove_func)	    pr_tree_remove,
    (dict_clear_func)	    tree_clear,
    (dict_traverse_func)    tree_traverse,
    (dict_select_func)	    pr_tree_select,
    (dict_count_func)	    tree_count,
    (dict_verify_func)	    pr_tree_verify,
};

static const itor_vtable pr_tree_itor_vtable = {
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
    (dict_iremove_func)	    pr_itor_remove,
    (dict_icompare_func)    tree_iterator_compare,
};

static unsigned	fixup(pr_tree* tree, pr_node* node);
static void	rot_left(pr_tree* tree, pr_node* node);
static void	rot_right(pr_tree* tree, pr_node* node);
static pr_node*	node_new(void* key);

pr_tree*
pr_tree_new(dict_compare_func cmp_func)
{
    ASSERT(cmp_func != NULL);

    pr_tree* tree = MALLOC(sizeof(*tree));
    if (tree) {
	tree->root = NULL;
	tree->count = 0;
	tree->cmp_func = cmp_func;
	tree->rotation_count = 0;
    }
    return tree;
}

dict*
pr_dict_new(dict_compare_func cmp_func)
{
    dict* dct = MALLOC(sizeof(*dct));
    if (dct) {
	if (!(dct->_object = pr_tree_new(cmp_func))) {
	    FREE(dct);
	    return NULL;
	}
	dct->_vtable = &pr_tree_vtable;
    }
    return dct;
}

size_t pr_tree_free(pr_tree* tree, dict_delete_func delete_func) { return tree_free(tree, delete_func); }
void** pr_tree_search(pr_tree* tree, const void* key) { return tree_search(tree, key); }
void** pr_tree_search_le(pr_tree* tree, const void* key) { return tree_search_le(tree, key); }
void** pr_tree_search_lt(pr_tree* tree, const void* key) { return tree_search_lt(tree, key); }
void** pr_tree_search_ge(pr_tree* tree, const void* key) { return tree_search_ge(tree, key); }
void** pr_tree_search_gt(pr_tree* tree, const void* key) { return tree_search_gt(tree, key); }

static unsigned
fixup(pr_tree* tree, pr_node* node)
{
    /*
     * The internal path length of a tree is defined as the sum of levels of
     * all the tree's internal nodes. Path-reduction trees are similar to
     * weight-balanced trees, except that rotations are only made when they can
     * reduce the total internal path length of the tree. These particular
     * trees are in the class BB[1/3], but because of these restrictions their
     * performance is superior to BB[1/3] trees.
     *
     * Consider a node N.
     * A single left rotation is performed when
     * WEIGHT(n->llink) < WEIGHT(n->rlink->rlink)
     * A right-left rotation is performed when
     * WEIGHT(n->llink) < WEIGHT(n->rlink->llink)
     *
     * A single right rotation is performed when
     * WEIGHT(n->rlink) > WEIGHT(n->llink->llink)
     * A left-right rotation is performed when
     * WEIGHT(n->rlink) > WEIGHT(n->llink->rlink)
     *
     * Although the worst case number of rotations for a single insertion or
     * deletion is O(n), the amortized worst-case number of rotations is
     * .44042lg(n) + O(1) for insertion, and .42062lg(n) + O(1) for deletion.
     *
     * We use tail recursion to minimize the number of recursive calls. For
     * single rotations, no recursive call is made, and we tail recurse to
     * continue checking for out-of-balance conditions. For double, we make one
     * recursive call and then tail recurse.
     */
    unsigned rotations = 0;
    const unsigned lweight = WEIGHT(node->llink);
    const unsigned rweight = WEIGHT(node->rlink);
    if (lweight < rweight) {
	pr_node* r = node->rlink;
	ASSERT(r != NULL);
	if (WEIGHT(r->rlink) > lweight) {	    /* LL */
	    rot_left(tree, node);
	    rotations += 1;
	    rotations += fixup(tree, node);
	    /* Commenting the next line means we must make the weight
	     * verification condition in node_verify() less stringent. */
	    rotations += fixup(tree, r);
	} else if (WEIGHT(r->llink) > lweight) {    /* RL */
	    /* Rotate |r| right, then |node| left, with |rl| taking the place
	     * of |node| and having |node| and |r| as left and right children,
	     * respectively. */
	    pr_node* const rl = r->llink;
	    pr_node* const parent = node->parent;

	    pr_node* const a = rl->llink;
	    rl->llink = node;
	    node->parent = rl;
	    if ((node->rlink = a) != NULL)
		a->parent = node;

	    pr_node* const b = rl->rlink;
	    rl->rlink = r;
	    r->parent = rl;
	    if ((r->llink = b) != NULL)
		b->parent = r;

	    rl->parent = parent;
	    *(parent ? (parent->llink == node ? &parent->llink : &parent->rlink) : &tree->root) = rl;

	    node->weight += WEIGHT(a) - r->weight;
	    r->weight += WEIGHT(b) - rl->weight;
	    rl->weight = node->weight + r->weight;

	    rotations += 1;
	    rotations += fixup(tree, r);
	    rotations += fixup(tree, node);
	}
    } else if (lweight > rweight) {
	pr_node* l = node->llink;
	ASSERT(l != NULL);
	if (WEIGHT(l->llink) > rweight) {	    /* RR */
	    rot_right(tree, node);
	    rotations += 1;
	    rotations += fixup(tree, node);
	    /* Commenting the next line means we must turn the weight
	     * verification condition in node_verify() less stringent. */
	    rotations += fixup(tree, l);
	} else if (WEIGHT(l->rlink) > rweight) {    /* LR */
	    /* Rotate |l| left, then |node| right, with |lr| taking the place of
	     * |node| and having |l| and |node| as left and right children,
	     * respectively. */
	    pr_node* const lr = l->rlink;
	    pr_node* const parent = node->parent;

	    pr_node* const a = lr->llink;
	    lr->llink = l;
	    l->parent = lr;
	    if ((l->rlink = a) != NULL)
		a->parent = l;

	    pr_node* const b = lr->rlink;
	    lr->rlink = node;
	    node->parent = lr;
	    if ((node->llink = b) != NULL)
		b->parent = node;

	    lr->parent = parent;
	    *(parent ? (parent->llink == node ? &parent->llink : &parent->rlink) : &tree->root) = lr;

	    node->weight += WEIGHT(b) - l->weight;
	    l->weight += WEIGHT(a) - lr->weight;
	    lr->weight = node->weight + l->weight;

	    rotations += 2;
	    rotations += fixup(tree, l);
	    rotations += fixup(tree, node);
	}
    }
    return rotations;
}

dict_insert_result
pr_tree_insert(pr_tree* tree, void* key)
{
    int cmp = 0;
    pr_node* node = tree->root;
    pr_node* parent = NULL;
    while (node) {
	cmp = tree->cmp_func(key, node->key);
	if (cmp < 0) {
	    parent = node; node = node->llink;
	} else if (cmp > 0) {
	    parent = node; node = node->rlink;
	} else
	    return (dict_insert_result) { &node->datum, false };
    }

    pr_node* add = node_new(key);
    if (!add)
	return (dict_insert_result) { NULL, false };
    if (!(add->parent = parent)) {
	ASSERT(tree->count == 0);
	ASSERT(tree->root == NULL);
	tree->root = add;
    } else {
	if (cmp < 0)
	    parent->llink = add;
	else
	    parent->rlink = add;

	unsigned rotations = 0;
	while ((node = parent) != NULL) {
	    parent = parent->parent;
	    ++node->weight;
	    rotations += fixup(tree, node);
	}
	tree->rotation_count += rotations;
    }
    tree->count++;
    return (dict_insert_result) { &add->datum, true };
}

static void
remove_node(pr_tree* tree, pr_node* node)
{
    if (node->llink && node->rlink) {
	pr_node* out;
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
    pr_node* child = node->llink ? node->llink : node->rlink;
    pr_node* parent = node->parent;
    if (child)
	child->parent = parent;
    *(parent ? (parent->llink == node ? &parent->llink : &parent->rlink) : &tree->root) = child;
    FREE(node);
    tree->count--;
    /* Now move up the tree, decrementing weights. */
    unsigned rotations = 0;
    while (parent) {
	--parent->weight;
	pr_node* up = parent->parent;
	rotations += fixup(tree, parent);
	parent = up;
    }
    tree->rotation_count += rotations;
}

dict_remove_result
pr_tree_remove(pr_tree* tree, const void* key)
{
    pr_node* node = tree_search_node(tree, key);
    if (!node)
	return (dict_remove_result) { NULL, NULL, false };
    dict_remove_result result = { node->key, node->datum, true };
    remove_node(tree, node);
    return result;
}

size_t pr_tree_clear(pr_tree* tree, dict_delete_func delete_func) { return tree_clear(tree, delete_func); }

size_t
pr_tree_traverse(pr_tree* tree, dict_visit_func visit, void* user_data)
{
    return tree_traverse(tree, visit, user_data);
}

bool
pr_tree_select(pr_tree* tree, size_t n, const void** key, void** datum)
{
    if (n >= tree->count) {
	if (key)
	    *key = NULL;
	if (datum)
	    *datum = NULL;
	return false;
    }
    pr_node* node = tree->root;
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

size_t pr_tree_count(const pr_tree* tree) { return tree_count(tree); }
size_t pr_tree_max_path_length(const pr_tree* tree) { return tree_max_path_length(tree); }
size_t pr_tree_min_path_length(const pr_tree* tree) { return tree_min_path_length(tree); }
size_t pr_tree_total_path_length(const pr_tree* tree) { return tree_total_path_length(tree); }

static pr_node*
node_new(void* key)
{
    pr_node* node = MALLOC(sizeof(*node));
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

/*
 * rot_left(T, B):
 *
 *     /	     /
 *    B	     D
 *   / \	   / \
 *  A   D   ==>   B   E
 *     / \       / \
 *    C   E     A   C
 *
 * Only the weights of B and B's right child to be readjusted.
 */
static void
rot_left(pr_tree* tree, pr_node	*node)
{
    ASSERT(node->rlink != NULL);

    pr_node* rlink = node->rlink;
    tree_node_rot_left(tree, node);

    node->weight = WEIGHT(node->llink) + WEIGHT(node->rlink);
    rlink->weight = node->weight + WEIGHT(rlink->rlink);
}

/*
 * rot_right(T, D):
 *
 *       /	   /
 *      D	   B
 *     / \	 / \
 *    B   E  ==>  A   D
 *   / \	     / \
 *  A   C	   C   E
 *
 * Only the weights of D and D's left child need to be readjusted.
 */
static void
rot_right(pr_tree* tree, pr_node* node)
{
    ASSERT(node->llink != NULL);

    pr_node* llink = node->llink;
    tree_node_rot_right(tree, node);

    node->weight = WEIGHT(node->llink) + WEIGHT(node->rlink);
    llink->weight = WEIGHT(llink->llink) + node->weight;
}

static bool
node_verify(const pr_tree* tree, const pr_node* parent, const pr_node* node)
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
	pr_node* l = node->llink;
	pr_node* r = node->rlink;
	if (!node_verify(tree, node, l) ||
	    !node_verify(tree, node, r))
	    return false;
	unsigned lweight = WEIGHT(l);
	unsigned rweight = WEIGHT(r);
	VERIFY(node->weight == lweight + rweight);
	if (rweight > lweight) {
	    VERIFY(WEIGHT(r->rlink) <= lweight);
	    VERIFY(WEIGHT(r->llink) <= lweight);
	} else if (lweight > rweight) {
	    VERIFY(WEIGHT(l->llink) <= rweight);
	    VERIFY(WEIGHT(l->rlink) <= rweight);
	}
    }
    return true;
}

bool
pr_tree_verify(const pr_tree* tree)
{
    if (tree->root) {
	VERIFY(tree->count > 0);
    } else {
	VERIFY(tree->count == 0);
    }
    return node_verify(tree, NULL, tree->root);
}

pr_itor*
pr_itor_new(pr_tree* tree)
{
    pr_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	itor->tree = tree;
	itor->node = NULL;
    }
    return itor;
}

dict_itor*
pr_dict_itor_new(pr_tree* tree)
{

    dict_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	if (!(itor->_itor = pr_itor_new(tree))) {
	    FREE(itor);
	    return NULL;
	}
	itor->_vtable = &pr_tree_itor_vtable;
    }
    return itor;
}

void pr_itor_free(pr_itor* itor) { tree_iterator_free(itor); }
bool pr_itor_valid(const pr_itor* itor) { return tree_iterator_valid(itor); }
void pr_itor_invalidate(pr_itor* itor) { tree_iterator_invalidate(itor); }
bool pr_itor_next(pr_itor* itor) { return tree_iterator_next(itor); }
bool pr_itor_prev(pr_itor* itor) { return tree_iterator_prev(itor); }
bool pr_itor_nextn(pr_itor* itor, size_t count) { return tree_iterator_nextn(itor, count); } /* TODO: speed up */
bool pr_itor_prevn(pr_itor* itor, size_t count) { return tree_iterator_prevn(itor, count); } /* TODO: speed up */
bool pr_itor_first(pr_itor* itor) { return tree_iterator_first(itor); }
bool pr_itor_last(pr_itor* itor) { return tree_iterator_last(itor); }
bool pr_itor_search(pr_itor* itor, const void* key) { return tree_iterator_search(itor, key); }
bool pr_itor_search_le(pr_itor* itor, const void* key) { return tree_iterator_search_le(itor, key); }
bool pr_itor_search_lt(pr_itor* itor, const void* key) { return tree_iterator_search_lt(itor, key); }
bool pr_itor_search_ge(pr_itor* itor, const void* key) { return tree_iterator_search_ge(itor, key); }
bool pr_itor_search_gt(pr_itor* itor, const void* key) { return tree_iterator_search_gt(itor, key); }
const void* pr_itor_key(const pr_itor* itor) { return tree_iterator_key(itor); }
void** pr_itor_datum(pr_itor* itor) { return tree_iterator_datum(itor); }
int pr_itor_compare(const pr_itor* i1, const pr_itor* i2) { return tree_iterator_compare(i1, i2); }

bool
pr_itor_remove(pr_itor* it)
{
    if (!it->node)
	return false;
    remove_node(it->tree, it->node);
    it->node = NULL;
    return true;
}
