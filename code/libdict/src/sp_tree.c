/*
 * libdict -- splay tree implementation.
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
 * cf. [Sleator and Tarjan, 1985], [Tarjan 1985], [Tarjan 1983]
 *
 * A single operation on a splay tree has a worst-case time complexity of O(N),
 * but a series of M operations have a time complexity of O(M lg N), and thus
 * the amortized time complexity of an operation is O(lg N). More specifically,
 * a series of M operations on a tree with N nodes will runs in O((N+M)lg(N+M))
 * time. Splay trees work by "splaying" a node up the tree using a series of
 * rotations until it is the root each time it is accessed. They are much
 * simpler to code than most balanced trees, because there is no strict
 * requirement about maintaining a balance scheme among nodes. When inserting
 * and searching, we simply splay the node in question up until it becomes the
 * root of the tree.
 *
 * This implementation is a bottom-up, move-to-root splay tree.
 */

/* TODO: rather than splay after the fact, use the splay operation to traverse
 * the tree during insert, search, delete, etc. */

#include "sp_tree.h"

#include "dict_private.h"
#include "tree_common.h"

typedef struct sp_node sp_node;
struct sp_node {
    TREE_NODE_FIELDS(sp_node);
};

struct sp_tree {
    TREE_FIELDS(sp_node);
};

struct sp_itor {
    TREE_ITERATOR_FIELDS(sp_tree, sp_node);
};

static const dict_vtable sp_tree_vtable = {
    true,
    (dict_inew_func)	    sp_dict_itor_new,
    (dict_dfree_func)	    tree_free,
    (dict_insert_func)	    sp_tree_insert,
    (dict_search_func)	    sp_tree_search,
    (dict_search_func)	    sp_tree_search_le,
    (dict_search_func)	    sp_tree_search_lt,
    (dict_search_func)	    sp_tree_search_ge,
    (dict_search_func)	    sp_tree_search_gt,
    (dict_remove_func)	    sp_tree_remove,
    (dict_clear_func)	    tree_clear,
    (dict_traverse_func)    tree_traverse,
    (dict_select_func)	    tree_select,
    (dict_count_func)	    tree_count,
    (dict_verify_func)	    sp_tree_verify,
};

static const itor_vtable sp_tree_itor_vtable = {
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
    (dict_isearch_func)	    sp_itor_search,
    (dict_isearch_func)	    tree_iterator_search_le,
    (dict_isearch_func)	    tree_iterator_search_lt,
    (dict_isearch_func)	    tree_iterator_search_ge,
    (dict_isearch_func)	    tree_iterator_search_gt,
    (dict_iremove_func)	    sp_itor_remove,
    (dict_icompare_func)    tree_iterator_compare
};

static sp_node*	node_new(void* key);
static void	splay(sp_tree* t, sp_node* n);

sp_tree*
sp_tree_new(dict_compare_func cmp_func)
{
    ASSERT(cmp_func != NULL);

    sp_tree* tree = MALLOC(sizeof(*tree));
    if (tree) {
	tree->root = NULL;
	tree->count = 0;
	tree->cmp_func = cmp_func;
	tree->rotation_count = 0;
    }
    return tree;
}

dict*
sp_dict_new(dict_compare_func cmp_func)
{
    dict* dct = MALLOC(sizeof(*dct));
    if (dct) {
	if (!(dct->_object = sp_tree_new(cmp_func))) {
	    FREE(dct);
	    return NULL;
	}
	dct->_vtable = &sp_tree_vtable;
    }
    return dct;
}

size_t sp_tree_free(sp_tree* tree, dict_delete_func delete_func) { return tree_free(tree, delete_func); }
size_t sp_tree_clear(sp_tree* tree, dict_delete_func delete_func) { return tree_clear(tree, delete_func); }

static void
splay(sp_tree* t, sp_node* n)
{
    unsigned rotations = 0;
    for (;;) {
	sp_node* p = n->parent;
	if (!p)
	    break;

	sp_node* pp = p->parent;
	if (!pp) {
	    /* Parent is the root; simply rotate root left or right so that |n|
	     * becomes new root. */
	    if (p->llink == n) {
		if ((p->llink = n->rlink) != NULL)
		    p->llink->parent = p;
		n->rlink = p;
		++rotations;
	    } else {
		if ((p->rlink = n->llink) != NULL)
		    p->rlink->parent = p;
		n->llink = p;
	    }
	    p->parent = n;
	    t->root = n;
	    n->parent = NULL;
	    rotations += 1;
	    break;
	}

	rotations += 2;
	sp_node* ppp = pp->parent;
	if (p->llink == n) {
	    if (pp->llink == p) {
		/* Rotate parent right, then node right. */
		sp_node* const pr = p->rlink;
		p->rlink = pp;
		pp->parent = p;
		if ((pp->llink = pr) != NULL)
		    pr->parent = pp;

		sp_node* const nr = n->rlink;
		n->rlink = p;
		p->parent = n;
		if ((p->llink = nr) != NULL)
		    nr->parent = p;
	    } else {
		/* Rotate node right, then parent left. */
		sp_node* const nr = n->rlink;
		n->rlink = p;
		p->parent = n;
		if ((p->llink = nr) != NULL)
		    nr->parent = p;

		sp_node* const nl = n->llink;
		n->llink = pp;
		pp->parent = n;
		if ((pp->rlink = nl) != NULL)
		    nl->parent = pp;
	    }
	} else {
	    if (pp->rlink == p) {
		/* Rotate parent left, then node left. */
		sp_node* const pl = p->llink;
		p->llink = pp;
		pp->parent = p;
		if ((pp->rlink = pl) != NULL)
		    pl->parent = pp;

		sp_node* const nl = n->llink;
		n->llink = p;
		p->parent = n;
		if ((p->rlink = nl) != NULL)
		    nl->parent = p;
	    } else {
		/* Rotate node left, then parent right. */
		sp_node* const nl = n->llink;
		n->llink = p;
		p->parent = n;
		if ((p->rlink = nl) != NULL)
		    nl->parent = p;

		sp_node* const nr = n->rlink;
		n->rlink = pp;
		pp->parent = n;
		if ((pp->llink = nr) != NULL)
		    nr->parent = pp;
	    }
	}
	n->parent = ppp;
	if (ppp) {
	    if (ppp->llink == pp)
		ppp->llink = n;
	    else
		ppp->rlink = n;
	} else {
	    t->root = n;
	    break;
	}
    }
    t->rotation_count += rotations;
}

dict_insert_result
sp_tree_insert(sp_tree* tree, void* key)
{
    int cmp = 0;
    sp_node* node = tree->root;
    sp_node* parent = NULL;
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

    if (!(node->parent = parent)) {
	ASSERT(tree->count == 0);
	ASSERT(tree->root == NULL);
	tree->root = node;
	tree->count = 1;
    } else {
	if (cmp < 0)
	    parent->llink = node;
	else
	    parent->rlink = node;
	splay(tree, node);
	tree->count++;
    }
    ASSERT(tree->root == node);
    return (dict_insert_result) { &node->datum, true };
}

void**
sp_tree_search(sp_tree* tree, const void* key)
{
    sp_node* parent = NULL;
    for (sp_node* node = tree->root; node;) {
	parent = node;
	const int cmp = tree->cmp_func(key, node->key);
	if (cmp < 0)
	    node = node->llink;
	else if (cmp)
	    node = node->rlink;
	else {
	    splay(tree, node);
	    ASSERT(tree->root == node);
	    return &node->datum;
	}
    }
    if (parent)
	splay(tree, parent);
    return NULL;
}

void**
sp_tree_search_le(sp_tree* tree, const void* key)
{
    sp_node* node = tree_search_le_node(tree, key);
    if (node) {
	splay(tree, node);
	ASSERT(tree->root == node);
	return &node->datum;
    }
    return NULL;
}

void**
sp_tree_search_lt(sp_tree* tree, const void* key)
{
    sp_node* node = tree_search_lt_node(tree, key);
    if (node) {
	splay(tree, node);
	ASSERT(tree->root == node);
	return &node->datum;
    }
    return NULL;
}

void**
sp_tree_search_ge(sp_tree* tree, const void* key)
{
    sp_node* node = tree_search_ge_node(tree, key);
    if (node) {
	splay(tree, node);
	ASSERT(tree->root == node);
	return &node->datum;
    }
    return NULL;
}

void**
sp_tree_search_gt(sp_tree* tree, const void* key)
{
    sp_node* node = tree_search_gt_node(tree, key);
    if (node) {
	splay(tree, node);
	ASSERT(tree->root == node);
	return &node->datum;
    }
    return NULL;
}

static void
remove_node(sp_tree* tree, sp_node* node)
{
    sp_node* out;
    if (!node->llink || !node->rlink) {
	out = node;
    } else {
	out = tree_node_min(node->rlink);
	void* tmp;
	SWAP(node->key, out->key, tmp);
	SWAP(node->datum, out->datum, tmp);
    }

    sp_node* const temp = out->llink ? out->llink : out->rlink;
    sp_node* const parent = out->parent;
    FREE(out);
    if (temp)
	temp->parent = parent;

    *(parent ? (parent->llink == out ? &parent->llink : &parent->rlink) : &tree->root) = temp;
    if (parent)
	splay(tree, parent);
    tree->count--;
}

dict_remove_result
sp_tree_remove(sp_tree* tree, const void* key)
{
    sp_node* node = tree_search_node(tree, key);
    if (!node)
	return (dict_remove_result) { NULL, NULL, false };
    dict_remove_result result = { node->key, node->datum, true };
    remove_node(tree, node);
    return result;
}

size_t sp_tree_traverse(sp_tree* tree, dict_visit_func visit, void* user_data) { return tree_traverse(tree, visit, user_data); }
bool sp_tree_select(sp_tree* tree, size_t n, const void** key, void** datum) { return tree_select(tree, n, key, datum); }
size_t sp_tree_count(const sp_tree* tree) { return tree_count(tree); }
size_t sp_tree_min_path_length(const sp_tree* tree) { return tree_min_path_length(tree); }
size_t sp_tree_max_path_length(const sp_tree* tree) { return tree_max_path_length(tree); }
size_t sp_tree_total_path_length(const sp_tree* tree) { return tree_total_path_length(tree); }

static sp_node*
node_new(void* key)
{
    sp_node* node = MALLOC(sizeof(*node));
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
node_verify(const sp_tree* tree, const sp_node* parent, const sp_node* node)
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
	if (!node_verify(tree, node, node->llink) ||
	    !node_verify(tree, node, node->rlink))
	    return false;
    }
    return true;
}

bool
sp_tree_verify(const sp_tree* tree)
{
    if (tree->root) {
	VERIFY(tree->count > 0);
    } else {
	VERIFY(tree->count == 0);
    }
    return node_verify(tree, NULL, tree->root);
}

sp_itor*
sp_itor_new(sp_tree* tree)
{
    sp_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	itor->tree = tree;
	itor->node = NULL;
    }
    return itor;
}

dict_itor*
sp_dict_itor_new(sp_tree* tree)
{
    dict_itor* itor = MALLOC(sizeof(*itor));
    if (itor) {
	if (!(itor->_itor = sp_itor_new(tree))) {
	    FREE(itor);
	    return NULL;
	}
	itor->_vtable = &sp_tree_itor_vtable;
    }
    return itor;
}

void sp_itor_free(sp_itor* itor) { tree_iterator_free(itor); }
bool sp_itor_valid(const sp_itor* itor) { return tree_iterator_valid(itor); }
void sp_itor_invalidate(sp_itor* itor) { tree_iterator_invalidate(itor); }
bool sp_itor_next(sp_itor* itor) { return tree_iterator_next(itor); }
bool sp_itor_prev(sp_itor* itor) { return tree_iterator_prev(itor); }
bool sp_itor_nextn(sp_itor* itor, size_t count) { return tree_iterator_nextn(itor, count); }
bool sp_itor_prevn(sp_itor* itor, size_t count) { return tree_iterator_prevn(itor, count); }
bool sp_itor_first(sp_itor* itor) { return tree_iterator_first(itor); }
bool sp_itor_last(sp_itor* itor) { return tree_iterator_last(itor); }
/* TODO: use algorithm from sp_tree_search() */
bool sp_itor_search(sp_itor* itor, const void* key) { return tree_iterator_search(itor, key); }
bool sp_itor_search_le(sp_itor* itor, const void* key) { return tree_iterator_search_le(itor, key); }
bool sp_itor_search_lt(sp_itor* itor, const void* key) { return tree_iterator_search_lt(itor, key); }
bool sp_itor_search_ge(sp_itor* itor, const void* key) { return tree_iterator_search_ge(itor, key); }
bool sp_itor_search_gt(sp_itor* itor, const void* key) { return tree_iterator_search_gt(itor, key); }
const void* sp_itor_key(const sp_itor* itor) { return tree_iterator_key(itor); }
void** sp_itor_datum(sp_itor* itor) { return tree_iterator_datum(itor); }

int
sp_itor_compare(const sp_itor* i1, const sp_itor* i2)
{
    return tree_iterator_compare(i1, i2);
}

bool
sp_itor_remove(sp_itor* itor)
{
    if (!itor->node)
	return false;
    remove_node(itor->tree, itor->node);
    itor->node = NULL;
    return true;
}
