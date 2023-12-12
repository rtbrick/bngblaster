/*
 * libdict -- treap interface.
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

#ifndef LIBDICT_TR_TREE_H__
#define LIBDICT_TR_TREE_H__

#include "dict.h"

BEGIN_DECL

typedef struct tr_tree tr_tree;

tr_tree*	tr_tree_new(dict_compare_func compare_func, dict_prio_func prio_func);
dict*		tr_dict_new(dict_compare_func compare_func, dict_prio_func prio_func);
size_t		tr_tree_free(tr_tree* tree, dict_delete_func delete_func);

dict_insert_result
		tr_tree_insert(tr_tree* tree, void* key);
void**		tr_tree_search(tr_tree* tree, const void* key);
void**		tr_tree_search_le(tr_tree* tree, const void* key);
void**		tr_tree_search_lt(tr_tree* tree, const void* key);
void**		tr_tree_search_ge(tr_tree* tree, const void* key);
void**		tr_tree_search_gt(tr_tree* tree, const void* key);
dict_remove_result
		tr_tree_remove(tr_tree* tree, const void* key);
size_t		tr_tree_clear(tr_tree* tree, dict_delete_func delete_func);
size_t		tr_tree_traverse(tr_tree* tree, dict_visit_func visit, void* user_data);
bool		tr_tree_select(tr_tree* tree, size_t n, const void** key, void** datum);
size_t		tr_tree_count(const tr_tree* tree);
size_t		tr_tree_min_path_length(const tr_tree* tree);
size_t		tr_tree_max_path_length(const tr_tree* tree);
size_t		tr_tree_total_path_length(const tr_tree* tree);
bool		tr_tree_verify(const tr_tree* tree);

typedef struct tr_itor tr_itor;

tr_itor*	tr_itor_new(tr_tree* tree);
dict_itor*	tr_dict_itor_new(tr_tree* tree);
void		tr_itor_free(tr_itor* tree);

bool		tr_itor_valid(const tr_itor* itor);
void		tr_itor_invalidate(tr_itor* itor);
bool		tr_itor_next(tr_itor* itor);
bool		tr_itor_prev(tr_itor* itor);
bool		tr_itor_nextn(tr_itor* itor, size_t count);
bool		tr_itor_prevn(tr_itor* itor, size_t count);
bool		tr_itor_first(tr_itor* itor);
bool		tr_itor_last(tr_itor* itor);
bool		tr_itor_search(tr_itor* itor, const void* key);
bool		tr_itor_search_le(tr_itor* itor, const void* key);
bool		tr_itor_search_lt(tr_itor* itor, const void* key);
bool		tr_itor_search_ge(tr_itor* itor, const void* key);
bool		tr_itor_search_gt(tr_itor* itor, const void* key);
const void*	tr_itor_key(const tr_itor* itor);
void**		tr_itor_datum(tr_itor* itor);
int             tr_itor_compare(const tr_itor* i1, const tr_itor* i2);
bool		tr_itor_remove(tr_itor* itor);

END_DECL

#endif /* !LIBDICT_TR_TREE_H__ */
