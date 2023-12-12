/*
 * libdict -- splay tree interface.
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

#ifndef LIBDICT_SP_TREE_H__
#define LIBDICT_SP_TREE_H__

#include "dict.h"

BEGIN_DECL

typedef struct sp_tree sp_tree;

sp_tree*	sp_tree_new(dict_compare_func cmp_func);
dict*		sp_dict_new(dict_compare_func cmp_func);
size_t		sp_tree_free(sp_tree* tree, dict_delete_func delete_func);

dict_insert_result
		sp_tree_insert(sp_tree* tree, void* key);
void**		sp_tree_search(sp_tree* tree, const void* key);
void**		sp_tree_search_le(sp_tree* tree, const void* key);
void**		sp_tree_search_lt(sp_tree* tree, const void* key);
void**		sp_tree_search_ge(sp_tree* tree, const void* key);
void**		sp_tree_search_gt(sp_tree* tree, const void* key);
dict_remove_result
		sp_tree_remove(sp_tree* tree, const void* key);
size_t		sp_tree_clear(sp_tree* tree, dict_delete_func delete_func);
size_t		sp_tree_traverse(sp_tree* tree, dict_visit_func visit, void* user_data);
bool		sp_tree_select(sp_tree* tree, size_t n, const void** key, void** datum);
size_t		sp_tree_count(const sp_tree* tree);
size_t		sp_tree_min_path_length(const sp_tree* tree);
size_t		sp_tree_max_path_length(const sp_tree* tree);
size_t		sp_tree_total_path_length(const sp_tree* tree);
bool		sp_tree_verify(const sp_tree* tree);

typedef struct sp_itor sp_itor;

sp_itor*	sp_itor_new(sp_tree* tree);
dict_itor*	sp_dict_itor_new(sp_tree* tree);
void		sp_itor_free(sp_itor* tree);

bool		sp_itor_valid(const sp_itor* itor);
void		sp_itor_invalidate(sp_itor* itor);
bool		sp_itor_next(sp_itor* itor);
bool		sp_itor_prev(sp_itor* itor);
bool		sp_itor_nextn(sp_itor* itor, size_t count);
bool		sp_itor_prevn(sp_itor* itor, size_t count);
bool		sp_itor_first(sp_itor* itor);
bool		sp_itor_last(sp_itor* itor);
bool		sp_itor_search(sp_itor* itor, const void* key);
bool		sp_itor_search_le(sp_itor* itor, const void* key);
bool		sp_itor_search_lt(sp_itor* itor, const void* key);
bool		sp_itor_search_ge(sp_itor* itor, const void* key);
bool		sp_itor_search_gt(sp_itor* itor, const void* key);
const void*	sp_itor_key(const sp_itor* itor);
void**		sp_itor_datum(sp_itor* itor);
int             sp_itor_compare(const sp_itor* i1, const sp_itor* i2);
bool		sp_itor_remove(sp_itor* itor);

END_DECL

#endif /* !LIBDICT_SP_TREE_H__ */
