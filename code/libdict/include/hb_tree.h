/*
 * libdict -- height-balanced (AVL) tree interface.
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

#ifndef LIBDICT_HB_TREE_H__
#define LIBDICT_HB_TREE_H__

#include "dict.h"

BEGIN_DECL

typedef struct hb_tree hb_tree;

hb_tree*	hb_tree_new(dict_compare_func cmp_func);
dict*		hb_dict_new(dict_compare_func cmp_func);
size_t		hb_tree_free(hb_tree* tree, dict_delete_func delete_func);

dict_insert_result
		hb_tree_insert(hb_tree* tree, void* key);
void**		hb_tree_search(hb_tree* tree, const void* key);
void**		hb_tree_search_le(hb_tree* tree, const void* key);
void**		hb_tree_search_lt(hb_tree* tree, const void* key);
void**		hb_tree_search_ge(hb_tree* tree, const void* key);
void**		hb_tree_search_gt(hb_tree* tree, const void* key);
dict_remove_result
		hb_tree_remove(hb_tree* tree, const void* key);
size_t		hb_tree_clear(hb_tree* tree, dict_delete_func delete_func);
size_t		hb_tree_traverse(hb_tree* tree, dict_visit_func visit, void* user_data);
bool		hb_tree_select(hb_tree* tree, size_t n, const void** key, void** datum);
size_t		hb_tree_count(const hb_tree* tree);
size_t		hb_tree_min_path_length(const hb_tree* tree);
size_t		hb_tree_max_path_length(const hb_tree* tree);
size_t		hb_tree_total_path_length(const hb_tree* tree);
bool		hb_tree_verify(const hb_tree* tree);

typedef struct hb_itor hb_itor;

hb_itor*	hb_itor_new(hb_tree* tree);
dict_itor*	hb_dict_itor_new(hb_tree* tree);
void		hb_itor_free(hb_itor* tree);

bool		hb_itor_valid(const hb_itor* itor);
void		hb_itor_invalidate(hb_itor* itor);
bool		hb_itor_next(hb_itor* itor);
bool		hb_itor_prev(hb_itor* itor);
bool		hb_itor_nextn(hb_itor* itor, size_t count);
bool		hb_itor_prevn(hb_itor* itor, size_t count);
bool		hb_itor_first(hb_itor* itor);
bool		hb_itor_last(hb_itor* itor);
bool		hb_itor_search(hb_itor* itor, const void* key);
bool		hb_itor_search_le(hb_itor* itor, const void* key);
bool		hb_itor_search_lt(hb_itor* itor, const void* key);
bool		hb_itor_search_ge(hb_itor* itor, const void* key);
bool		hb_itor_search_gt(hb_itor* itor, const void* key);
const void*	hb_itor_key(const hb_itor* itor);
void**		hb_itor_datum(hb_itor* itor);
int		hb_itor_compare(const hb_itor* i1, const hb_itor* i2);
bool		hb_itor_remove(hb_itor* itor);

END_DECL

#endif /* !LIBDICT_HB_TREE_H__ */
