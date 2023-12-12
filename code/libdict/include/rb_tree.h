/*
 * libdict -- red-black tree interface.
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

#ifndef LIBDICT_RB_TREE_H__
#define LIBDICT_RB_TREE_H__

#include "dict.h"

BEGIN_DECL

typedef struct rb_tree rb_tree;

rb_tree*	rb_tree_new(dict_compare_func cmp_func);
dict*		rb_dict_new(dict_compare_func cmp_func);
size_t		rb_tree_free(rb_tree* tree, dict_delete_func delete_func);

dict_insert_result
		rb_tree_insert(rb_tree* tree, void* key);
void**		rb_tree_search(rb_tree* tree, const void* key);
void**		rb_tree_search_le(rb_tree* tree, const void* key);
void**		rb_tree_search_lt(rb_tree* tree, const void* key);
void**		rb_tree_search_ge(rb_tree* tree, const void* key);
void**		rb_tree_search_gt(rb_tree* tree, const void* key);
dict_remove_result
		rb_tree_remove(rb_tree* tree, const void* key);
size_t		rb_tree_clear(rb_tree* tree, dict_delete_func delete_func);
size_t		rb_tree_traverse(rb_tree* tree, dict_visit_func visit, void* user_data);
bool		rb_tree_select(rb_tree* tree, size_t n, const void** key, void** datum);
size_t		rb_tree_count(const rb_tree* tree);
size_t		rb_tree_min_path_length(const rb_tree* tree);
size_t		rb_tree_max_path_length(const rb_tree* tree);
size_t		rb_tree_total_path_length(const rb_tree* tree);
bool		rb_tree_verify(const rb_tree* tree);

typedef struct rb_itor rb_itor;

rb_itor*	rb_itor_new(rb_tree* tree);
dict_itor*	rb_dict_itor_new(rb_tree* tree);
void		rb_itor_free(rb_itor* tree);

bool		rb_itor_valid(const rb_itor* itor);
void		rb_itor_invalidate(rb_itor* itor);
bool		rb_itor_next(rb_itor* itor);
bool		rb_itor_prev(rb_itor* itor);
bool		rb_itor_nextn(rb_itor* itor, size_t count);
bool		rb_itor_prevn(rb_itor* itor, size_t count);
bool		rb_itor_first(rb_itor* itor);
bool		rb_itor_last(rb_itor* itor);
bool		rb_itor_search(rb_itor* itor, const void* key);
bool		rb_itor_search_le(rb_itor* itor, const void* key);
bool		rb_itor_search_lt(rb_itor* itor, const void* key);
bool		rb_itor_search_ge(rb_itor* itor, const void* key);
bool		rb_itor_search_gt(rb_itor* itor, const void* key);
const void*	rb_itor_key(const rb_itor* itor);
void**		rb_itor_datum(rb_itor* itor);
int             rb_itor_compare(const rb_itor* i1, const rb_itor* i2);
bool		rb_itor_remove(rb_itor* itor);

END_DECL

#endif /* !LIBDICT_RB_TREE_H__ */
