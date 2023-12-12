/*
 * libdict -- skiplist interface.
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

#ifndef LIBDICT_SKIPLIST_H__
#define LIBDICT_SKIPLIST_H__

#include "dict.h"

BEGIN_DECL

typedef struct skiplist skiplist;

skiplist*	skiplist_new(dict_compare_func cmp_func, unsigned max_link);
dict*		skiplist_dict_new(dict_compare_func cmp_func, unsigned max_link);
size_t		skiplist_free(skiplist* list, dict_delete_func delete_func);

dict_insert_result
		skiplist_insert(skiplist* list, void* key);
void**		skiplist_search(skiplist* list, const void* key);
void**		skiplist_search_le(skiplist* list, const void* key);
void**		skiplist_search_lt(skiplist* list, const void* key);
void**		skiplist_search_ge(skiplist* list, const void* key);
void**		skiplist_search_gt(skiplist* list, const void* key);
dict_remove_result
		skiplist_remove(skiplist* list, const void* key);
size_t		skiplist_clear(skiplist* list, dict_delete_func delete_func);
size_t		skiplist_traverse(skiplist* list, dict_visit_func visit, void* user_data);
size_t		skiplist_count(const skiplist* list);
bool		skiplist_verify(const skiplist* list);

/* Compute the histogram of link counts of the skiplist.
 * For 0 < x < |ncounts|, |counts|[x] will be set to the number of nodes with x
 * links, and the maximal link count will be returned. If the return value is
 * greater than or equal to |ncounts|, not all link counts could be stored in
 * |counts| (i.e. the array was not large enough). */
size_t		skiplist_link_count_histogram(const skiplist* list,
					      size_t counts[], size_t ncounts);

typedef struct skiplist_itor skiplist_itor;

skiplist_itor*	skiplist_itor_new(skiplist* list);
dict_itor*	skiplist_dict_itor_new(skiplist* list);
void		skiplist_itor_free(skiplist_itor* );

bool		skiplist_itor_valid(const skiplist_itor* itor);
void		skiplist_itor_invalidate(skiplist_itor* itor);
bool		skiplist_itor_next(skiplist_itor* itor);
bool		skiplist_itor_prev(skiplist_itor* itor);
bool		skiplist_itor_nextn(skiplist_itor* itor, size_t count);
bool		skiplist_itor_prevn(skiplist_itor* itor, size_t count);
bool		skiplist_itor_first(skiplist_itor* itor);
bool		skiplist_itor_last(skiplist_itor* itor);
bool		skiplist_itor_search(skiplist_itor* itor, const void* key);
bool		skiplist_itor_search_le(skiplist_itor* itor, const void* key);
bool		skiplist_itor_search_lt(skiplist_itor* itor, const void* key);
bool		skiplist_itor_search_ge(skiplist_itor* itor, const void* key);
bool		skiplist_itor_search_gt(skiplist_itor* itor, const void* key);
const void*	skiplist_itor_key(const skiplist_itor* itor);
void**		skiplist_itor_datum(skiplist_itor* itor);
int             skiplist_itor_compare(const skiplist_itor* it1, const skiplist_itor* it2);
bool		skiplist_itor_remove(skiplist_itor* itor);

END_DECL

#endif /* !LIBDICT_SKIPLIST_H__ */
