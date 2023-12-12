/*
 * libdict -- hash-value sorted, chained hash-table interface.
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

#ifndef LIBDICT_HASHTABLE_H__
#define LIBDICT_HASHTABLE_H__

#include "dict.h"

BEGIN_DECL

typedef struct hashtable hashtable;

hashtable*	hashtable_new(dict_compare_func cmp_func, dict_hash_func hash_func, unsigned size);
dict*		hashtable_dict_new(dict_compare_func cmp_func, dict_hash_func hash_func, unsigned size);
size_t		hashtable_free(hashtable* table, dict_delete_func delete_func);

dict_insert_result
		hashtable_insert(hashtable* table, void* key);
void**		hashtable_search(hashtable* table, const void* key);
dict_remove_result
		hashtable_remove(hashtable* table, const void* key);
size_t		hashtable_clear(hashtable* table, dict_delete_func delete_func);
size_t		hashtable_traverse(hashtable* table, dict_visit_func visit, void* user_data);
size_t		hashtable_count(const hashtable* table);
size_t		hashtable_size(const hashtable* table);
size_t		hashtable_slots_used(const hashtable* table);
bool		hashtable_verify(const hashtable* table);
bool		hashtable_resize(hashtable* table, unsigned size);

typedef struct hashtable_itor hashtable_itor;

hashtable_itor* hashtable_itor_new(hashtable* table);
dict_itor*	hashtable_dict_itor_new(hashtable* table);
void		hashtable_itor_free(hashtable_itor* itor);

bool		hashtable_itor_valid(const hashtable_itor* itor);
void		hashtable_itor_invalidate(hashtable_itor* itor);
bool		hashtable_itor_next(hashtable_itor* itor);
bool		hashtable_itor_prev(hashtable_itor* itor);
bool		hashtable_itor_nextn(hashtable_itor* itor, size_t count);
bool		hashtable_itor_prevn(hashtable_itor* itor, size_t count);
bool		hashtable_itor_first(hashtable_itor* itor);
bool		hashtable_itor_last(hashtable_itor* itor);
bool		hashtable_itor_search(hashtable_itor* itor, const void* key);
const void*	hashtable_itor_key(const hashtable_itor* itor);
void**		hashtable_itor_datum(hashtable_itor* itor);
bool		hashtable_itor_remove(hashtable_itor* itor);

END_DECL

#endif /* !LIBDICT_HASHTABLE_H__ */
