/*
 * libdict -- open-addressing hash-table interface.
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

#ifndef LIBDICT_HASHTABLE2_H__
#define LIBDICT_HASHTABLE2_H__

#include "dict.h"

BEGIN_DECL

typedef struct hashtable2 hashtable2;

hashtable2*	hashtable2_new(dict_compare_func cmp_func, dict_hash_func hash_func, unsigned initial_size);
dict*		hashtable2_dict_new(dict_compare_func cmp_func, dict_hash_func hash_func, unsigned initial_size);
size_t		hashtable2_free(hashtable2* table, dict_delete_func delete_func);

dict_insert_result
		hashtable2_insert(hashtable2* table, void* key);
void**		hashtable2_search(hashtable2* table, const void* key);
dict_remove_result
		hashtable2_remove(hashtable2* table, const void* key);
size_t		hashtable2_clear(hashtable2* table, dict_delete_func delete_func);
size_t		hashtable2_traverse(hashtable2* table, dict_visit_func visit, void* user_data);
size_t		hashtable2_count(const hashtable2* table);
size_t		hashtable2_size(const hashtable2* table);
size_t		hashtable2_slots_used(const hashtable2* table);
bool		hashtable2_verify(const hashtable2* table);
bool		hashtable2_resize(hashtable2* table, unsigned size);

typedef struct hashtable2_itor hashtable2_itor;

hashtable2_itor* hashtable2_itor_new(hashtable2* table);
dict_itor*	hashtable2_dict_itor_new(hashtable2* table);
void		hashtable2_itor_free(hashtable2_itor* itor);

bool		hashtable2_itor_valid(const hashtable2_itor* itor);
void		hashtable2_itor_invalidate(hashtable2_itor* itor);
bool		hashtable2_itor_next(hashtable2_itor* itor);
bool		hashtable2_itor_prev(hashtable2_itor* itor);
bool		hashtable2_itor_nextn(hashtable2_itor* itor, size_t count);
bool		hashtable2_itor_prevn(hashtable2_itor* itor, size_t count);
bool		hashtable2_itor_first(hashtable2_itor* itor);
bool		hashtable2_itor_last(hashtable2_itor* itor);
bool		hashtable2_itor_search(hashtable2_itor* itor, const void* key);
const void*	hashtable2_itor_key(const hashtable2_itor* itor);
void**		hashtable2_itor_datum(hashtable2_itor* itor);
bool		hashtable2_itor_remove(hashtable2_itor* itor);

END_DECL

#endif /* !LIBDICT_HASHTABLE2_H__ */
