/*
 * libdict -- generic dictionary implementation.
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

#include "dict_private.h"

#define XSTRINGIFY(x)	STRINGIFY(x)
#define STRINGIFY(x)	#x

const char* const kDictVersionString = XSTRINGIFY(DICT_VERSION_MAJOR) "."
				       XSTRINGIFY(DICT_VERSION_MINOR) "."
				       XSTRINGIFY(DICT_VERSION_PATCH);

void* (*dict_malloc_func)(size_t) = malloc;
void (*dict_free_func)(void*) = free;

int
dict_int_cmp(const void* k1, const void* k2)
{
    const int a = *(const int*)k1;
    const int b = *(const int*)k2;
    return (a > b) - (a < b);
}

int
dict_uint_cmp(const void* k1, const void* k2)
{
    const unsigned int a = *(const unsigned int*)k1;
    const unsigned int b = *(const unsigned int*)k2;
    return (a > b) - (a < b);
}

int
dict_long_cmp(const void* k1, const void* k2)
{
    const long a = *(const long*)k1;
    const long b = *(const long*)k2;
    return (a > b) - (a < b);
}

int
dict_ulong_cmp(const void* k1, const void* k2)
{
    const unsigned long a = *(const unsigned long*)k1;
    const unsigned long b = *(const unsigned long*)k2;
    return (a > b) - (a < b);
}

int
dict_ptr_cmp(const void* k1, const void* k2)
{
    return (k1 > k2) - (k1 < k2);
}

int
dict_str_cmp(const void* k1, const void* k2)
{
    const char* a = k1;
    const char* b = k2;

    for (;;) {
	char p = *a++, q = *b++;
	if (!p || p != q)
	    return (p > q) - (p < q);
    }
}

unsigned
dict_str_hash(const void* k)
{
    /* FNV 1-a string hash. */
    unsigned hash = 2166136261U;
    for (const uint8_t* ptr = k; *ptr;) {
	hash = (hash ^ *ptr++) * 16777619U;
    }
    return hash;
}

size_t
dict_free(dict* dct, dict_delete_func delete_func)
{
    ASSERT(dct != NULL);

    size_t count = dct->_vtable->dfree(dct->_object, delete_func);
    FREE(dct);
    return count;
}

void
dict_itor_free(dict_itor* itor)
{
    ASSERT(itor != NULL);

    itor->_vtable->ifree(itor->_itor);
    FREE(itor);
}
