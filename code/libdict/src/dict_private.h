/*
 * libdict - private definitions.
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

#ifndef LIBDICT_DICT_PRIVATE_H__
#define LIBDICT_DICT_PRIVATE_H__

#include <stdio.h>
#include <stdlib.h>

#include "dict.h"

/* A feature (or bug) of this macro is that the expression is always evaluated,
 * regardless of whether NDEBUG is defined or not. This is intentional and
 * sometimes useful. */
#ifndef NDEBUG
# undef ASSERT
# if defined(__GNUC__) || defined(__clang__)
#  define ASSERT(expr) \
    do { \
	if (!__builtin_expect((expr), 1)) { \
	    fprintf(stderr, "\n%s:%d (%s) assertion failed: %s\n", \
		    __FILE__, __LINE__, __func__, #expr); \
	    abort(); \
	} \
    } while (0)
# else
#  define ASSERT(expr) \
    do { \
	if (!(expr)) { \
	    fprintf(stderr, "\n%s:%d assertion failed: %s\n", \
		    __FILE__, __LINE__, #expr); \
	    abort(); \
	} \
    } while (0)
# endif
#else
# define ASSERT(expr)	(void)(expr)
#endif

#if defined(__GNUC__) || defined(__clang__)
# define LIKELY(expr)	    __builtin_expect((expr), 1)
# define UNLIKELY(expr)	    __builtin_expect((expr), 0)
# define VERIFY(expr) \
    do { \
	if (!__builtin_expect((expr), 1)) { \
	    fprintf(stderr, "\n%s:%d (%s) verification failed: %s\n", \
		    __FILE__, __LINE__, __func__, #expr); \
	    return false; \
	} \
    } while (0)
#else
# define LIKELY(expr)	    (expr)
# define UNLIKELY(expr)	    (expr)
# define VERIFY(expr) \
    do { \
	if (!(expr)) { \
	    fprintf(stderr, "\n%s:%d verification failed: %s\n", \
		    __FILE__, __LINE__, #expr); \
	    return false; \
	} \
    } while (0)
#endif

#define MALLOC(n)	(*dict_malloc_func)(n)
#define FREE(p)		(*dict_free_func)(p)

#define ABS(a)		((a) < 0 ? -(a) : (a))
#define MIN(a,b)	((a) < (b) ? (a) : (b))
#define MAX(a,b)	((a) > (b) ? (a) : (b))
#define SWAP(a,b,v)	do { v = (a); (a) = (b); (b) = v; } while (0)

#if defined(__GNUC__) || defined(__clang__)
# define GCC_INLINE	__inline__
# define GCC_CONST	__attribute__((__const__))
#else
# define GCC_INLINE
# define GCC_CONST
#endif

extern long random(void);
static inline unsigned dict_rand() { return (unsigned) random(); }

#endif /* !LIBDICT_DICT_PRIVATE_H__ */
