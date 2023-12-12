/*
 * libdict - common definitions for hash tables.
 *
 * Copyright (c) 2014, Farooq Mela
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

#include "hashtable_common.h"

static const unsigned kPrimes[] = {
    11,		17,	    37,		67,	    131,
    257,	521,	    1031,       2053,       4099,
    8209,       16411,      32771,      65537,      131101,
    262147,     524309,     1048583,    2097169,    4194319,
    8388617,    16777259,   33554467,   67108879,   134217757,
    268435459,  536870923,  1073741827, 2147483659, 4294967291
};
static const unsigned kNumPrimes = sizeof(kPrimes) / sizeof(kPrimes[0]);

unsigned
dict_prime_geq(unsigned n)
{
    /* TODO(farooq): use binary search */
    for (unsigned index = 0; index < kNumPrimes; ++index)
	if (kPrimes[index] >= n)
	    return kPrimes[index];
    return kPrimes[kNumPrimes - 1];
}
