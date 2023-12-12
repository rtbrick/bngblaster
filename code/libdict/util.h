#ifndef UTIL_H__
#define UTIL_H__

#include <assert.h>

void shuffle(char **p, size_t size);
bool is_prime(unsigned n);
bool next_permutation(unsigned a[], unsigned n);

void shuffle(char **p, size_t size)
{
    for (size_t i = 0; i < size - 1; i++) {
	size_t n = (size_t) rand() % (size - i);
	char *t = p[i+n]; p[i+n] = p[i]; p[i] = t;
    }
}

bool is_prime(unsigned n)
{
    if (n <= 0)
	return false;
    if (n <= 3)
	return true;
    if (!(n & 1))
	return false;
    for (unsigned f = 3, f2 = f * f;;) {
	if (f2 >= n) {
	    if (f2 == n)
		return false;
	    return true;
	}
	if (n % f == 0)
	    return false;
	if (f2 + (4 * f + 4) < f2)
	    return true; /* Overflow */
	f2 += 4 * f + 4;
	f += 2;
    }
}


bool next_permutation(unsigned a[], unsigned n)
{
    if (n <= 1)
	return false;
    unsigned i = n-2;
    while (!(a[i] < a[i+1]))
	if (i-- == 0)
	    return false;
    assert(a[i] < a[i+1]);
    unsigned j = n-1;
    while (!(a[j] > a[i]))
	--j;
    assert(j > i);
    assert(a[j] > a[i]);
    unsigned t = a[i]; a[i] = a[j]; a[j] = t;
    for (++i, j=n-1; i < j; ++i, --j) {
	t = a[i]; a[i] = a[j]; a[j] = t;
    }
    return true;
}

#endif /* !UTIL_H__ */
