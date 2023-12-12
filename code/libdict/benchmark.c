/* benchmark.c
 * Some timing tests for libdict
 * Copyright (C) 2001-2011 Farooq Mela */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "dict.h"
#include "dict_private.h"
#include "tree_common.h"
#include "util.h"

static const char appname[] = "benchmark";

char *xstrdup(const char *str);

#ifdef __GNUC__
# define NORETURN	__attribute__((__noreturn__))
#else
# define NORETURN
#endif
void quit(const char *, ...) NORETURN;
void warn(const char *fmt, ...);
void *xmalloc(size_t size);

static size_t hash_count = 0, comp_count = 0;
unsigned str_hash(const void *p);
int my_strcmp(const void *k1, const void *k2);
unsigned ptr_hash(const void *p);
int my_ptrcmp(const void *k1, const void *k2);
void key_str_free(void *key, void *datum);

void timer_start(struct rusage* start);
void timer_end(const struct rusage* start, struct rusage *end,
	       struct timeval *total);
dict *create_dictionary(char type, const char **container_name);

#define HASHTABLE_SIZE 97
/* #define HASHTABLE_SIZE 997 */
/* #define HASHTABLE_SIZE 9973 */

static size_t malloced = 0;

int
main(int argc, char **argv)
{
    bool shuffle_keys = true;

    if (argc != 3) {
	fprintf(stderr, "usage: %s [type] [input]\n", appname);
	fprintf(stderr, "type: specifies the dictionary type:\n");
	fprintf(stderr, "   h: height-balanced tree\n");
	fprintf(stderr, "   p: path-reduction tree\n");
	fprintf(stderr, "   r: red-black tree\n");
	fprintf(stderr, "   t: treap\n");
	fprintf(stderr, "   s: splay tree\n");
	fprintf(stderr, "   w: weight-balanced tree\n");
	fprintf(stderr, "   S: skiplist\n");
	fprintf(stderr, "   H: hashtable\n");
	fprintf(stderr, "   2: hashtable 2\n");
	fprintf(stderr, "input: text file consisting of newline-separated keys\n");
	exit(EXIT_FAILURE);
    }

    srand(0xdeadbeef);

    dict_malloc_func = xmalloc;

    const char type = argv[1][0];
    const char *container_name = NULL;
    dict *dct = create_dictionary(type, &container_name);
    if (!dct)
	quit("can't create container");

    ASSERT(dict_verify(dct));
    ASSERT(comp_count == 0);
    ASSERT(hash_count == 0);

    const size_t malloced_save = malloced;

    FILE *fp = fopen(argv[2], "r");
    if (fp == NULL)
	quit("cant open file '%s': %s", argv[2], strerror(errno));

    size_t nwords = 0;
    char buf[512];
    while (fgets(buf, sizeof(buf), fp))
	++nwords;

    if (!nwords)
	quit("nothing read from file");

    char **words = xmalloc(sizeof(*words) * nwords);
    rewind(fp);
    size_t words_read = 0;
    while (words_read < nwords && fgets(buf, sizeof(buf), fp)) {
	strtok(buf, "\n");
	words[words_read++] = xstrdup(buf);
    }
    fclose(fp);
    if (words_read < nwords)
	quit("Only read %zu/%zu words!", words_read, nwords);
    printf("Loaded %zu keys from %s.\n", nwords, argv[2]);

    malloced = malloced_save;
    size_t total_comp = 0, total_hash = 0, total_rotations = 0;

    struct rusage start, end;
    struct timeval total = { 0, 0 };

    timer_start(&start);
    for (unsigned i = 0; i < nwords; i++) {
	dict_insert_result result = dict_insert(dct, words[i]);
	if (!result.inserted)
	    quit("insert #%d failed for '%s'", i, words[i]);
	ASSERT(result.datum_ptr != NULL);
	ASSERT(*result.datum_ptr == NULL);
	*result.datum_ptr = words[i];
    }
    timer_end(&start, &end, &total);
    printf("    %s container: %.02fkB\n", container_name, malloced_save * 1e-3);
    printf("       %s memory: %.02fkB\n", container_name, malloced * 1e-3);
    printf("       %s insert: %6.03fs %9zu cmp (%.02f/insert)",
	   container_name,
	   (end.ru_utime.tv_sec * 1000000 + end.ru_utime.tv_usec) * 1e-6,
	   comp_count, comp_count / (double) nwords);
    if (hash_count)
	printf(" %9zu hash", hash_count);
    printf("\n");
    total_comp += comp_count; comp_count = 0;
    total_hash += hash_count; hash_count = 0;
    if (dict_is_sorted(dct) && type != 'S') {
	tree_base *tree = dict_private(dct);
	printf(" min path length: %zu\n", tree_min_path_length(tree));
	printf(" max path length: %zu\n", tree_max_path_length(tree));
	printf(" tot path length: %zu\n", tree_total_path_length(tree));
	printf("insert rotations: %zu\n", tree->rotation_count);
	total_rotations += tree->rotation_count;
	tree->rotation_count = 0;
    } else if (type == 'S') {
	size_t counts[16] = { 0 };
	size_t num_counts = skiplist_link_count_histogram(dict_private(dct), counts, sizeof(counts) / sizeof(counts[0]));
	size_t count_sum = 0;
	for (size_t i = 0; i <= num_counts; ++i) {
	    printf("skiplist %zu-node(s): %zu\n", i, counts[i]);
	    count_sum += counts[i];
	}
	ASSERT(count_sum == nwords);
    }

    ASSERT(dict_verify(dct));
    comp_count = hash_count = 0; /* Ignore comparisons/hashes incurred by dict_verify() */

    size_t n = dict_count(dct);
    if (n != nwords)
	quit("bad count (%u - should be %u)!", n, nwords);

    dict_itor *itor = dict_itor_new(dct);

    timer_start(&start);
    n = 0;
    ASSERT(dict_itor_first(itor));
    do {
	ASSERT(dict_itor_valid(itor));
	ASSERT(dict_itor_key(itor) == *dict_itor_datum(itor));
	++n;
    } while (dict_itor_next(itor));
    timer_end(&start, &end, &total);
    printf("  %s fwd iterate: %6.03fs\n",
	   container_name,
	   (end.ru_utime.tv_sec * 1000000 + end.ru_utime.tv_usec) * 1e-6);
    if (n != nwords)
	warn("Fwd iteration returned %u items - should be %u", n, nwords);

    ASSERT(dict_verify(dct));
    comp_count = hash_count = 0; /* Ignore comparisons/hashes incurred by dict_verify() */

    timer_start(&start);
    n = 0;
    ASSERT(dict_itor_last(itor));
    do {
	ASSERT(dict_itor_valid(itor));
	ASSERT(dict_itor_key(itor) == *dict_itor_datum(itor));
	++n;
    } while (dict_itor_prev(itor));
    timer_end(&start, &end, &total);
    printf("  %s rev iterate: %6.03fs\n",
	   container_name,
	   (end.ru_utime.tv_sec * 1000000 + end.ru_utime.tv_usec) * 1e-6);
    if (n != nwords)
	warn("Rev iteration returned %u items - should be %u", n, nwords);

    dict_itor_free(itor);

    if (shuffle_keys) shuffle(words, nwords);

    ASSERT(dict_verify(dct));
    comp_count = hash_count = 0; /* Ignore comparisons/hashes incurred by dict_verify() */

    timer_start(&start);
    for (unsigned i = 0; i < nwords; i++) {
	void **p = dict_search(dct, words[i]);
	if (!p)
	    quit("lookup failed for '%s'", buf);
	if (*p != words[i])
	    quit("bad data for '%s', got '%s' instead", words[i], *(char **)p);
    }
    timer_end(&start, &end, &total);
    printf("  %s good search: %6.03fs %9zu cmp (%.02f/search)",
	   container_name,
	   (end.ru_utime.tv_sec * 1000000 + end.ru_utime.tv_usec) * 1e-6,
	   comp_count, comp_count / (double) nwords);
    if (hash_count)
	printf(" %9zu hash", hash_count);
    printf("\n");
    total_comp += comp_count; comp_count = 0;
    total_hash += hash_count; hash_count = 0;
    if (type != 'H' && type != '2' && type != 'S') {
	tree_base *tree = dict_private(dct);
	printf("search rotations: %zu\n", tree->rotation_count);
	total_rotations += tree->rotation_count;
	tree->rotation_count = 0;
    }

    ASSERT(dict_verify(dct));
    comp_count = hash_count = 0; /* Ignore comparisons/hashes incurred by dict_verify() */

    timer_start(&start);
    for (unsigned i = 0; i < nwords; i++) {
	unsigned rv = dict_rand() % strlen(words[i]);
	words[i][rv]++;
	dict_search(dct, words[i]);
	words[i][rv]--;
    }
    timer_end(&start, &end, &total);
    printf("   %s bad search: %6.03fs %9zu cmp (%.02f/search)",
	   container_name,
	   (end.ru_utime.tv_sec * 1000000 + end.ru_utime.tv_usec) * 1e-6,
	   comp_count, comp_count / (double) nwords);
    if (hash_count)
	printf(" %9zu hash", hash_count);
    printf("\n");
    total_comp += comp_count; comp_count = 0;
    total_hash += hash_count; hash_count = 0;

    ASSERT(dict_verify(dct));
    comp_count = hash_count = 0; /* Ignore comparisons/hashes incurred by dict_verify() */

    if (shuffle_keys) shuffle(words, nwords);

    timer_start(&start);
    for (unsigned i = 0; i < nwords; i++) {
	dict_remove_result result = dict_remove(dct, words[i]);
	if (!result.removed)
	    quit("removing #%d '%s' failed!\n", i, words[i]);
	ASSERT(result.key == words[i]);
	ASSERT(result.datum == words[i]);
    }
    timer_end(&start, &end, &total);
    printf("       %s remove: %6.03fs %9zu cmp (%.2f/remove)",
	   container_name,
	   (end.ru_utime.tv_sec * 1000000 + end.ru_utime.tv_usec) * 1e-6,
	   comp_count, comp_count / (double)nwords);
    if (hash_count)
	printf(" %9zu hash", hash_count);
    printf("\n");
    total_comp += comp_count; comp_count = 0;
    total_hash += hash_count; hash_count = 0;
    if (type != 'H' && type != '2' && type != 'S') {
	tree_base *tree = dict_private(dct);
	printf("remove rotations: %zu\n", tree->rotation_count);
	total_rotations += tree->rotation_count;
	tree->rotation_count = 0;
    }

    ASSERT(dict_verify(dct));
    comp_count = hash_count = 0; /* Ignore comparisons/hashes incurred by dict_verify() */

    if ((n = dict_count(dct)) != 0)
	quit("error - count not zero (%u)!", n);

    dict_free(dct, key_str_free);

    printf("        %s total: %6.03fs %9zu cmp",
	   container_name,
	   (total.tv_sec * 1000000 + total.tv_usec) * 1e-6,
	   total_comp);
    if (total_hash)
	printf(" %9zu hash", total_hash);
    printf("\n");

    if (type != 'H' && type != '2' && type != 'S') {
	printf(" total rotations: %zu\n", total_rotations);
    }

    FREE(words);

    exit(EXIT_SUCCESS);
}

dict *
create_dictionary(char type, const char **container_name)
{
    dict_compare_func cmp_func = my_strcmp;
    dict_hash_func hash_func = str_hash;

    switch (type) {
	case 'h':
	    *container_name = "hb";
	    return hb_dict_new(cmp_func);

	case 'p':
	    *container_name = "pr";
	    return pr_dict_new(cmp_func);

	case 'r':
	    *container_name = "rb";
	    return rb_dict_new(cmp_func);

	case 't':
	    *container_name = "tr";
	    return tr_dict_new(cmp_func, NULL);

	case 's':
	    *container_name = "sp";
	    return sp_dict_new(cmp_func);

	case 'S':
	    *container_name = "sk";
	    return skiplist_dict_new(cmp_func, 12);

	case 'w':
	    *container_name = "wb";
	    return wb_dict_new(cmp_func);

	case 'H':
	    *container_name = "ht";
	    return hashtable_dict_new(cmp_func, hash_func, HASHTABLE_SIZE);

	case '2':
	    *container_name = "h2";
	    return hashtable2_dict_new(cmp_func, hash_func, HASHTABLE_SIZE);

	default:
	    quit("type must be one of h, p, r, t, s, w or H");
    }
}

char *
xstrdup(const char *str)
{
    size_t len = strlen(str) + 1;
    return memcpy(xmalloc(len), str, len);
}

void
quit(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    fprintf(stderr, "%s: ", appname);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);

    exit(EXIT_FAILURE);
}

void
warn(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    fprintf(stderr, "warning: %s: ", appname);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void *
xmalloc(size_t size)
{
    void *p = malloc(size);
    if (!p)
	quit("out of memory");
    malloced += size;
    return p;
}

unsigned
str_hash(const void *p)
{
    ++hash_count;
    return dict_str_hash(p);
}

int
my_strcmp(const void *k1, const void *k2)
{
    ++comp_count;
    return strcmp(k1, k2);
}

unsigned
ptr_hash(const void *p)
{
    ++hash_count;
    return (unsigned) ((2166136261U ^ (uintptr_t)p) * 16777619U);
}

int
my_ptrcmp(const void *k1, const void *k2)
{
    ++comp_count;
    return (k1 < k2) ? -1 : (k1 > k2);
}

void
key_str_free(void *key, void *datum)
{
    ASSERT(key == datum);
    free(key);
}

void
timer_start(struct rusage *start)
{
    getrusage(RUSAGE_SELF, start);
}

void
timer_end(const struct rusage *start, struct rusage *end,
	  struct timeval *total) {
    getrusage(RUSAGE_SELF, end);
    if (end->ru_utime.tv_usec < start->ru_utime.tv_usec) {
	end->ru_utime.tv_usec += 1000000; end->ru_utime.tv_sec--;
    }
    end->ru_utime.tv_usec -= start->ru_utime.tv_usec;
    end->ru_utime.tv_sec -= start->ru_utime.tv_sec;
    total->tv_sec += end->ru_utime.tv_sec;
    if ((total->tv_usec += end->ru_utime.tv_usec) > 1000000) {
	total->tv_usec -= 1000000; total->tv_sec++;
    }
}
