/* demo.c
 * Interactive demo of libdict.
 * Copyright (C) 2001-2011 Farooq Mela */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include "dict.h"

static const char appname[] = "demo";

char *xstrdup(const char *str);

#if defined(__GNUC__) || defined(__clang__)
# define NORETURN	__attribute__((__noreturn__))
#else
# define NORETURN
#endif
void quit(const char *, ...) NORETURN;
void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void *xdup(const void *ptr, size_t size);

static void
key_val_free(void *key, void *datum)
{
    free(key);
    free(datum);
}

#define HSIZE		997
#define SKIPLINKS       10

int
main(int argc, char **argv)
{
    if (argc != 2)
	quit("usage: %s [type]", appname);

    srand((unsigned)time(NULL));

    dict_malloc_func = xmalloc;

    dict *dct = NULL;
    ++argv;
    switch (argv[0][0]) {
	case 'h':
	    dct = hb_dict_new((dict_compare_func)strcmp);
	    break;
	case 'p':
	    dct = pr_dict_new((dict_compare_func)strcmp);
	    break;
	case 'r':
	    dct = rb_dict_new((dict_compare_func)strcmp);
	    break;
	case 't':
	    dct = tr_dict_new((dict_compare_func)strcmp, NULL);
	    break;
	case 's':
	    dct = sp_dict_new((dict_compare_func)strcmp);
	    break;
	case 'w':
	    dct = wb_dict_new((dict_compare_func)strcmp);
	    break;
	case 'S':
	    dct = skiplist_dict_new((dict_compare_func)strcmp, SKIPLINKS);
	    break;
	case 'H':
	    dct = hashtable_dict_new((dict_compare_func)strcmp, dict_str_hash, HSIZE);
	    break;
	case '2':
	    dct = hashtable2_dict_new((dict_compare_func)strcmp, dict_str_hash, HSIZE);
	    break;
	default:
	    quit("type must be one of h, p, r, t, s, w, S, H, or 2");
    }

    if (!dct)
	quit("can't create container");

    for (;;) {
	dict_verify(dct);
	printf("> ");
	fflush(stdout);

	char buf[512];
	if (fgets(buf, sizeof(buf), stdin) == NULL)
	    break;

	char *p, *ptr, *ptr2;
	if ((p = strchr(buf, '\n')) != NULL)
	    *p = 0;
	for (p = buf; *p && isspace(*p); p++)
	    /* void */;
	if (buf != p) {
	    strcpy(buf, p);
	}
	ptr2 = (ptr = strtok(buf, " ") ? strtok(NULL, " ") : NULL) ?
	    strtok(NULL, " ") : NULL;
	if (*buf == 0)
	    continue;
	if (strcmp(buf, "insert") == 0) {
	    if (!ptr2) {
		printf("usage: insert <key> <data>\n");
		continue;
	    }
	    dict_insert_result result = dict_insert(dct, xstrdup(ptr));
	    if (result.inserted) {
		*result.datum_ptr = xstrdup(ptr2);
		printf("inserted '%s': '%s'\n",
		       ptr, (char *)*result.datum_ptr);
	    } else {
		printf("'%s' already in dict: '%s'\n",
		       ptr, (char *)*result.datum_ptr);
	    }
	} else if (strcmp(buf, "search") == 0) {
	    if (ptr2) {
		printf("usage: search <key>\n");
		continue;
	    }
	    void** search = dict_search(dct, ptr);
	    if (search)
		printf("found '%s': '%s'\n", ptr, *(char **)search);
	    else
		printf("'%s' not found!\n", ptr);
	} else if (strcmp(buf, "searchle") == 0) {
	    if (ptr2) {
		printf("usage: searchle <key>\n");
		continue;
	    }
	    if (!dict_is_sorted(dct)) {
		printf("dict does not support that operation!");
		continue;
	    }
	    void** search = dict_search_le(dct, ptr);
	    if (search)
		printf("le '%s': '%s'\n", ptr, *(char **)search);
	    else
		printf("le '%s': no result.\n", ptr);
	} else if (strcmp(buf, "searchlt") == 0) {
	    if (ptr2) {
		printf("usage: searchlt <key>\n");
		continue;
	    }
	    if (!dict_is_sorted(dct)) {
		printf("dict does not support that operation!");
		continue;
	    }
	    void** search = dict_search_lt(dct, ptr);
	    if (search)
		printf("lt '%s': '%s'\n", ptr, *(char **)search);
	    else
		printf("lt '%s': no result.\n", ptr);
	} else if (strcmp(buf, "searchge") == 0) {
	    if (ptr2) {
		printf("usage: searchge <key>\n");
		continue;
	    }
	    if (!dict_is_sorted(dct)) {
		printf("dict does not support that operation!");
		continue;
	    }
	    void** search = dict_search_ge(dct, ptr);
	    if (search)
		printf("ge '%s': '%s'\n", ptr, *(char **)search);
	    else
		printf("ge '%s': no result.\n", ptr);
	} else if (strcmp(buf, "searchgt") == 0) {
	    if (ptr2) {
		printf("usage: searchgt <key>\n");
		continue;
	    }
	    if (!dict_is_sorted(dct)) {
		printf("dict does not support that operation!");
		continue;
	    }
	    void** search = dict_search_gt(dct, ptr);
	    if (search)
		printf("gt '%s': '%s'\n", ptr, *(char **)search);
	    else
		printf("gt '%s': no result.\n", ptr);
	} else if (strcmp(buf, "remove") == 0) {
	    if (!ptr || ptr2) {
		printf("usage: remove <key>\n");
		continue;
	    }
	    dict_remove_result result = dict_remove(dct, ptr);
	    if (result.removed) {
		printf("removed '%s' from dict: %s\n", (char *)result.key, (char *)result.datum);
		free(result.key);
		free(result.datum);
	    } else
		printf("key '%s' not in dict!\n", ptr);
	} else if (strcmp(buf, "show") == 0) {
	    if (ptr) {
		printf("usage: show\n");
		continue;
	    }
	    dict_itor *itor = dict_itor_new(dct);
	    dict_itor_first(itor);
	    for (; dict_itor_valid(itor); dict_itor_next(itor))
		printf("'%s': '%s'\n",
		       (char *)dict_itor_key(itor),
		       (char *)*dict_itor_datum(itor));
	    dict_itor_free(itor);
	} else if (strcmp(buf, "reverse") == 0) {
	    if (ptr) {
		printf("usage: reverse\n");
		continue;
	    }
	    dict_itor *itor = dict_itor_new(dct);
	    dict_itor_last(itor);
	    for (; dict_itor_valid(itor); dict_itor_prev(itor))
		printf("'%s': '%s'\n",
		       (char *)dict_itor_key(itor),
		       (char *)*dict_itor_datum(itor));
	    dict_itor_free(itor);
	} else if (strcmp(buf, "clear") == 0) {
	    if (ptr) {
		printf("usage: clear\n");
		continue;
	    }
	    dict_clear(dct, key_val_free);
	} else if (strcmp(buf, "count") == 0) {
	    if (ptr) {
		printf("usage: count\n");
		continue;
	    }
	    printf("count = %zu\n", dict_count(dct));
	} else if (strcmp(buf, "quit") == 0) {
	    break;
	} else {
	    printf("Usage summary:\n");
	    printf("  insert <key> <data>\n");
	    printf("  search <key>\n");
	    printf("  searchle <key>\n");
	    printf("  searchlt <key>\n");
	    printf("  searchge <key>\n");
	    printf("  searchgt <key>\n");
	    printf("  remove <key>\n");
	    printf("  clear\n");
	    printf("  count\n");
	    printf("  show\n");
	    printf("  reverse\n");
	    printf("  quit\n");
	}
    }

    dict_free(dct, key_val_free);

    exit(0);
}

char *
xstrdup(const char *str)
{
    return xdup(str, strlen(str) + 1);
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

void *
xmalloc(size_t size)
{
    void *p = malloc(size);
    if (!p) {
	fprintf(stderr, "out of memory\n");
	abort();
    }
    return p;
}

void *
xdup(const void *ptr, size_t size)
{
    return memcpy(xmalloc(size), ptr, size);
}
