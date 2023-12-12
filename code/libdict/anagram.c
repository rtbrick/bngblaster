#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "dict.h"
#include "dict_private.h"

void *xmalloc(size_t size);
char *xstrdup(const char *s);

typedef struct WordList WordList;
struct WordList {
    char	*word;
    WordList	*next;
};

int
main(int argc, char *argv[])
{
    if (argc != 2) {
	printf("Expected filename argument.\n");
	exit(1);
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
	printf("Unable to open file '%s'.\n", argv[1]);
	exit(1);
    }

    rb_tree *tree = rb_tree_new(dict_str_cmp);

    char buf[512];
    while (fgets(buf, sizeof(buf), fp)) {
	if (isupper(buf[0]))	/* Disregard proper nouns. */
	    continue;

	strtok(buf, "\r\n");
	int freq[256] = { 0 };
	memset(freq, 0, sizeof(freq));

	ASSERT(buf[0] != '\0');

	for (char *p = buf; *p; p++)
	    freq[tolower(*p)]++;

	char name[1024];
	char *p = name;
	for (int i=1; i<256; i++) {
	    if (freq[i]) {
		ASSERT(freq[i] < 10);

		*p++ = (char) i;
		*p++ = '0' + (char) freq[i];
	    }
	}
	*p = 0;

	WordList* word = xmalloc(sizeof(*word));
	word->word = xstrdup(buf);
	WordList** wordp = (WordList**) rb_tree_insert(tree, xstrdup(name)).datum_ptr;
	word->next = *wordp;
	*wordp = word;
    }

    rb_itor *itor = rb_itor_new(tree);
    for (rb_itor_first(itor); rb_itor_valid(itor); rb_itor_next(itor)) {
	WordList *word = *rb_itor_datum(itor);
	ASSERT(word != NULL);
	if (word->next) {
	    int count = 1;
	    for (; word->next; count++)
		word = word->next;
	    printf("%2d:[", count);
	    word = *rb_itor_datum(itor);
	    while (word) {
		printf("%s%c", word->word, word->next ? ',' : ']');
		word = word->next;
	    }
	    printf("\n");
	}
	word = *rb_itor_datum(itor);
	while (word) {
	    WordList *next = word->next;
	    free(word->word);
	    free(word);
	    word = next;
	}
    } while (rb_itor_next(itor));
    rb_itor_free(itor);
    rb_tree_free(tree, NULL);

    return 0;
}

char *
xstrdup(const char *s)
{
    size_t len = strlen(s) + 1;
    return memcpy(xmalloc(len), s, len);
}

void *
xmalloc(size_t size)
{
    ASSERT(size > 0);
    void *p = malloc(size);
    if (!p) {
	fprintf(stderr, "Out of memory\n");
	abort();
    }
    return p;
}
