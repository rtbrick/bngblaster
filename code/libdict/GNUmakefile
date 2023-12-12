SOURCE_DIR := src
HEADER_DIR := include
OUTPUT_DIR := bin

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
HOMEBREW_PREFIX := $(shell dirname `which brew`)
HOMEBREW_PREFIX := $(shell dirname $(HOMEBREW_PREFIX))
TEST_CFLAGS := -I$(HOMEBREW_PREFIX)/include
TEST_LDFLAGS := -L$(HOMEBREW_PREFIX)/lib
endif

SOURCE := $(wildcard $(SOURCE_DIR)/*.c)
HEADER := $(wildcard $(HEADER_DIR)/*.h $(SOURCE_DIR)/*.h)

STATIC_OBJ := $(SOURCE:$(SOURCE_DIR)/%.c=$(OUTPUT_DIR)/%.o)
PROFIL_OBJ := $(SOURCE:$(SOURCE_DIR)/%.c=$(OUTPUT_DIR)/%.po)
SHARED_OBJ := $(SOURCE:$(SOURCE_DIR)/%.c=$(OUTPUT_DIR)/%.So)

PROG_SRC := anagram.c benchmark.c demo.c
PROGRAMS := $(PROG_SRC:%.c=$(OUTPUT_DIR)/%)

LIB := dict
STATIC_LIB_NAME := lib$(LIB).a
PROFIL_LIB_NAME := lib$(LIB)_p.a
SHARED_LIB_NAME := lib$(LIB).so
STATIC_LIB := $(OUTPUT_DIR)/$(STATIC_LIB_NAME)
PROFIL_LIB := $(OUTPUT_DIR)/$(PROFIL_LIB_NAME)
SHARED_LIB := $(OUTPUT_DIR)/$(SHARED_LIB_NAME)

ifeq ($(CC),cc)
  CC := $(shell which clang || which gcc)
endif
INCLUDES := -I$(HEADER_DIR) -I$(SOURCE_DIR)
ifeq ($(findstring clang,$(CC)),clang)
  WARNINGS := -Weverything -Wno-padded -Wno-format-nonliteral -Wno-disabled-macro-expansion
else # gcc
  WARNINGS := -Wall -Wextra
endif
WARNINGS := $(WARNINGS) -Werror -ansi -pedantic
CFLAGS := $(WARNINGS) -std=c11 -O2 -pipe $(INCLUDES)
LDFLAGS :=

AR ?= ar
ARFLAGS ?= cru

INSTALL_PREFIX ?= /usr/local
INSTALL_BINDIR = $(INSTALL_PREFIX)/bin
INSTALL_LIBDIR = $(INSTALL_PREFIX)/lib
INSTALL_INCDIR = $(INSTALL_PREFIX)/include/dict
INSTALL_MANDIR = $(INSTALL_PREFIX)/man
INSTALL ?= install
INSTALL_LIBVER = 2
INSTALL_SHLIB = $(SHARED_LIB_NAME).$(INSTALL_LIBVER)
INSTALL_USER ?= 0
INSTALL_GROUP ?= 0
INSTALL_EXTRA_ARGS ?= -s

all: $(OUTPUT_DIR) $(STATIC_LIB) $(SHARED_LIB) $(PROGRAMS)
	@echo && echo "Don't forget to run 'make test'"

shared: $(SHARED_LIB)

static: $(STATIC_LIB) $(PROFIL_LIB)

$(OUTPUT_DIR):
	[ -d $(OUTPUT_DIR) ] || mkdir -m 755 $(OUTPUT_DIR)

$(STATIC_LIB): $(OUTPUT_DIR) $(STATIC_OBJ)
	$(AR) $(ARFLAGS) $(STATIC_LIB) $(STATIC_OBJ)

$(PROFIL_LIB): $(OUTPUT_DIR) $(PROFIL_OBJ)
	$(AR) $(ARFLAGS) $(PROFIL_LIB) $(PROFIL_OBJ)

$(SHARED_LIB): $(OUTPUT_DIR) $(SHARED_OBJ)
	$(CC) -shared -o $(SHARED_LIB) $(SHARED_OBJ)

$(OUTPUT_DIR)/%.o: $(SOURCE_DIR)/%.c $(HEADER) GNUmakefile $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -c -o $(@) $(<)

$(OUTPUT_DIR)/%.po: $(SOURCE_DIR)/%.c $(HEADER) GNUmakefile $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -pg -c -o $(@) $(<)

$(OUTPUT_DIR)/%.So: $(SOURCE_DIR)/%.c $(HEADER) GNUmakefile $(OUTPUT_DIR)
	$(CC) $(CFLAGS) -fPIC -DPIC -c -o $(@) $(<)

$(OUTPUT_DIR)/unit_tests: unit_tests.c $(STATIC_OBJ) GNUmakefile
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -o $(@) $(<) $(STATIC_OBJ) $(LDFLAGS) $(TEST_LDFLAGS) -lcunit

$(OUTPUT_DIR)/%: %.c $(STATIC_OBJ) GNUmakefile
	$(CC) $(CFLAGS) -o $(@) $(<) $(STATIC_OBJ) $(LDFLAGS)

test: $(OUTPUT_DIR)/unit_tests
	./$(OUTPUT_DIR)/unit_tests

.PHONY: clean
clean:
	if test -d $(OUTPUT_DIR); then rm -r $(OUTPUT_DIR); fi

.PHONY: analyze
analyze:
	@for x in $(SOURCE) $(PROG_SRC); \
		do echo Analyzing $$x ...; \
		clang --analyze $(INCLUDES) $$x -o /dev/null; \
	done

.PHONY: install
install: $(STATIC_LIB) $(PROFIL_LIB) $(SHARED_LIB)
	[ -d $(INSTALL_INCDIR) ] || mkdir -p -m 755 $(INSTALL_INCDIR)
	$(INSTALL) -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 644 $(HEADER) $(INSTALL_INCDIR)
	[ -d $(INSTALL_LIBDIR) ] || mkdir -p -m 755 $(INSTALL_LIBDIR)
	$(INSTALL) $(INSTALL_EXTRA_ARGS) -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 644 $(STATIC_LIB) $(INSTALL_LIBDIR)/$(STATIC_LIB_NAME)
	$(INSTALL) $(INSTALL_EXTRA_ARGS) -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 644 $(PROFIL_LIB) $(INSTALL_LIBDIR)/$(PROFIL_LIB_NAME)
	$(INSTALL) $(INSTALL_EXTRA_ARGS) -o $(INSTALL_USER) -g $(INSTALL_GROUP) -m 755 $(SHARED_LIB) $(INSTALL_LIBDIR)/$(INSTALL_SHLIB)
	$(SHELL) -ec 'cd $(INSTALL_LIBDIR) && ln -sf $(INSTALL_SHLIB) $(SHARED_LIB_NAME)'

.PHONY: uninstall
uninstall :
	-rm -rf $(INSTALL_INCDIR)
	-rm -f $(INSTALL_LIBDIR)/$(STATIC_LIB)
	-rm -f $(INSTALL_LIBDIR)/$(PROFIL_LIB)
	-rm -f $(INSTALL_LIBDIR)/$(INSTALL_SHLIB)
	-rm -f $(INSTALL_LIBDIR)/$(SHARED_LIB)
