# libnyfe Makefile

CC?=cc
AR?=ar
OBJDIR?=obj

LIB=libnyfe.a

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2 -fPIC
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude
CFLAGS+=-fno-builtin -DNYFE_LIBRARY_ONLY=1

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif

SRC=	src/agelas.c \
	src/file.c \
	src/keccak1600.c \
	src/kmac256.c \
	src/mem.c \
	src/passphrase.c \
	src/sha3.c \
	src/random.c

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)

$(LIB): $(OBJDIR) $(OBJS)
	$(AR) rcs $(LIB) $(OBJS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

sync:
	@if [ -z "$(NYFE)" ]; then \
		echo "No NYFE path has been set"; \
		exit 1; \
	fi
	@for src in $(SRC); do \
		cp $(NYFE)/$${src} src; \
	done
	@cp $(NYFE)/include/libnyfe.h include
	@echo -n "nyfe synced from $(NYFE) "
	@echo "$(shell cd $(NYFE) && git rev-parse --short=8 HEAD)"

clean:
	rm -rf $(OBJDIR) $(LIB)

.PHONY: all clean force
