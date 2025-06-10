# ambry Makefile

CC?=cc
OBJDIR?=obj
BIN=ambry
TOPDIR?=../../
LIBNYFE=../../nyfe/libnyfe.a

DESTDIR?=
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -I../../include
CFLAGS+=-I../../nyfe/include
CFLAGS+=-g

LDFLAGS+=$(LIBNYFE)

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif

SRC=	src/ambry.c

include $(TOPDIR)/mk/random/$(RANDOM).mk
include $(TOPDIR)/mk/ciphers/$(CIPHER).mk

OBJS=	$(SRC:%.c=$(OBJDIR)/%.o)

$(BIN): $(OBJDIR) $(OBJS) $(LIBNYFE)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

install: $(BIN)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	install -m 555 $(BIN) $(DESTDIR)$(INSTALL_DIR)/

uninstall:
	rm -f $(DESTDIR)$(INSTALL_DIR)/$(BIN)

$(LIBNYFE):
	$(MAKE) -C ../../nyfe

$(OBJDIR)/%.o: %.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BIN) $(OBJDIR)

.PHONY: all clean
