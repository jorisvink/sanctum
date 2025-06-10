# vicar Makefile

ifeq ("$(TOPDIR)", "")
	error("No TOPDIR set")
endif

include $(TOPDIR)/mk/defaults.mk

BIN=vicar
OBJDIR?=obj

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -I$(TOPDIR)/include
CFLAGS+=-I$(TOPDIR)/nyfe/include
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

SRC=	src/vicar.c

include $(RANDOM_MK_PATH)

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
	$(MAKE) -C $(TOPDIR)/nyfe

$(OBJDIR)/%.o: %.c
	@mkdir -p $(shell dirname $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BIN) $(OBJDIR)

.PHONY: all clean
