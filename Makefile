# sanctum Makefile

CC?=cc
OBJDIR?=obj
BIN=sanctum
LIBNYFE=$(CURDIR)/nyfe/libnyfe.a
VERSION=$(OBJDIR)/version.c

DESTDIR?=
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin
SHARE_DIR=$(PREFIX)/share/sanctum
DARWIN_SB_PATH?=$(SHARE_DIR)/sb

CIPHER?=openssl-aes-gcm

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude
CFLAGS+=-Inyfe/include
CFLAGS+=-g

SRC=	src/sanctum.c \
	src/bless.c \
	src/bishop.c \
	src/cathedral.c \
	src/chapel.c \
	src/confess.c \
	src/config.c \
	src/control.c \
	src/heaven_rx.c \
	src/heaven_tx.c \
	src/liturgy.c \
	src/proc.c \
	src/packet.c \
	src/pool.c \
	src/pilgrim.c \
	src/purgatory_rx.c \
	src/purgatory_tx.c \
	src/ring.c \
	src/shrine.c \
	src/utils.c

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

LDFLAGS+=$(LIBNYFE)

ifeq ("$(JUMBO_FRAMES)", "1")
	CFLAGS+=-DSANCTUM_JUMBO_FRAMES=1
endif

ifeq ("$(CIPHER)", "openssl-aes-gcm")
	CFLAGS+=$(shell pkg-config openssl --cflags)
	LDFLAGS+=$(shell pkg-config openssl --libs)
	SRC+=src/openssl_aes_gcm.c
else ifeq ("$(CIPHER)", "intel-aes-gcm")
	CFLAGS+=$(shell pkg-config libisal_crypto --cflags)
	LDFLAGS+=$(shell pkg-config libisal_crypto --libs)
	SRC+=src/intel_aes_gcm.c
else ifeq ("$(CIPHER)", "nyfe-agelas")
	SRC+=src/nyfe_agelas.c
else
$(error "No CIPHER selected")
endif

INSTALL_TARGETS=install-bin

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-DPLATFORM_LINUX
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
	SRC+=src/platform_linux.c
else ifeq ("$(OSNAME)", "darwin")
	CFLAGS+=-DPLATFORM_DARWIN
	SRC+=src/platform_darwin.c
	INSTALL_TARGETS+=install-darwin-sb
else ifeq ("$(OSNAME)", "openbsd")
	CFLAGS+=-DPLATFORM_OPENBSD
	SRC+=src/platform_openbsd.c
endif

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/version.o

all: $(BIN)
	$(MAKE) -C tools/hymn
	$(MAKE) -C tools/ambry
	$(MAKE) -C tools/vicar

$(BIN): $(OBJDIR) $(LIBNYFE) $(OBJS) $(VERSION)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

$(VERSION): $(OBJDIR) force
	@if [ -f RELEASE ]; then \
		printf "const char *sanctum_build_rev = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION); \
	elif [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION); \
		printf "const char *sanctum_build_rev = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION); \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *sanctum_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION);

install: $(INSTALL_TARGETS)

install-bin: $(BIN)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	install -m 555 $(BIN) $(DESTDIR)$(INSTALL_DIR)/
	$(MAKE) -C tools/hymn install
	$(MAKE) -C tools/ambry install
	$(MAKE) -C tools/vicar install

install-darwin-sb:
	mkdir -p $(DARWIN_SB_PATH)
	install -m 644 share/sb/*.sb $(DARWIN_SB_PATH)

$(LIBNYFE):
	$(MAKE) -C nyfe

src/sanctum.c: $(VERSION)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(VERSION)
	$(MAKE) -C nyfe clean
	$(MAKE) -C tools/hymn clean
	$(MAKE) -C tools/ambry clean
	$(MAKE) -C tools/vicar clean
	rm -rf $(OBJDIR) $(BIN)

.PHONY: all clean force
