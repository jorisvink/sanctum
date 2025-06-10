#
# x25519 via libsodium in sanctum.
#

ifeq ("$(LIBSODIUM)", "")
	CFLAGS+=$(shell pkg-config libsodium --cflags)
	LDFLAGS+=$(shell pkg-config libsodium --libs)
endif

LIBSODIUM=	1

SRC+=		$(CURDIR)/src/libsodium_x25519.c
