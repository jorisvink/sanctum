#
# AEGIS support via libsodium in sanctum.
#

ifeq ("$(LIBSODIUM)", "")
	CFLAGS+=$(shell pkg-config libsodium --cflags)
	LDFLAGS+=$(shell pkg-config libsodium --libs)
endif

LIBSODIUM=	1

CFLAGS+=	-DSANCTUM_TAG_LENGTH=32 -DSANCTUM_NONCE_LENGTH=32

SRC+=		$(TOPDIR)/src/libsodium_aegis.c
