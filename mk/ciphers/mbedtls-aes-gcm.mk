#
# AES-GCM support via mbedtls its cryptolib in sanctum.
#

ifeq ("$(MBEDTLS)", "")
	CFLAGS+=$(shell pkg-config mbedtls --cflags)
	LDFLAGS+=$(shell pkg-config mbedtls --libs-only-L) -lmbedcrypto
endif

MBEDTLS=	1

SRC+=		$(TOPDIR)/src/mbedtls_aes_gcm.c
