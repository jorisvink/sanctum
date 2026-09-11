#
# AES-GCM support via OpenSSL.
#

CFLAGS+=	$(shell pkg-config libcrypto --cflags)
LDFLAGS+=	$(shell pkg-config libcrypto --libs)

SRC+=		$(TOPDIR)/src/openssl_aes_gcm.c
