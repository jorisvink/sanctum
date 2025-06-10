#
# AES-GCM support via intel's libisal in sanctum.
#

CFLAGS+=	$(shell pkg-config libisal_crypto --cflags)
LDFLAGS+=	$(shell pkg-config libisal_crypto --libs)

SRC+=		$(TOPDIR)/src/intel_aes_gcm.c
