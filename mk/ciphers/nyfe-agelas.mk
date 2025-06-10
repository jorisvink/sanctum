#
# Agelas support via nyfe in sanctum.
#

CFLAGS+=	-DSANCTUM_USE_AGELAS

SRC+=		$(CURDIR)/src/nyfe_agelas.c
