#
# Agelas support via nyfe in sanctum.
#

CFLAGS+=	-DSANCTUM_USE_AGELAS

SRC+=		$(TOPDIR)/src/nyfe_agelas.c
