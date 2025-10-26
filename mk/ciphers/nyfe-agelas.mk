#
# Agelas support via nyfe in sanctum.
#

CFLAGS+=	-DSANCTUM_TAG_LENGTH=32

SRC+=		$(TOPDIR)/src/nyfe_agelas.c
