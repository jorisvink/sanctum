#
# ML-KEM-1024 via the reference implementation carried in sanctum's repo.
#

KEMLIB=		$(CURDIR)/mlkem1024/libmlkem1024.a
LDFLAGS+=	$(KEMLIB)

$(KEMLIB): $(LIBNYFE)
	$(MAKE) -C mlkem1024

mlkem-tests: $(LIBNYFE)
	$(MAKE) -C mlkem1024 tests

SRC+=		src/mlkem1024_ref.c
