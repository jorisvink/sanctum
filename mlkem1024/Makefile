# mlkem1024 library Makefile

CC?=cc
AR?=ar
OBJDIR?=obj

LIB=libmlkem1024.a

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2 -fPIC
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common
CFLAGS+=-fno-builtin -I../nyfe/include -DKYBER_K=4

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif

SRC=	src/cbd.c \
	src/fips202.c \
	src/indcpa.c \
	src/kem.c \
	src/ntt.c \
	src/poly.c \
	src/polyvec.c \
	src/reduce.c \
	src/symmetric-shake.c \
	src/verify.c

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)

$(LIB): $(OBJDIR) $(OBJS)
	$(AR) rcs $(LIB) $(OBJS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

tests: nist_tests.c $(LIB) ../nyfe/libnyfe.a
	$(CC) $(CFLAGS) nist_tests.c -o nist_tests $(LIB) ../nyfe/libnyfe.a
	./nist_tests

clean:
	rm -rf $(OBJDIR) $(LIB) nist_tests

.PHONY: all clean force
