/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/sanctum_cipher.h"

/*
 * We perform the NIST ACVP AFT tests for ML-KEM-1024 using the
 * reference implementation found in this directory.
 *
 * The test vectors originally come in JSON format, they were instead
 * converted to binary format using tests/convert.py so that they
 * are much easier to load here.
 */

#define KEYGEN_TEST	"test-vectors/acvp_nist_keygen_fips203.bin"
#
struct keygen_test {
	int		tcid;
	u_int8_t	z[SANCTUM_KEY_LENGTH];
	u_int8_t	d[SANCTUM_KEY_LENGTH];
	u_int8_t	ek[SANCTUM_MLKEM_1024_PUBLICKEYBYTES];
	u_int8_t	dk[SANCTUM_MLKEM_1024_SECRETKEYBYTES];
} __attribute__((packed));

#define ENCDEC_TEST	"test-vectors/acvp_nist_encap_decap_fips203.bin"

struct encdec_test {
	int		tcid;
	u_int8_t	ek[SANCTUM_MLKEM_1024_PUBLICKEYBYTES];
	u_int8_t	dk[SANCTUM_MLKEM_1024_SECRETKEYBYTES];
	u_int8_t	ct[SANCTUM_MLKEM_1024_CIPHERTEXTBYTES];
	u_int8_t	k[SANCTUM_KEY_LENGTH];
	u_int8_t	m[SANCTUM_KEY_LENGTH];
} __attribute__((packed));

void	fatal(const char *, ...);

int
main(void)
{
	int				fd;
	ssize_t				ret;
	struct encdec_test		encdec;
	struct keygen_test		keygen;
	struct sanctum_mlkem1024	ref, test;
	u_int8_t			coins[2 * SANCTUM_KEY_LENGTH];

	if ((fd = open(KEYGEN_TEST, O_RDONLY)) == -1)
		fatal("open: %s", KEYGEN_TEST);

	printf("keygen tests:\n");

	for (;;) {
		if ((ret = read(fd, &keygen, sizeof(keygen))) == -1)
			fatal("read: %s", KEYGEN_TEST);

		if (ret == 0)
			break;

		if ((size_t)ret != sizeof(keygen)) {
			fatal("failed to read test case (%zd/%zu)",
			    ret, sizeof(keygen));
		}

		memcpy(&coins[0], keygen.d, sizeof(keygen.d));
		memcpy(&coins[sizeof(keygen.d)], keygen.z, sizeof(keygen.z));

		memcpy(ref.pk, keygen.ek, sizeof(keygen.ek));
		memcpy(ref.sk, keygen.dk, sizeof(keygen.dk));

		(void)pqcrystals_kyber1024_ref_keypair_derand(test.pk,
		    test.sk, coins);

		if (memcmp(test.pk, ref.pk, sizeof(test.pk)))
			fatal("test.ek != ref.ek (%d)", keygen.tcid);

		if (memcmp(test.sk, ref.sk, sizeof(test.sk)))
			fatal("test.dk != ref.dk (%d)", keygen.tcid);

		printf("  NIST ACVP tcid %d passed\n", keygen.tcid);
	}

	(void)close(fd);

	if ((fd = open(ENCDEC_TEST, O_RDONLY)) == -1)
		fatal("open: %s", ENCDEC_TEST);

	printf("encap/decap tests:\n");

	for (;;) {
		if ((ret = read(fd, &encdec, sizeof(encdec))) == -1)
			fatal("read: %s", ENCDEC_TEST);

		if (ret == 0)
			break;

		if ((size_t)ret != sizeof(encdec)) {
			fatal("failed to read test case (%zd/%zu)",
			    ret, sizeof(encdec));
		}

		memcpy(ref.pk, encdec.ek, sizeof(encdec.ek));
		memcpy(ref.sk, encdec.dk, sizeof(encdec.dk));

		(void)pqcrystals_kyber1024_ref_enc_derand(test.ct,
		    test.ss, ref.pk, encdec.m);

		if (memcmp(test.ct, encdec.ct, sizeof(encdec.ct)))
			fatal("test.ct != encdec.ct (%d)", encdec.tcid);

		if (memcmp(test.ss, encdec.k, sizeof(encdec.k)))
			fatal("test.ss != k (%d)", encdec.tcid);

		memcpy(ref.ct, encdec.ct, sizeof(encdec.ct));
		(void)pqcrystals_kyber1024_ref_dec(ref.ss, ref.ct, ref.sk);

		if (memcmp(ref.ss, encdec.k, sizeof(encdec.k)))
			fatal("ref.ss != k (%d)", encdec.tcid);

		printf("  NIST ACVP tcid %d passed\n", encdec.tcid);
	}

	(void)close(fd);
	printf("all tests passed\n");

	return (0);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");
	exit(1);
}
