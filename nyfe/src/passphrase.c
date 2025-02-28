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
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nyfe.h"

/*
 * The nyfe_passphrase_kdf(passphrase, salt) function:
 *
 *	tmp = Intermediate buffer holding pseudorandom data
 *	ap = Pseudorandom generated list of accesses into tmp
 *	buf = SHAKE256(len(passphrase) || passphrase || salt)[512]
 *	Kt = 512-bit Agelas key to generate key stream (buf_0[0..63])
 *	Km = 256-bit KMAC256 key (tmp[0..31])
 *
 *	ap = SHAKE256(buf[0..255])[PASSPHRASE_KDF_AP_SIZE]
 *	tmp = SHAKE256(buf[256..512])[PASSPHRASE_KDF_MEM_SIZE]
 *	tmp = Agelas(Kt, tmp, aad=None)
 *
 *	for iter = 0, iter < PASSPHRASE_KDF_ITERATIONS; do
 *		offset = ap[iter] * PASSPHRASE_KDF_STEP_LEN
 *		if iter % 2048 == 0; do
 *			Agelas(Kt,tmp[offset..PASSPHRASE_KDF_MEM_SIZE - offset])
 *		tmp[offset..offset+256] ^= SHAKE256(tmp[0..255])
 *
 *	X = tmp[32..PASSPHRASE_KDF_MEM_SIZE]
 *	return KMAC256(Km, X, "NYFE.PASSPHRASE.KDF")[64]
 */

/* Passphrase KDF settings, will use 32MB memory, 65536 iterations. */
#define PASSPHRASE_KDF_ITERATIONS	65536
#define PASSPHRASE_KDF_MEM_SIZE		(1024 * 1024 * 32)
#define PASSPHRASE_KDF_STEP_LEN		\
    (PASSPHRASE_KDF_MEM_SIZE / PASSPHRASE_KDF_ITERATIONS)
#define PASSPHRASE_KDF_AP_SIZE		\
    (PASSPHRASE_KDF_ITERATIONS * sizeof(u_int16_t))

/*
 * Derives a 256-bit key from the given passphrase and salt using
 * SHAKE256, Agelas and KMAC256 using a large amount of memory
 * and pseudorandom access patterns.
 */
void
nyfe_passphrase_kdf(const void *passphrase, u_int32_t passphrase_len,
    const void *salt, size_t salt_len, u_int8_t *out, size_t out_len)
{
	u_int16_t			*ap;
#if !defined(NYFE_LIBRARY_ONLY)
	int				sig;
#endif
	struct nyfe_kmac256		kmac;
	struct nyfe_sha3		shake;
	struct nyfe_agelas		stream;
	size_t				idx, offset;
	u_int32_t			iter, counter;
	u_int8_t			*tmp, buf[512];

	PRECOND(passphrase != NULL);
	PRECOND(salt != NULL);
	PRECOND(salt_len == NYFE_KEY_FILE_SALT_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == NYFE_KEY_LEN);

	/* Allocate large intermediate buffers. */
	if ((tmp = calloc(1, PASSPHRASE_KDF_MEM_SIZE)) == NULL)
		fatal("failed to allocate temporary kdf buffer");
	if ((ap = calloc(1, PASSPHRASE_KDF_AP_SIZE)) == NULL)
		fatal("failed to allocate temporary kdf access patterns");

	/* Register buffers / structs that contain sensitive information. */
	nyfe_zeroize_register(buf, sizeof(buf));
	nyfe_zeroize_register(&kmac, sizeof(kmac));
	nyfe_zeroize_register(&shake, sizeof(shake));
	nyfe_zeroize_register(&stream, sizeof(stream));
	nyfe_zeroize_register(ap, PASSPHRASE_KDF_AP_SIZE);
	nyfe_zeroize_register(tmp, PASSPHRASE_KDF_MEM_SIZE);

	/*
	 * Run the passphrase and the salt through SHAKE256() to obtain
	 * 512 bytes of output. This output is used to generate the
	 * intermediate plaintext data, and the access patterns.
	 */
	nyfe_xof_shake256_init(&shake);
	nyfe_sha3_update(&shake, &passphrase_len, sizeof(passphrase_len));
	nyfe_sha3_update(&shake, passphrase, passphrase_len);
	nyfe_sha3_update(&shake, salt, salt_len);
	nyfe_sha3_final(&shake, buf, sizeof(buf));

	/* Generate access patterns based on first half of buf. */
	nyfe_xof_shake256_init(&shake);
	nyfe_sha3_update(&shake, &buf[0], sizeof(buf) / 2);
	nyfe_sha3_final(&shake, (u_int8_t *)ap, PASSPHRASE_KDF_AP_SIZE);

	/*
	 * Generate the intermediate plaintext data using the second half
	 * of buf and encrypt it under Agelas.
	 */
	nyfe_xof_shake256_init(&shake);
	nyfe_sha3_update(&shake, &buf[sizeof(buf) / 2], sizeof(buf) / 2);
	nyfe_sha3_final(&shake, tmp, PASSPHRASE_KDF_MEM_SIZE);

	nyfe_agelas_init(&stream, &buf[0], NYFE_KEY_LEN);
	nyfe_agelas_encrypt(&stream, tmp, tmp, PASSPHRASE_KDF_MEM_SIZE);

	/* Using nyfe_mem_zero() here since buf is still used later. */
	nyfe_mem_zero(buf, sizeof(buf));

	/*
	 * For each iteration:
	 *	- Grab the access location from ap.
	 *	- offset = ap * PASSPHRASE_KDF_STEP_LEN
	 *	- iter % 2048 == 0:
	 *		tmp[offset] <- Agelas(tmp[offset])
	 *	- buf <- SHAKE256(iteration || tmp[offset)
	 *	- tmp[offset] ^= buf
	 */
	for (iter = 0; iter < PASSPHRASE_KDF_ITERATIONS; iter++) {
#if !defined(NYFE_LIBRARY_ONLY)
		if ((sig = nyfe_signal_pending()) != -1)
			fatal("clean abort due to received signal %d", sig);
#endif

		offset = ap[iter] * PASSPHRASE_KDF_STEP_LEN;

		/*
		 * Every 2048th iteration run part of the intermediate data
		 * through the Agelas cipher.
		 */
		if ((iter % 2048) == 0) {
#if !defined(NYFE_LIBRARY_ONLY)
			nyfe_output_spin();
#endif
			nyfe_agelas_encrypt(&stream,
			    &tmp[offset], &tmp[offset],
			    PASSPHRASE_KDF_MEM_SIZE - offset);
		}

		counter = htobe32(iter);
		nyfe_xof_shake256_init(&shake);
		nyfe_sha3_update(&shake, &counter, sizeof(counter));
		nyfe_sha3_update(&shake, &tmp[offset], PASSPHRASE_KDF_STEP_LEN);
		nyfe_sha3_final(&shake, buf, PASSPHRASE_KDF_STEP_LEN);

		for (idx = 0; idx < PASSPHRASE_KDF_STEP_LEN; idx++)
			tmp[offset] ^= buf[idx];
	}

	/* No longer need any of these intermediates. */
	nyfe_zeroize(buf, sizeof(buf));
	nyfe_zeroize(&shake, sizeof(shake));
	nyfe_zeroize(&stream, sizeof(stream));

	/*
	 * Use KMAC256() to derive the requested okm.
	 *
	 * The first 32 bytes of the tmp data is used as K for KMAC256
	 * while the remainder is used as X.
	 */
	iter = htobe32(PASSPHRASE_KDF_MEM_SIZE - 32);
	nyfe_kmac256_init(&kmac, tmp, 32, NYFE_PASSPHRASE_DERIVE_LABEL,
	    sizeof(NYFE_PASSPHRASE_DERIVE_LABEL) - 1);
	nyfe_kmac256_update(&kmac, &iter, sizeof(iter));
	nyfe_kmac256_update(&kmac, &tmp[32], PASSPHRASE_KDF_MEM_SIZE - 32);
	nyfe_kmac256_final(&kmac, out, out_len);
	nyfe_zeroize(&kmac, sizeof(kmac));

	nyfe_zeroize(tmp, PASSPHRASE_KDF_MEM_SIZE);
	nyfe_zeroize(ap, PASSPHRASE_KDF_AP_SIZE);

	free(ap);
	free(tmp);
}
