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

#include <stdio.h>

#include <mbedtls/error.h>
#include <mbedtls/gcm.h>

#include "sanctum.h"

/*
 * State structure, we only hold the mbedtls gcm context here.
 */
struct cipher_aes_gcm {
	mbedtls_gcm_context		gcm;
};

static const char	*cipher_strerror(int);

/* The cipher indicator for -v. */
const char	*sanctum_cipher = "mbedtls-aes-gcm";

/*
 * Perform any one-time cipher initialization.
 */
void
sanctum_cipher_init(void)
{
	int	ret;

	if ((ret = mbedtls_gcm_self_test(0)) != 0)
		fatal("mbedtls_gcm_self_test: %s", cipher_strerror(ret));
}

/*
 * Setup the cipher for use.
 */
void *
sanctum_cipher_setup(struct sanctum_key *key)
{
	int			ret;
	struct cipher_aes_gcm	*cipher;

	PRECOND(key != NULL);

	if ((cipher = calloc(1, sizeof(*cipher))) == NULL)
		fatal("failed to allocate cipher context");

	nyfe_zeroize_register(cipher, sizeof(*cipher));

	mbedtls_gcm_init(&cipher->gcm);

	if ((ret = mbedtls_gcm_setkey(&cipher->gcm,
	    MBEDTLS_CIPHER_ID_AES, key->key, 256)) != 0)
		fatal("mbedtls_gcm_setkey: %s", cipher_strerror(ret));

	return (cipher);
}

/*
 * Encrypt and authenticate some data in combination with the given nonce
 * aad, etc.
 */
void
sanctum_cipher_encrypt(struct sanctum_cipher *cipher)
{
	int			ret;
	struct cipher_aes_gcm	*ctx;
	size_t			data_len;

	PRECOND(cipher != NULL);

	VERIFY(cipher->pt != NULL);
	VERIFY(cipher->ct != NULL);
	VERIFY(cipher->tag != NULL);
	VERIFY(cipher->aad != NULL);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == SANCTUM_NONCE_LENGTH);

	ctx = cipher->ctx;

	if ((ret = mbedtls_gcm_starts(&ctx->gcm, MBEDTLS_GCM_ENCRYPT,
	    cipher->nonce, cipher->nonce_len)) != 0)
		fatal("mbedtls_gcm_starts: %s", cipher_strerror(ret));

	if ((ret = mbedtls_gcm_update_ad(&ctx->gcm,
	    cipher->aad, cipher->aad_len)) != 0)
		fatal("mbedtls_gcm_update_ad: %s", cipher_strerror(ret));

	if ((ret = mbedtls_gcm_update(&ctx->gcm, cipher->pt,
	    cipher->data_len, cipher->pt, cipher->data_len, &data_len)) != 0)
		fatal("mbedtls_gcm_update: %s", cipher_strerror(ret));

	VERIFY(data_len == cipher->data_len);

	if ((ret = mbedtls_gcm_finish(&ctx->gcm, NULL, 0,
	    &data_len, cipher->tag, SANCTUM_TAG_LENGTH)) != 0)
		fatal("mbedtls_gcm_finish: %s", cipher_strerror(ret));

	VERIFY(data_len == 0);
}

/*
 * Decrypt and authenticate some data in combination with the given nonce,
 * aad etc. Returns -1 if the data was unable to be authenticated.
 */
int
sanctum_cipher_decrypt(struct sanctum_cipher *cipher)
{
	int			ret;
	struct cipher_aes_gcm	*ctx;
	size_t			data_len;
	u_int8_t		tag[SANCTUM_TAG_LENGTH];

	PRECOND(cipher != NULL);

	VERIFY(cipher->pt != NULL);
	VERIFY(cipher->ct != NULL);
	VERIFY(cipher->tag != NULL);
	VERIFY(cipher->aad != NULL);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == SANCTUM_NONCE_LENGTH);

	ctx = cipher->ctx;

	if ((ret = mbedtls_gcm_starts(&ctx->gcm, MBEDTLS_GCM_DECRYPT,
	    cipher->nonce, cipher->nonce_len)) != 0)
		fatal("mbedtls_gcm_starts: %s", cipher_strerror(ret));

	if ((ret = mbedtls_gcm_update_ad(&ctx->gcm,
	    cipher->aad, cipher->aad_len)) != 0)
		fatal("mbedtls_gcm_update_ad: %s", cipher_strerror(ret));

	if ((ret = mbedtls_gcm_update(&ctx->gcm, cipher->pt,
	    cipher->data_len, cipher->pt, cipher->data_len, &data_len)) != 0)
		fatal("mbedtls_gcm_update: %s", cipher_strerror(ret));

	VERIFY(data_len == cipher->data_len);

	if ((ret = mbedtls_gcm_finish(&ctx->gcm, NULL, 0,
	    &data_len, tag, sizeof(tag))) != 0)
		fatal("mbedtls_gcm_finish: %s", cipher_strerror(ret));

	VERIFY(data_len == 0);

	if (nyfe_mem_cmp(cipher->tag, tag, sizeof(tag)))
		return (-1);

	return (0);
}

/*
 * Cleanup and wipe the cipher state.
 */
void
sanctum_cipher_cleanup(void *arg)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(arg != NULL);

	cipher = arg;

	mbedtls_gcm_free(&cipher->gcm);
	free(cipher);
}

/*
 * Helper function to convert the given error into a human readable
 * string and return a pointer to it to the caller.
 */
static const char *
cipher_strerror(int err)
{
	static char	buf[128];

	mbedtls_strerror(err, buf, sizeof(buf));

	return (buf);
}
