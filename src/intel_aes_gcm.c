/*
 * Copyright (c) 2023-2025 Joris Vink <joris@sanctorum.se>
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

/*
 * AES-GCM via the Intel "ISA-L_crypto" library.
 */

#include <sys/types.h>

#include <isa-l_crypto.h>
#include <stdio.h>

#include "sanctum.h"

/*
 * The local cipher state.
 */
struct cipher_aes_gcm {
	struct gcm_key_data		key;
	struct gcm_context_data		gcm;
};

/*
 * The functions we use needs non const pointers for ivs so we do a dirty.
 */
union deconst {
	void		*p;
	const void	*cp;
};

/* The cipher indicator for -v. */
const char	*sanctum_cipher = "intel-aes-gcm";

/*
 * Perform any one-time cipher initialization.
 */
void
sanctum_cipher_init(void)
{
}

/*
 * Setup the cipher for use.
 */
void *
sanctum_cipher_setup(struct sanctum_key *key)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(key != NULL);

	if ((cipher = calloc(1, sizeof(*cipher))) == NULL)
		fatal("failed to allocate cipher context");

	nyfe_zeroize_register(cipher, sizeof(*cipher));
	aes_gcm_pre_256(key->key, &cipher->key);

	return (cipher);
}

/*
 * Encrypt and authenticate some data in combination with the given nonce
 * aad, etc.
 */
void
sanctum_cipher_encrypt(struct sanctum_cipher *cipher)
{
	struct cipher_aes_gcm	*ctx;

	PRECOND(cipher != NULL);

	VERIFY(cipher->pt != NULL);
	VERIFY(cipher->ct != NULL);
	VERIFY(cipher->tag != NULL);
	VERIFY(cipher->aad != NULL);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == SANCTUM_NONCE_LENGTH);

	ctx = cipher->ctx;

	aes_gcm_enc_256(&ctx->key, &ctx->gcm, cipher->ct, cipher->pt,
	    cipher->data_len, cipher->nonce, cipher->aad, cipher->aad_len,
	    cipher->tag, SANCTUM_TAG_LENGTH);
}

/*
 * Decrypt and authenticate some data in combination with the given nonce,
 * aad etc. Returns -1 if the data was unable to be authenticated.
 */
int
sanctum_cipher_decrypt(struct sanctum_cipher *cipher)
{
	struct cipher_aes_gcm	*ctx;
	u_int8_t		tag[SANCTUM_TAG_LENGTH];

	PRECOND(cipher != NULL);

	VERIFY(cipher->pt != NULL);
	VERIFY(cipher->ct != NULL);
	VERIFY(cipher->tag != NULL);
	VERIFY(cipher->aad != NULL);
	VERIFY(cipher->nonce != NULL);
	VERIFY(cipher->nonce_len == SANCTUM_NONCE_LENGTH);

	ctx = cipher->ctx;

	aes_gcm_dec_256(&ctx->key, &ctx->gcm, cipher->pt, cipher->ct,
	    cipher->data_len, cipher->nonce, cipher->aad, cipher->aad_len,
	    tag, sizeof(tag));

	if (nyfe_mem_cmp(cipher->tag, tag, sizeof(tag)))
		return (-1);

	return (0);
}

/*
 * Cleanup the cipher states.
 */
void
sanctum_cipher_cleanup(void *arg)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(arg != NULL);

	cipher = arg;

	nyfe_zeroize(cipher, sizeof(*cipher));
	free(cipher);
}
