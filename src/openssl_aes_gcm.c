/*
 * Copyright (c) 2023-2024 Joris Vink <joris@sanctorum.se>
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
 * AES-GCM support via OpenSSL its libcrypto.
 *
 * Since OpenSSL doesn't know what its users actually want we
 * have to disable some deprecated warning vomit.
 */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <sys/types.h>

#include <openssl/aes.h>
#include <openssl/modes.h>

#include <stdio.h>

#include "sanctum.h"

#define CIPHER_AES_GCM_TAG_SIZE		16

/*
 * The local cipher state.
 */
struct cipher_aes_gcm {
	AES_KEY			key;
	GCM128_CONTEXT		*gcm;
};

/* The cipher indicator for -v. */
const char	*sanctum_cipher = "openssl-aes-gcm";

/*
 * Setup the AES-GCM cipher by running key expansion first on the
 * given AES key.
 *
 * Then initialising a GCM128_CONTEXT with said key.
 */
void *
sanctum_cipher_setup(struct sanctum_key *key)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(key != NULL);

	if ((cipher = calloc(1, sizeof(*cipher))) == NULL)
		fatal("failed to allocate cipher context");

	nyfe_zeroize_register(cipher, sizeof(*cipher));

	if (AES_set_encrypt_key(key->key, 256, &cipher->key) != 0)
		fatal("AES_set_encrypt_key: failed");

	if ((cipher->gcm = CRYPTO_gcm128_new(&cipher->key,
	    (block128_f)AES_encrypt)) == NULL)
		fatal("CRYPTO_gcm128_new: failed");

	return (cipher);
}

/*
 * Returns the overhead for AES-GCM. In this case it's the
 * 16 byte tag.
 */
size_t
sanctum_cipher_overhead(void)
{
	return (CIPHER_AES_GCM_TAG_SIZE);
}

/*
 * Encrypt the packet data.
 * Automatically adds the integrity tag at the end of the ciphertext.
 */
void
sanctum_cipher_encrypt(void *arg, const void *nonce, size_t nonce_len,
    const void *aad, size_t aad_len, struct sanctum_packet *pkt)
{
	struct cipher_aes_gcm	*cipher;
	u_int8_t		*data, *tag;

	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	VERIFY(pkt->length + CIPHER_AES_GCM_TAG_SIZE < sizeof(pkt->buf));

	cipher = arg;

	data = sanctum_packet_data(pkt);
	tag = data + pkt->length;

	CRYPTO_gcm128_setiv(cipher->gcm, nonce, nonce_len);

	if (CRYPTO_gcm128_aad(cipher->gcm, aad, aad_len) != 0)
		fatal("CRYPTO_gcm128_aad failed");

	if (CRYPTO_gcm128_encrypt(cipher->gcm, data, data, pkt->length) != 0)
		fatal("CRYPTO_gcm128_encrypt failed");

	CRYPTO_gcm128_tag(cipher->gcm, tag, CIPHER_AES_GCM_TAG_SIZE);

	pkt->length += CIPHER_AES_GCM_TAG_SIZE;
}

/*
 * Verify and decrypts a given packet.
 */
int
sanctum_cipher_decrypt(void *arg, const void *nonce, size_t nonce_len,
    const void *aad, size_t aad_len, struct sanctum_packet *pkt)
{
	struct cipher_aes_gcm	*cipher;
	size_t			ctlen, len;
	u_int8_t		*data, *tag;

	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	if (pkt->length <
	    sizeof(struct sanctum_ipsec_hdr) + CIPHER_AES_GCM_TAG_SIZE)
		return (-1);

	cipher = arg;
	len = pkt->length - sizeof(struct sanctum_ipsec_hdr);

	data = sanctum_packet_data(pkt);
	tag = &data[len - CIPHER_AES_GCM_TAG_SIZE];
	ctlen = tag - data;

	CRYPTO_gcm128_setiv(cipher->gcm, nonce, nonce_len);

	if (CRYPTO_gcm128_aad(cipher->gcm, aad, aad_len) != 0)
		fatal("CRYPTO_gcm128_aad failed");

	if (CRYPTO_gcm128_decrypt(cipher->gcm, data, data, ctlen) != 0)
		fatal("CRYPTO_gcm128_decrypt failed");

	if (CRYPTO_gcm128_finish(cipher->gcm, tag,
	    CIPHER_AES_GCM_TAG_SIZE) != 0)
		return (-1);

	return (0);
}

/*
 * Cleanup the AES-GCM cipher states.
 */
void
sanctum_cipher_cleanup(void *arg)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(arg != NULL);

	cipher = arg;

	CRYPTO_gcm128_release(cipher->gcm);
	nyfe_zeroize(cipher, sizeof(*cipher));

	free(cipher);
}
