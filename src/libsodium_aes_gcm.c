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

#include <sodium.h>

#include "sanctum.h"

/*
 * State structure, we only need to hold the key here.
 */
struct cipher_aes_gcm {
	crypto_aead_aes256gcm_state	ctx;
};

/* The cipher indicator for -v. */
const char	*sanctum_cipher = "libsodium-aes-gcm";

/*
 * Perform any one-time cipher initialization.
 */
void
sanctum_cipher_init(void)
{
	if (sodium_init() == -1)
		fatal("failed to initialize libsodium");
}

/*
 * Setup the cipher for use in bless and confess.
 */
void *
sanctum_cipher_setup(struct sanctum_key *key)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(key != NULL);

	if ((cipher = calloc(1, sizeof(*cipher))) == NULL)
		fatal("failed to allocate cipher context");

	nyfe_zeroize_register(cipher, sizeof(*cipher));

	if (crypto_aead_aes256gcm_beforenm(&cipher->ctx, key->key) == -1)
		fatal("failed to do key expansion");

	return (cipher);
}

/*
 * Returns the overhead for AES-GCM.
 * In this case it's the 16 byte tag.
 */
size_t
sanctum_cipher_overhead(void)
{
	return (crypto_aead_aes256gcm_ABYTES);
}

/*
 * Encrypt the packet data.
 * Automatically adds the integrity tag at the end of the ciphertext.
 */
void
sanctum_cipher_encrypt(void *arg, const void *nonce, size_t nonce_len,
    const void *aad, size_t aad_len, struct sanctum_packet *pkt)
{
	unsigned long long	mlen;
	u_int8_t		*data;
	struct cipher_aes_gcm	*cipher;

	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(nonce_len == crypto_aead_aes256gcm_NPUBBYTES);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	VERIFY(pkt->length + crypto_aead_aes256gcm_ABYTES < sizeof(pkt->buf));

	cipher = arg;
	mlen = pkt->length;
	data = sanctum_packet_data(pkt);

	if (crypto_aead_aes256gcm_encrypt_afternm(data, &mlen, data, mlen,
	    aad, aad_len, NULL, nonce, &cipher->ctx) == -1)
		return;

	pkt->length += crypto_aead_aes256gcm_ABYTES;
}

/*
 * Decrypt and verify a packet, returns -1 on error or 0 on success.
 */
int
sanctum_cipher_decrypt(void *arg, const void *nonce, size_t nonce_len,
    const void *aad, size_t aad_len, struct sanctum_packet *pkt)
{
	size_t			len;
	u_int8_t		*data;
	struct cipher_aes_gcm	*cipher;

	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(nonce_len == crypto_aead_aes256gcm_NPUBBYTES);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	if (pkt->length <
	    sizeof(struct sanctum_ipsec_hdr) + crypto_aead_aes256gcm_ABYTES)
		return (-1);

	cipher = arg;
	data = sanctum_packet_data(pkt);
	len = pkt->length - sizeof(struct sanctum_ipsec_hdr);

	if (crypto_aead_aes256gcm_decrypt_afternm(data, NULL, NULL,
	    data, len, aad, aad_len, nonce, &cipher->ctx) == -1)
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

	nyfe_zeroize(cipher, sizeof(*cipher));
	free(cipher);
}
