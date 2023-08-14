/*
 * Copyright (c) 2023 Joris Vink <joris@sanctorum.se>
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

#define CIPHER_AES_GCM_TAG_SIZE		16

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

/*
 * Setup the cipher.
 */
void *
sanctum_cipher_setup(struct sanctum_key *key)
{
	struct cipher_aes_gcm	*cipher;

	PRECOND(key != NULL);

	if ((cipher = calloc(1, sizeof(*cipher))) == NULL)
		fatal("failed to allocate cipher context");

	aes_gcm_pre_256(key->key, &cipher->key);

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
	union deconst		nptr;
	struct cipher_aes_gcm	*cipher;
	u_int8_t		*data, *tag;

	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	VERIFY(pkt->length + CIPHER_AES_GCM_TAG_SIZE < sizeof(pkt->buf));

	cipher = arg;
	nptr.cp = nonce;

	data = sanctum_packet_data(pkt);
	tag = data + pkt->length;

	aes_gcm_enc_256(&cipher->key, &cipher->gcm, data, data,
	    pkt->length, nptr.p, aad, aad_len, tag, CIPHER_AES_GCM_TAG_SIZE);

	pkt->length += CIPHER_AES_GCM_TAG_SIZE;
}

/*
 * Decrypt and verify a packet.
 */
int
sanctum_cipher_decrypt(void *arg, const void *nonce, size_t nonce_len,
    const void *aad, size_t aad_len, struct sanctum_packet *pkt)
{
	union deconst		nptr;
	size_t			ctlen;
	struct cipher_aes_gcm	*cipher;
	u_int8_t		*data, *tag, calc[CIPHER_AES_GCM_TAG_SIZE];

	PRECOND(arg != NULL);
	PRECOND(nonce != NULL);
	PRECOND(aad != NULL);
	PRECOND(pkt != NULL);

	if (pkt->length < CIPHER_AES_GCM_TAG_SIZE)
		return (-1);

	cipher = arg;
	nptr.cp = nonce;

	data = sanctum_packet_data(pkt);
	tag = &pkt->buf[pkt->length - CIPHER_AES_GCM_TAG_SIZE];
	ctlen = tag - data;

	aes_gcm_dec_256(&cipher->key, &cipher->gcm, data, data,
	    ctlen, nptr.p, aad, aad_len, calc, sizeof(calc));

	if (memcmp(tag, calc, sizeof(calc)))
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

	sanctum_mem_zero(cipher, sizeof(*cipher));
	free(cipher);
}
