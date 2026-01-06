/*
 * Copyright (c) 2025-2026 Joris Vink <joris@sanctorum.se>
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

#include <sodium.h>
#include <unistd.h>

#include "sanctum.h"

/* The indicator for -v. */
const char	*sanctum_signature = "libsodium-ed25519";

/*
 * Perform any one-time signature initialisation.
 */
void
sanctum_signature_init(void)
{
	if (sodium_init() == -1)
		fatal("failed to initialize libsodium");
}

/*
 * Generate a signing key pair, this mostly exists to allow tools
 * to use this if they would require. Sanctum itself does not call this.
 */
int
sanctum_signature_keygen(u_int8_t *sk, size_t slen, u_int8_t *pk, size_t plen)
{
	PRECOND(sk != NULL);
	PRECOND(slen == SANCTUM_ED25519_SIGN_SECRET_LENGTH);
	PRECOND(pk != NULL);
	PRECOND(plen == SANCTUM_ED25519_SIGN_PUBLIC_LENGTH);

	if (crypto_sign_keypair(pk, sk) != 0)
		return (-1);

	return (0);
}

/*
 * Sign the given data with the provide secret key and place the
 * signature under ´sig'.
 */
int
sanctum_signature_create(const u_int8_t *sk, size_t sk_len, const void *data,
    size_t data_len, u_int8_t *sig, size_t sig_len)
{
	PRECOND(sk != NULL);
	PRECOND(sk_len == SANCTUM_ED25519_SIGN_SECRET_LENGTH);
	PRECOND(data != NULL);
	PRECOND(data_len > 0);
	PRECOND(sig != NULL);
	PRECOND(sig_len == SANCTUM_ED25519_SIGN_LENGTH);

	if (crypto_sign_detached(sig, NULL, data, data_len, sk) != 0)
		return (-1);

	return (0);
}

/*
 * Verify the given data against the provider signature using the public key.
 */
int
sanctum_signature_verify(const u_int8_t *pk, size_t pk_len, const void *data,
    size_t data_len, const u_int8_t *sig, size_t sig_len)
{
	PRECOND(pk != NULL);
	PRECOND(pk_len == SANCTUM_ED25519_SIGN_PUBLIC_LENGTH);
	PRECOND(data != NULL);
	PRECOND(data_len > 0);
	PRECOND(sig != NULL);
	PRECOND(sig_len == SANCTUM_ED25519_SIGN_LENGTH);

	if (crypto_sign_verify_detached(sig, data, data_len, pk) != 0)
		return (-1);

	return (0);
}
