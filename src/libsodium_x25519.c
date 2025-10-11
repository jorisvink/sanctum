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

#include <sodium.h>

#include "sanctum.h"

/* The indicator for -v. */
const char	*sanctum_asymmetry = "libsodium-x25519";

/*
 * Perform any one-time asymmetry initialization.
 */
void
sanctum_asymmetry_init(void)
{
	if (sodium_init() == -1)
		fatal("failed to initialize libsodium");
}

/*
 * Generate a new x25519 private key and derive its public key from it.
 */
int
sanctum_asymmetry_keygen(u_int8_t *priv, size_t privlen,
    u_int8_t *pub, size_t publen)
{
	PRECOND(priv != NULL);
	PRECOND(privlen == crypto_scalarmult_curve25519_SCALARBYTES);
	PRECOND(pub != NULL);
	PRECOND(publen == crypto_scalarmult_curve25519_SCALARBYTES);

	sanctum_random_bytes(priv, privlen);

	/*
	 * The libsodium scalarmult base function will clamp the
	 * private key as required.
	 */
	if (crypto_scalarmult_curve25519_base(pub, priv) == -1)
		return (-1);

	return (0);
}

/*
 * Using the peer its public key derive a shared secret.
 */
int
sanctum_asymmetry_derive(struct sanctum_kex *kex, u_int8_t *out, size_t len)
{
	PRECOND(kex != NULL);
	PRECOND(out != NULL);
	PRECOND(len == crypto_scalarmult_curve25519_SCALARBYTES);

	if (crypto_scalarmult_curve25519(out, kex->private, kex->remote) == -1)
		return (-1);

	return (0);
}
