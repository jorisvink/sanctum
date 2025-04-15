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

#include "sanctum.h"

/*
 * Note that the reference implementation its KEM functions are all
 * declared as returning an int but do not actually return error codes.
 *
 * Good thing they're good at math instead.
 */

/*
 * Generate a new ML-KEM-768 keypair. The public key part is to be sent
 * to our peer who will encapsulate a secret value with it. We then use
 * the secret part of the keypair to decapsulate it revealing the same secret.
 */
void
sanctum_mlkem768_keypair(struct sanctum_mlkem768 *ctx)
{
	PRECOND(ctx != NULL);

	(void)pqcrystals_kyber768_ref_keypair(ctx->pk, ctx->sk);
}

/*
 * Encapsulate a secret we wish to share with our peer using the public
 * key we have received from said peer.
 *
 * The computed ciphertext that we will send to our peer is written
 * to ctx->ct and the shared secret is written to ctx->ss.
 *
 * Note that you must have populated the ctx->pk member with the
 * peer its public key before calling this function.
 */
void
sanctum_mlkem768_encapsulate(struct sanctum_mlkem768 *ctx)
{
	PRECOND(ctx != NULL);

	(void)pqcrystals_kyber768_ref_enc(ctx->ct, ctx->ss, ctx->pk);
}

/*
 * Decapsulate the received ciphertext with our secret key and
 * reveal the shared secret.
 *
 * The shared secret is written into ctx->ss.
 *
 * Note that you must have populated ctx->ct with the ciphertext
 * we received from the peer before calling this function.
 */
void
sanctum_mlkem768_decapsulate(struct sanctum_mlkem768 *ctx)
{
	PRECOND(ctx != NULL);

	(void)pqcrystals_kyber768_ref_dec(ctx->ss, ctx->ct, ctx->sk);
}
