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

#include <sys/types.h>

#include <string.h>

#include "nyfe.h"

#define SHA3_PADDING		'\x06'
#define SHAKE_PADDING		'\x1f'

/*
 * Initializes an nyfe_sha3 context for use as a SHA3-256() context.
 */
void
nyfe_sha3_init256(struct nyfe_sha3 *ctx)
{
	PRECOND(ctx != NULL);

	nyfe_mem_zero(ctx, sizeof(*ctx));
	nyfe_keccak1600_init(&ctx->keccak, SHA3_PADDING, 512);

	ctx->digest_len = 32;
}

/*
 * Initializes an nyfe_sha3 context for use as a SHA3-512() context.
 */
void
nyfe_sha3_init512(struct nyfe_sha3 *ctx)
{
	PRECOND(ctx != NULL);

	nyfe_mem_zero(ctx, sizeof(*ctx));
	nyfe_keccak1600_init(&ctx->keccak, SHA3_PADDING, 1024);

	ctx->digest_len = 64;
}

/*
 * Initializes an nyfe_sha3 context for use as a SHAKE-128() context.
 */
void
nyfe_xof_shake128_init(struct nyfe_sha3 *ctx)
{
	PRECOND(ctx != NULL);

	nyfe_mem_zero(ctx, sizeof(*ctx));
	nyfe_keccak1600_init(&ctx->keccak, SHAKE_PADDING, 256);

	ctx->digest_len = 0;
}

/*
 * Initializes an nyfe_sha3 context for use as a SHAKE-256() context.
 */
void
nyfe_xof_shake256_init(struct nyfe_sha3 *ctx)
{
	PRECOND(ctx != NULL);

	nyfe_mem_zero(ctx, sizeof(*ctx));
	nyfe_keccak1600_init(&ctx->keccak, SHAKE_PADDING, 512);

	ctx->digest_len = 0;
}

/*
 * Absorb indata from the caller into the underlying keccak1600 state,
 * saving any remaining bytes in our local context buffer.
 */
void
nyfe_sha3_update(struct nyfe_sha3 *ctx, const void *buf, size_t len)
{
	const u_int8_t		*ptr;
	size_t			left;

	PRECOND(ctx != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);
	PRECOND(ctx->offset <= sizeof(ctx->buf) &&
	    (ctx->offset <= ctx->keccak.rate));

	ptr = buf;

	if (ctx->offset > 0) {
		left = ctx->keccak.rate - ctx->offset;
		if (len < left) {
			memcpy(&ctx->buf[ctx->offset], ptr, len);
			ctx->offset += len;
			return;
		}

		if (left > 0) {
			memcpy(&ctx->buf[ctx->offset], ptr, left);
			ctx->offset += left;
		}

		len -= left;
		ptr += left;

		VERIFY(ctx->offset == ctx->keccak.rate);
		nyfe_keccak1600_absorb(&ctx->keccak, ctx->buf, ctx->offset);

		ctx->offset = 0;
	}

	if (len > 0) {
		left = nyfe_keccak1600_absorb(&ctx->keccak, ptr, len);
		if (left > 0) {
			memcpy(ctx->buf, &ptr[len - left], left);
			ctx->offset = left;
		}
	}
}

/*
 * Pad and absorb any lingering data from out context into the underlying
 * keccak1600 state.
 *
 * After that squeeze out the requested amount of bytes from the keccak1600
 * state. For SHA3-256 and SHA-512 the outlen must match their digest lengths.
 *
 * For the XOF functions the outlen may be variable.
 */
void
nyfe_sha3_final(struct nyfe_sha3 *ctx, u_int8_t *out, size_t outlen)
{
	size_t		left;

	PRECOND(ctx != NULL);
	PRECOND(out != NULL);
	PRECOND(ctx->offset < sizeof(ctx->buf));
	PRECOND(ctx->offset < ctx->keccak.rate);

	left = ctx->keccak.rate - ctx->offset;
	memset(&ctx->buf[ctx->offset], 0, left);

	ctx->buf[ctx->offset] = ctx->keccak.padding;
	ctx->buf[ctx->keccak.rate - 1] |= 0x80;

	nyfe_keccak1600_absorb(&ctx->keccak, ctx->buf, ctx->keccak.rate);

	if (ctx->digest_len != 0) {
		VERIFY(outlen == ctx->digest_len);
		nyfe_keccak1600_squeeze(&ctx->keccak, out, ctx->digest_len);
	} else {
		nyfe_keccak1600_squeeze(&ctx->keccak, out, outlen);
	}
}
