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

#include <sys/param.h>
#include <sys/types.h>

#include <string.h>

#include "nyfe.h"

/*
 * An easy to read and verify Keccak1600 implementation.
 *
 * Note that due to C its arrays the x, y coordinates are reversed.
 */

#define rho(v)		((v % 64))

static u_int64_t	rotl64(u_int64_t, u_int64_t);

static void	keccak1600_rounds(struct nyfe_keccak1600 *);

/*
 * The Rho step bit shifting offsets for each coordinate in the matrix.
 * The rho() macro basically does mod 64 on these but this way they
 * are mappable to the standard.
 */
static const u_int8_t rho_offsets[5][5] = {
	{ rho(0), rho(1), rho(190), rho(28), rho(91) },
	{ rho(36), rho(300), rho(6), rho(55), rho(276) },
	{ rho(3), rho(10), rho(171), rho(153), rho(231) },
	{ rho(105), rho(45), rho(15), rho(21), rho(136) },
	{ rho(210), rho(66), rho(253), rho(120), rho(78) },
};

/*
 * Precalculated round constants for the Iota step.
 */
static const u_int64_t iota_rc[] = {
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808a,
	0x8000000080008000,
	0x000000000000808b,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008a,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000a,
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008
};

/*
 * Initialize a keccak1600 context. The caller supplies the number of
 * bits its requesting. This in combination with the padding byte used
 * denotes the type. We accept 256, 512, 768 and 1024 bits.
 *
 * This means the following SHA3 constructs can be made:
 *
 *	SHA3-256(M) = KECCAK[512] (M || 01, 256);
 *	SHA3-384(M) = KECCAK[768] (M || 01, 384);
 *	SHA3-512(M) = KECCAK[1024] (M || 01, 512).
 *
 * and the following XOF constructs:
 *
 *	SHAKE128(M, d) = KECCAK[256] (M || 1111, d),
 *	SHAKE256(M, d) = KECCAK[512] (M || 1111, d).
 */
void
nyfe_keccak1600_init(struct nyfe_keccak1600 *ctx, u_int8_t pad, size_t bits)
{
	PRECOND(ctx != NULL);
	PRECOND(bits == 256 || bits == 512 || bits == 768 || bits == 1024);
	PRECOND(pad == 0 || pad == '\x1f' || pad == '\x04' || pad == '\x06');

	nyfe_mem_zero(ctx, sizeof(*ctx));

	ctx->padding = pad;
	ctx->rate = (NYFE_KECCAK_1600_RATE - bits) / 8;
}

/*
 * Absorb data into the Keccak sponge.
 *
 * This is done at a fixed rate, this function will return the number
 * of lingering bytes it was unable to process.
 */
size_t
nyfe_keccak1600_absorb(struct nyfe_keccak1600 *ctx, const void *buf, size_t len)
{
	const u_int8_t		*ptr;
	size_t			i, b;
	u_int64_t		v, *array;

	PRECOND(ctx != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	ptr = buf;
	array = &ctx->A[0][0];

	while (len >= ctx->rate) {
		for (i = 0; i < (ctx->rate / 8); i++) {
			v = 0;

			for (b = 0; b < sizeof(v); b++)
				v |= (u_int64_t)ptr[b] << (b * 8);

			ptr += sizeof(v);
			array[i] ^= v;
		}

		keccak1600_rounds(ctx);
		len -= ctx->rate;
	}

	return (len);
}

/*
 * Squeeze out the requested amount of data from the sponge.
 */
void
nyfe_keccak1600_squeeze(struct nyfe_keccak1600 *ctx, void *buf, size_t len)
{
	u_int8_t		*ptr;
	u_int64_t		v, *array;
	size_t			i, b, left;

	PRECOND(ctx != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	ptr = buf;
	array = &ctx->A[0][0];

	while (len != 0) {
		for (i = 0; i < (ctx->rate / 8); i++) {
			if (len == 0)
				return;

			v = array[i];
			left = MIN(sizeof(v), len);

			for (b = 0; b < left; b++)
				ptr[b] = (u_int8_t)(v >> (b * 8));

			len -= left;
			ptr += left;
		}

		if (len != 0)
			keccak1600_rounds(ctx);
	}
}

/*
 * Perform 24 rounds of Keccak: Theta, Rho, Pi, Chi, Iota.
 */
static void
keccak1600_rounds(struct nyfe_keccak1600 *ctx)
{
	size_t		round;
	u_int64_t	A[5][5], C[5], D[5];

	PRECOND(ctx != NULL);

	for (round = 0; round < 24; round++) {
		/* Theta step 1, from chapter 3.2.1. */
		C[0] = ctx->A[0][0];
		C[1] = ctx->A[0][1];
		C[2] = ctx->A[0][2];
		C[3] = ctx->A[0][3];
		C[4] = ctx->A[0][4];

		C[0] ^= ctx->A[1][0];
		C[1] ^= ctx->A[1][1];
		C[2] ^= ctx->A[1][2];
		C[3] ^= ctx->A[1][3];
		C[4] ^= ctx->A[1][4];

		C[0] ^= ctx->A[2][0];
		C[1] ^= ctx->A[2][1];
		C[2] ^= ctx->A[2][2];
		C[3] ^= ctx->A[2][3];
		C[4] ^= ctx->A[2][4];

		C[0] ^= ctx->A[3][0];
		C[1] ^= ctx->A[3][1];
		C[2] ^= ctx->A[3][2];
		C[3] ^= ctx->A[3][3];
		C[4] ^= ctx->A[3][4];

		C[0] ^= ctx->A[4][0];
		C[1] ^= ctx->A[4][1];
		C[2] ^= ctx->A[4][2];
		C[3] ^= ctx->A[4][3];
		C[4] ^= ctx->A[4][4];

		/* Theta step 2, from chapter 3.2.1. */
		D[0] = C[4] ^ rotl64(C[1], 1);
		D[1] = C[0] ^ rotl64(C[2], 1);
		D[2] = C[1] ^ rotl64(C[3], 1);
		D[3] = C[2] ^ rotl64(C[4], 1);
		D[4] = C[3] ^ rotl64(C[0], 1);

		/*
		 * Theta step 3, from chapter 3.2.1 in combination
		 * with the correct Rho shifts from chapter 3.2.2.
		 */
		A[0][0] = rotl64(ctx->A[0][0] ^ D[0], rho_offsets[0][0]);
		A[0][1] = rotl64(ctx->A[0][1] ^ D[1], rho_offsets[0][1]);
		A[0][2] = rotl64(ctx->A[0][2] ^ D[2], rho_offsets[0][2]);
		A[0][3] = rotl64(ctx->A[0][3] ^ D[3], rho_offsets[0][3]);
		A[0][4] = rotl64(ctx->A[0][4] ^ D[4], rho_offsets[0][4]);

		A[1][0] = rotl64(ctx->A[1][0] ^ D[0], rho_offsets[1][0]);
		A[1][1] = rotl64(ctx->A[1][1] ^ D[1], rho_offsets[1][1]);
		A[1][2] = rotl64(ctx->A[1][2] ^ D[2], rho_offsets[1][2]);
		A[1][3] = rotl64(ctx->A[1][3] ^ D[3], rho_offsets[1][3]);
		A[1][4] = rotl64(ctx->A[1][4] ^ D[4], rho_offsets[1][4]);

		A[2][0] = rotl64(ctx->A[2][0] ^ D[0], rho_offsets[2][0]);
		A[2][1] = rotl64(ctx->A[2][1] ^ D[1], rho_offsets[2][1]);
		A[2][2] = rotl64(ctx->A[2][2] ^ D[2], rho_offsets[2][2]);
		A[2][3] = rotl64(ctx->A[2][3] ^ D[3], rho_offsets[2][3]);
		A[2][4] = rotl64(ctx->A[2][4] ^ D[4], rho_offsets[2][4]);

		A[3][0] = rotl64(ctx->A[3][0] ^ D[0], rho_offsets[3][0]);
		A[3][1] = rotl64(ctx->A[3][1] ^ D[1], rho_offsets[3][1]);
		A[3][2] = rotl64(ctx->A[3][2] ^ D[2], rho_offsets[3][2]);
		A[3][3] = rotl64(ctx->A[3][3] ^ D[3], rho_offsets[3][3]);
		A[3][4] = rotl64(ctx->A[3][4] ^ D[4], rho_offsets[3][4]);

		A[4][0] = rotl64(ctx->A[4][0] ^ D[0], rho_offsets[4][0]);
		A[4][1] = rotl64(ctx->A[4][1] ^ D[1], rho_offsets[4][1]);
		A[4][2] = rotl64(ctx->A[4][2] ^ D[2], rho_offsets[4][2]);
		A[4][3] = rotl64(ctx->A[4][3] ^ D[3], rho_offsets[4][3]);
		A[4][4] = rotl64(ctx->A[4][4] ^ D[4], rho_offsets[4][4]);

		/*
		 * The Pi step from chapter 3.2.3 in combination with the
		 * Chi step from chapter 3.2.2.
		 */
		ctx->A[0][0] = A[0][0] ^ (~A[1][1] & A[2][2]);
		ctx->A[0][1] = A[1][1] ^ (~A[2][2] & A[3][3]);
		ctx->A[0][2] = A[2][2] ^ (~A[3][3] & A[4][4]);
		ctx->A[0][3] = A[3][3] ^ (~A[4][4] & A[0][0]);
		ctx->A[0][4] = A[4][4] ^ (~A[0][0] & A[1][1]);

		ctx->A[1][0] = A[0][3] ^ (~A[1][4] & A[2][0]);
		ctx->A[1][1] = A[1][4] ^ (~A[2][0] & A[3][1]);
		ctx->A[1][2] = A[2][0] ^ (~A[3][1] & A[4][2]);
		ctx->A[1][3] = A[3][1] ^ (~A[4][2] & A[0][3]);
		ctx->A[1][4] = A[4][2] ^ (~A[0][3] & A[1][4]);

		ctx->A[2][0] = A[0][1] ^ (~A[1][2] & A[2][3]);
		ctx->A[2][1] = A[1][2] ^ (~A[2][3] & A[3][4]);
		ctx->A[2][2] = A[2][3] ^ (~A[3][4] & A[4][0]);
		ctx->A[2][3] = A[3][4] ^ (~A[4][0] & A[0][1]);
		ctx->A[2][4] = A[4][0] ^ (~A[0][1] & A[1][2]);

		ctx->A[3][0] = A[0][4] ^ (~A[1][0] & A[2][1]);
		ctx->A[3][1] = A[1][0] ^ (~A[2][1] & A[3][2]);
		ctx->A[3][2] = A[2][1] ^ (~A[3][2] & A[4][3]);
		ctx->A[3][3] = A[3][2] ^ (~A[4][3] & A[0][4]);
		ctx->A[3][4] = A[4][3] ^ (~A[0][4] & A[1][0]);

		ctx->A[4][0] = A[0][2] ^ (~A[1][3] & A[2][4]);
		ctx->A[4][1] = A[1][3] ^ (~A[2][4] & A[3][0]);
		ctx->A[4][2] = A[2][4] ^ (~A[3][0] & A[4][1]);
		ctx->A[4][3] = A[3][0] ^ (~A[4][1] & A[0][2]);
		ctx->A[4][4] = A[4][1] ^ (~A[0][2] & A[1][3]);

		/* Iota round constant application. */
		ctx->A[0][0] ^= iota_rc[round];
	}
}

/* Rotate 64-bit integer left with carry. */
static u_int64_t
rotl64(u_int64_t v, u_int64_t b)
{
	if (b == 0)
		return (v);

	return ((v << b) | (v >> (64 - b)));
}
