/*
 * Copyright (c) 2023, 2024 Joris Vink <joris@sanctorum.se>
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
#include <stdlib.h>

#include "nyfe.h"

/*
 * Agelas: An experimental, simple and fully authenticated stream cipher
 * based on Keccak1600. This work is inspired on Keyak, Spongewrap etc.
 *
 * The underlying keccak state is initialized with a capacity of 512-bits.
 *
 * This puts the rate at 136 bytes. Agelas operates on 128 byte blocks
 * as it retains 8 bytes per block for a 56-bit state counter and a single
 * domain seperation byte. The domain seperation byte has different values
 * when absorbing the state for different purposes.
 *
 * init(key):
 *	K_1 = bytepad(0x20 || key[ 0..31], 136)
 *	K_1[135] = 0x01
 *	K_2 = bytepad(0x20 || key[32..63], 136)
 *	K_2[135] = 0x03
 *	keccak = KECCAK[512]
 *	keccak.absorb(K_1)
 *	State <- keccak.squeeze(136)
 *
 * encryption(pt):
 *	for each 128 byte block, do
 *		for i = 0 -> i = 127, do
 *			ct[i] = pt[i] ^ State[i]
 *			State[i] = pt[i]
 *		clen += len(pt)
 *		State[128..134] = counter
 *		State[135] = 0x07
 *		keccak.absorb(State)
 *		counter = counter + 1
 *		State <- keccak.squeeze(136)
 *
 * decryption(ct):
 *	for each 128 byte block, do
 *		for i = 0 -> i = 127, do
 *			pt[i] = ct[i] ^ State[i]
 *			State[i] = pt[i]
 *		clen += len(ct)
 *		State[128..134] = counter
 *		State[135] = 0x07
 *		keccak.absorb(State)
 *		counter = counter + 1
 *		State <- keccak.squeeze(136)
 *
 * Additional Authenticated Data may be added at any time as long as this
 * matches in both the encryption and decryption process.
 *
 * The data for each AAD call must fit in a single agelas_bytepad() block.
 *
 * add_aad(aad):
 *	aad_padded = bytepad(aad, 136)
 *	aad_padded[135] = 0x0f
 *	keccak.absorb(aad_padded)
 *	alen += len(aad)
 *
 * The authentication tag is obtained at the end. The authentication step
 * includes the length of the AAD and data operated on.
 *
 * authenticate(tag, taglen):
 *	L = bytepad(alen, 136)
 *	L[135] = 0x1f
 *	keccak.absorb(L)
 *	L = bytepad(clen, 136)
 *	L[135] = 0x1f
 *	keccak.absorb(L)
 *	State[128..134] = counter
 *	State[135] = 0x3f
 *	keccak.absorb(State)
 *	keccak.absorb(K_2)
 *	tag <- keccak.squeeze(taglen)
 */

/* Number of bits for the capacity (c). */
#define AGELAS_KECCAK_BITS	512

/* The sponge rate (r). */
#define AGELAS_SPONGE_RATE	136

/* The number of bytes from the state we consume for a block. */
#define AGELAS_XOR_RATE		(AGELAS_SPONGE_RATE - 8)

/* The number of bytes we can absorb when byte padded. */
#define AGELAS_ABSORB_LEN	(AGELAS_SPONGE_RATE - 4)

static void	agelas_absorb_state(struct nyfe_agelas *, u_int8_t);
static void	agelas_bytepad(const void *, size_t, u_int8_t *, size_t);

/*
 * Initializes an Agelas context with the given key.
 */
void
nyfe_agelas_init(struct nyfe_agelas *ctx, const void *key, size_t key_len)
{
	u_int8_t		len;
	const u_int8_t		*ptr;
	u_int8_t		k1[AGELAS_SPONGE_RATE];
	u_int8_t		buf[AGELAS_SPONGE_RATE];

	PRECOND(ctx != NULL);
	PRECOND(key != NULL);
	PRECOND(key_len == NYFE_KEY_LEN);

	nyfe_mem_zero(ctx, sizeof(*ctx));

	nyfe_zeroize_register(k1, sizeof(k1));
	nyfe_zeroize_register(buf, sizeof(buf));

	/*
	 * Construct K_1 and K_2.
	 *
	 * K_1 is absorbed into the initial state.
	 * K_2 is absorbed into the state before squeezing out the tag.
	 */
	len = key_len / 2;
	nyfe_memcpy(buf, &len, sizeof(len));
	nyfe_memcpy(&buf[sizeof(len)], key, len);

	agelas_bytepad(buf, sizeof(len) + len, k1, sizeof(k1));
	k1[AGELAS_SPONGE_RATE - 1] = 0x01;

	/* Absorb K_1 into keccak sponge. */
	nyfe_keccak1600_init(&ctx->sponge, 0, AGELAS_KECCAK_BITS);
	nyfe_keccak1600_absorb(&ctx->sponge, k1, sizeof(k1));

	/* Prepare K_2. */
	ptr = key;
	len = key_len / 2;
	nyfe_memcpy(buf, &len, sizeof(len));
	nyfe_memcpy(&buf[sizeof(len)], &ptr[len], len);

	/* Bytepad K2 into our context for later. */
	agelas_bytepad(buf, sizeof(len) + len, ctx->k2, sizeof(ctx->k2));
	ctx->k2[AGELAS_SPONGE_RATE - 1] = 0x03;

	/* Generate first state. */
	ctx->offset = 0;
	nyfe_keccak1600_squeeze(&ctx->sponge, ctx->state, sizeof(ctx->state));

	nyfe_zeroize(k1, sizeof(k1));
	nyfe_zeroize(buf, sizeof(buf));
}

/*
 * Encrypt and authenticate plaintext given in `in` to the `out` buffer.
 * These buffers may be the same.
 */
void
nyfe_agelas_encrypt(struct nyfe_agelas *ctx, const void *in,
    void *out, size_t len)
{
	size_t			idx;
	const u_int8_t		*src;
	u_int8_t		tmp, *dst;

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(len > 0);

	src = in;
	dst = out;

	for (idx = 0; idx < len; idx++) {
		if (ctx->offset == AGELAS_XOR_RATE)
			agelas_absorb_state(ctx, 0x07);
		tmp = src[idx];
		dst[idx] = tmp ^ ctx->state[ctx->offset];
		ctx->state[ctx->offset++] = tmp;
	}

	ctx->clen += len;
}

/*
 * Decrypt and authenticate ciphertext given in `in` to the `out` buffer.
 * These buffers may be the same.
 */
void
nyfe_agelas_decrypt(struct nyfe_agelas *ctx, const void *in,
    void *out, size_t len)
{
	size_t			idx;
	u_int8_t		*dst;
	const u_int8_t		*src;

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(len > 0);

	src = in;
	dst = out;

	for (idx = 0; idx < len; idx++) {
		if (ctx->offset == AGELAS_XOR_RATE)
			agelas_absorb_state(ctx, 0x07);
		dst[idx] = src[idx] ^ ctx->state[ctx->offset];
		ctx->state[ctx->offset++] = dst[idx];
	}

	ctx->clen += len;
}

/*
 * Add additional authenticated data into the Agelas context.
 * The data its length must be 0 < len <= 132.
 */
void
nyfe_agelas_aad(struct nyfe_agelas *ctx, const void *data, size_t len)
{
	u_int8_t	buf[AGELAS_SPONGE_RATE];

	PRECOND(ctx != NULL);
	PRECOND(data != NULL);
	PRECOND(len <= AGELAS_ABSORB_LEN - 2);

	agelas_bytepad(data, len, buf, sizeof(buf));
	buf[AGELAS_SPONGE_RATE - 1] = 0x0f;
	nyfe_keccak1600_absorb(&ctx->sponge, buf, sizeof(buf));

	ctx->alen += len;
}

/*
 * Obtain the tag from the Agelas context after also including the
 * aad length and data length.
 */
void
nyfe_agelas_authenticate(struct nyfe_agelas *ctx, u_int8_t *tag, size_t len)
{
	u_int64_t	length;
	u_int8_t	buf[AGELAS_SPONGE_RATE];

	PRECOND(ctx != NULL);
	PRECOND(tag != NULL);
	PRECOND(len == NYFE_TAG_LEN);

	length = htobe64(ctx->alen);
	agelas_bytepad(&length, sizeof(length), buf, sizeof(buf));
	buf[AGELAS_SPONGE_RATE - 1] = 0x1f;
	nyfe_keccak1600_absorb(&ctx->sponge, buf, sizeof(buf));

	length = htobe64(ctx->clen);
	agelas_bytepad(&length, sizeof(length), buf, sizeof(buf));
	buf[AGELAS_SPONGE_RATE - 1] = 0x1f;
	nyfe_keccak1600_absorb(&ctx->sponge, buf, sizeof(buf));

	agelas_absorb_state(ctx, 0x3f);
	nyfe_keccak1600_absorb(&ctx->sponge, ctx->k2, sizeof(ctx->k2));
	nyfe_keccak1600_squeeze(&ctx->sponge, tag, len);
}

/*
 * Absorb the current state into the keccak state and squeeze out a new one.
 */
static void
agelas_absorb_state(struct nyfe_agelas *ctx, u_int8_t tag)
{
	PRECOND(ctx != NULL);

	ctx->state[AGELAS_SPONGE_RATE - 8] = ctx->counter >> 48;
	ctx->state[AGELAS_SPONGE_RATE - 7] = ctx->counter >> 40;
	ctx->state[AGELAS_SPONGE_RATE - 6] = ctx->counter >> 32;
	ctx->state[AGELAS_SPONGE_RATE - 5] = ctx->counter >> 24;
	ctx->state[AGELAS_SPONGE_RATE - 4] = ctx->counter >> 16;
	ctx->state[AGELAS_SPONGE_RATE - 3] = ctx->counter >> 8;
	ctx->state[AGELAS_SPONGE_RATE - 2] = ctx->counter & 0xff;
	ctx->state[AGELAS_SPONGE_RATE - 1] = tag;

	nyfe_keccak1600_absorb(&ctx->sponge, ctx->state, sizeof(ctx->state));
	nyfe_keccak1600_squeeze(&ctx->sponge, ctx->state, sizeof(ctx->state));

	ctx->offset = 0;
	ctx->counter++;
}

/*
 * Helper function to bytepad() the given input to one AGELAS_SPONGE_RATE bytes.
 */
static void
agelas_bytepad(const void *in, size_t inlen, u_int8_t *out, size_t outlen)
{
	PRECOND(in != NULL);
	PRECOND(inlen <= AGELAS_ABSORB_LEN);
	PRECOND(out != NULL);
	PRECOND(outlen == AGELAS_SPONGE_RATE);

	nyfe_mem_zero(out, outlen);
	out[0] = 0x01;
	out[1] = AGELAS_SPONGE_RATE;
	out[2] = 0x01;
	out[3] = (u_int8_t)inlen;

	nyfe_memcpy(&out[4], in, inlen);
}
