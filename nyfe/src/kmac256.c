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

#include <ctype.h>
#include <string.h>

#include "nyfe.h"

/*
 * KMAC256 as per NIST-800.185
 *
 * KMAC256(K, X, L, S):
 *	newX = bytepad(encode_string(K), 136) || X || right_encode(L).
 *	return cSHAKE256(newX, L, “KMAC”, S).
 *
 * cSHAKE256(X, L, "KMAC", S)
 *	return KECCAK[512](bytepad(encode_string("KMAC") ||
 *	    encode_string(S), 136) || X || 00, L)
 */

#define KMAC256_KECCAK_RATE	136

static size_t	kmac256_encode_bits(size_t);
static void	kmac256_bytepad(const void *, size_t, u_int8_t *, size_t);
static size_t	kmac256_encode_string(const void *, size_t, u_int8_t *, size_t);

/*
 * Initialise a KMAC256 context.
 */
void
nyfe_kmac256_init(struct nyfe_kmac256 *ctx, const void *k, size_t klen,
    const void *s, size_t slen)
{
	size_t		off;
	u_int8_t	tmp[128], padded[KMAC256_KECCAK_RATE];

	PRECOND(ctx != NULL);
	PRECOND(k != NULL);
	PRECOND(s != NULL);
	PRECOND(slen <= 32);

	nyfe_zeroize_register(tmp, sizeof(tmp));
	nyfe_zeroize_register(padded, sizeof(padded));

	nyfe_mem_zero(ctx, sizeof(*ctx));
	nyfe_keccak1600_init(&ctx->sha3.keccak, '\x04', 512);

	/*
	 * Initial data to feed into our keccak1600 state:
	 *	bytepad(encode_string("KMAC") || encode_string(S), 136)
	 */
	off = kmac256_encode_string("KMAC", 4, tmp, sizeof(tmp));
	off += kmac256_encode_string(s, slen, &tmp[off], sizeof(tmp) - off);

	kmac256_bytepad(tmp, off, padded, sizeof(padded));
	nyfe_keccak1600_absorb(&ctx->sha3.keccak, padded, sizeof(padded));

	/*
	 * Next data that is fed into the keccak1600 state is
	 *	newX = bytepad(encode_string(K), 136) || X || right_encode(L).
	 * Since we don't have X or L yet, only feed the byte padded key.
	 */
	off = kmac256_encode_string(k, klen, tmp, sizeof(tmp));
	kmac256_bytepad(tmp, off, padded, sizeof(padded));
	nyfe_keccak1600_absorb(&ctx->sha3.keccak, padded, sizeof(padded));

	nyfe_zeroize(tmp, sizeof(tmp));
	nyfe_zeroize(padded, sizeof(padded));
}

/*
 * Mark that this KMAC256 context is to be used as a XOF instead.
 */
void
nyfe_kmac256_xof(struct nyfe_kmac256 *ctx)
{
	PRECOND(ctx != NULL);

	ctx->isxof = 1;
}

/*
 * Add additional data into the KMAC256 state.
 */
void
nyfe_kmac256_update(struct nyfe_kmac256 *ctx, const void *buf, size_t len)
{
	PRECOND(ctx != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	nyfe_sha3_update(&ctx->sha3, buf, len);
}

/*
 * Output the requested number of bytes from the KMAC256 state.
 */
void
nyfe_kmac256_final(struct nyfe_kmac256 *ctx, u_int8_t *out, size_t outlen)
{
	int		idx;
	u_int8_t	buf[3];
	size_t		count, bits, l;

	PRECOND(ctx != NULL);
	PRECOND(out != NULL);

	if (ctx->isxof == 1) {
		l = 0;
	} else {
		l = outlen;
	}

	/* Feed right_encode(l) to the keccak1600 state. */
	bits = l * 8;
	count = kmac256_encode_bits(bits);

	for (idx = count - 1; idx >= 0; idx--) {
		buf[idx] = (u_int8_t)(bits & 0xff);
		bits = bits >> 8;
	}

	buf[count] = (u_int8_t)count;
	nyfe_sha3_update(&ctx->sha3, buf, 1 + count);

	/*
	 * Now we can finally generate the output and we immediately zero
	 * the state afterwards.
	 */
	nyfe_sha3_final(&ctx->sha3, out, outlen);
	nyfe_mem_zero(ctx, sizeof(*ctx));
}

/*
 * Return the number of bytes required to encode the given number of bits.
 */
static size_t
kmac256_encode_bits(size_t bits)
{
	size_t		count;

	count = 0;

	while (bits) {
		count++;
		bits = bits >> 8;
	}

	if (count > 2)
		fatal("%s: too many bytes required (%zu)", __func__, count);

	if (count == 0)
		count = 1;

	return (count);
}

/*
 * The KMAC256 encode_string(S) function that will write
 * `left_encode(len(S)) || S` into the given output buffer.
 *
 * We apply hard constraints on number of encoded bytes for the length,
 * limiting it to a max of 2 bytes (required for 256-bit key material).
 */
static size_t
kmac256_encode_string(const void *in, size_t inlen, u_int8_t *out,
    size_t outlen)
{
	size_t		idx, bits, total, count;

	PRECOND(in != NULL);
	PRECOND(out != NULL);

	/*
	 * First we count and constrain how many bytes we require
	 * to encode the given number of bits.
	 */
	bits = inlen * 8;
	count = kmac256_encode_bits(bits);

	/*
	 * Now we output the encoded bits and the original data into out.
	 */
	total = 1 + count + inlen;

	if (total > outlen)
		fatal("%s: too little bytes in out (%zu)", __func__, outlen);

	out[0] = count;
	for (idx = count; idx > 0; idx--) {
		out[idx] = (u_int8_t)(bits & 0xff);
		bits = bits >> 8;
	}

	if (in != NULL)
		nyfe_memcpy(&out[1 + count], in, inlen);

	return (total);
}

/*
 * The KMAC256 bytepad() function.
 *
 * Very constricted in the sense that we only accept padding it out to
 * a single size of KMAC256_KECCAK_RATE (136).
 */
static void
kmac256_bytepad(const void *in, size_t inlen, u_int8_t *out, size_t outlen)
{
	PRECOND(in != NULL);
	PRECOND(inlen < KMAC256_KECCAK_RATE - 2);
	PRECOND(out != NULL);
	PRECOND(outlen == KMAC256_KECCAK_RATE);

	nyfe_mem_zero(out, outlen);
	out[0] = 0x01;
	out[1] = KMAC256_KECCAK_RATE;

	nyfe_memcpy(&out[2], in, inlen);
}
