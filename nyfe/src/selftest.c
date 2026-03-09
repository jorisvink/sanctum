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

#define KMAC		"My Tagged Application"

static void	test_fill_buffer(const u_int8_t, u_int8_t *, size_t);

static const u_int8_t kmac_test_1[] = {
	0x20, 0xC5, 0x70, 0xC3, 0x13, 0x46, 0xF7, 0x03,
	0xC9, 0xAC, 0x36, 0xC6, 0x1C, 0x03, 0xCB, 0x64,
	0xC3, 0x97, 0x0D, 0x0C, 0xFC, 0x78, 0x7E, 0x9B,
	0x79, 0x59, 0x9D, 0x27, 0x3A, 0x68, 0xD2, 0xF7,
	0xF6, 0x9D, 0x4C, 0xC3, 0xDE, 0x9D, 0x10, 0x4A,
	0x35, 0x16, 0x89, 0xF2, 0x7C, 0xF6, 0xF5, 0x95,
	0x1F, 0x01, 0x03, 0xF3, 0x3F, 0x4F, 0x24, 0x87,
	0x10, 0x24, 0xD9, 0xC2, 0x77, 0x73, 0xA8, 0xDD
};

static const u_int8_t kmac_test_2[] = {
	0xd5, 0xbe, 0x73, 0x1c, 0x95, 0x4e, 0xd7, 0x73,
	0x28, 0x46, 0xbb, 0x59, 0xdb, 0xe3, 0xa8, 0xe3,
	0x0f, 0x83, 0xe7, 0x7a, 0x4b, 0xff, 0x44, 0x59,
	0xf2, 0xf1, 0xc2, 0xb4, 0xec, 0xeb, 0xb8, 0xce,
	0x67, 0xba, 0x01, 0xc6, 0x2e, 0x8a, 0xb8, 0x57,
	0x8d, 0x2d, 0x49, 0x9b, 0xd1, 0xbb, 0x27, 0x67,
	0x68, 0x78, 0x11, 0x90, 0x02, 0x0a, 0x30, 0x6a,
	0x97, 0xde, 0x28, 0x1d, 0xcc, 0x30, 0x30, 0x5d
};

/*
 * Perform KMAC256 self tests and abort if they fail.
 * These are taken from the NIST KMAC samples.
 */
void
nyfe_selftest_kmac256(void)
{
	struct nyfe_kmac256	ctx;
	u_int8_t		key[32], in[256], out[64];

	/*
	 * Test 1:
	 *
	 * Key 32 bytes (0x40 -> 0x5f)
	 * Input 4 bytes (00 -> 0x03)
	 * Output 64 bytes, not xof.
	 */
	test_fill_buffer(0x00, in, 4);
	test_fill_buffer(0x40, key, sizeof(key));

	nyfe_kmac256_init(&ctx, key, sizeof(key), KMAC, sizeof(KMAC) - 1);
	nyfe_kmac256_update(&ctx, in, 4);
	nyfe_kmac256_final(&ctx, out, sizeof(out));

	nyfe_mem_zero(&ctx, sizeof(ctx));

	if (memcmp(out, kmac_test_1, sizeof(out)))
		nyfe_fatal("%s: kmac_self_test_1 failed", __func__);

	/*
	 * Test 2:
	 *
	 * Key 32 bytes (0x40 -> 0x5f)
	 * Input 200 bytes (00 -> 0xc7)
	 * Output 64 bytes, xof.
	 */
	test_fill_buffer(0x00, in, 200);
	test_fill_buffer(0x40, key, sizeof(key));

	nyfe_kmac256_init(&ctx, key, sizeof(key), KMAC, sizeof(KMAC) - 1);
	nyfe_kmac256_update(&ctx, in, 200);
	nyfe_kmac256_xof(&ctx);
	nyfe_kmac256_final(&ctx, out, sizeof(out));

	nyfe_mem_zero(&ctx, sizeof(ctx));

	if (memcmp(out, kmac_test_2, sizeof(out)))
		nyfe_fatal("%s: kmac_self_test_2 failed", __func__);
}

/*
 * Helper function to set the given buffer to a series of bytes
 * starting at the base byte.
 */
static void
test_fill_buffer(const u_int8_t base, u_int8_t *buf, size_t len)
{
	size_t		idx;

	PRECOND(buf != NULL);

	for (idx = 0; idx < len; idx++)
		buf[idx] = base + idx;
}
