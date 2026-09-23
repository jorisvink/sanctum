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

#include <stdlib.h>

#include "nyfe.h"
#include "queue.h"

/*
 * Points to memory that contains sensitive data and must be cleared
 * before we exit.
 */
struct zeroize {
	void			*ptr;
	size_t			length;
	LIST_ENTRY(zeroize)	list;
};

static LIST_HEAD(, zeroize)		zeroize_list;

/* Initialize the zeroize list. */
void
nyfe_zeroize_init(void)
{
	LIST_INIT(&zeroize_list);
}

/*
 * Register sensitive data and its length so that it can be cleared
 * in case of a nyfe_fatal().
 */
void
nyfe_zeroize_register(void *ptr, size_t len)
{
	struct zeroize		*z;

	PRECOND(ptr != NULL);
	PRECOND(len > 0);

	if ((z = calloc(1, sizeof(*z))) == NULL)
		nyfe_fatal("failed to allocate zeroize list member");

	z->ptr = ptr;
	z->length = len;

	LIST_INSERT_HEAD(&zeroize_list, z, list);
}

/*
 * Warn if there are any pending entries on the zeroize list.
 */
void
nyfe_zeroize_warn(void)
{
	struct zeroize		*z;

	LIST_FOREACH(z, &zeroize_list, list) {
		printf("WARN: %p (%zu bytes) was still on zeroize list\n",
		    z->ptr, z->length);
	}
}

/*
 * Clear all sensitive data that was previously registered.
 */
void
nyfe_zeroize_all(void)
{
	struct zeroize		*z;

	while ((z = LIST_FIRST(&zeroize_list)) != NULL) {
		nyfe_mem_zero(z->ptr, z->length);
		LIST_REMOVE(z, list);
		free(z);
	}
}

/*
 * Remove an entry that was previously registered and clear its contents.
 */
void
nyfe_zeroize(void *ptr, size_t len)
{
	struct zeroize		*z;

	PRECOND(ptr != NULL);
	PRECOND(len > 0);

	LIST_FOREACH(z, &zeroize_list, list) {
		if (z->ptr == ptr && z->length == len) {
			nyfe_mem_zero(ptr, len);
			LIST_REMOVE(z, list);
			free(z);
			return;
		}
	}

	nyfe_mem_zero(ptr, len);
	nyfe_fatal("failed to find a zeroize entry for %p (%zu)",  ptr, len);
}

/*
 * Do a byte for byte memory copy. We build with -fno-builtin such that
 * the compiler does not decide to optimize this using potentially wider
 * registers. You probably want to verify that this holds on whatever
 * platform you end up using this on.
 */
void
nyfe_memcpy(void *dst, const void *src, size_t len)
{
	size_t			idx;
	const u_int8_t		*in;
	u_int8_t		*out;

	PRECOND(dst != NULL);
	PRECOND(src != NULL);
	PRECOND(len > 0);

	in = src;
	out = dst;

	for (idx = 0; idx < len; idx++)
		out[idx] = in[idx];
}

/*
 * Poor mans memset() that isn't optimized away on the platforms I use it on.
 *
 * If you build this on something and don't test that it actually clears the
 * contents of the data, thats on you. You probably want to do some binary
 * verification.
 */
void
nyfe_mem_zero(void *ptr, size_t len)
{
	volatile char	*p;

	PRECOND(ptr != NULL);
	PRECOND(len > 0);

	p = (volatile char *)ptr;

	while (len-- > 0)
		*(p)++ = 0x00;
}

/*
 * Constant time comparison of 2 given buffers of the same size.
 * Returns 0 if both contain the same data.
 */
int
nyfe_mem_cmp(const void *b1, const void *b2, size_t len)
{
	int			ret;
	size_t			idx;
	const u_int8_t		*p1, *p2;

	PRECOND(b1 != NULL);
	PRECOND(b2 != NULL);

	p1 = b1;
	p2 = b2;
	ret = 0;

	for (idx = 0; idx < len; idx++)
		ret |= p1[idx] ^ p2[idx];

	return (ret);
}
