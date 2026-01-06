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

/*
 * Cryptographically secure random bytes via the nyfe library.
 */

#include <sys/types.h>

#include <stdio.h>

#include "sanctum.h"

/* The indicator for -v. */
const char	*sanctum_random = "nyfe-random";

/*
 * Initialise the underlying random system, can be called multiple
 * times to re-initialise it.
 */
void
sanctum_random_init(void)
{
	nyfe_random_init();
}

/*
 * Generate a number of cryptographically secure random bytes.
 */
void
sanctum_random_bytes(void *buf, size_t len)
{
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	nyfe_random_bytes(buf, len);
}
