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

#include <stdio.h>
#include <unistd.h>

#include "sanctum.h"

#define POOL_ALIGN		16

struct entry {
	int		free;
	void		*uptr;
};

/*
 * Allocate a pool that can be shared between different processes.
 */
struct sanctum_pool *
sanctum_pool_init(size_t elm, size_t len)
{
	struct sanctum_pool	*pool;
	struct entry		*entry;
	size_t			total, idx;

	PRECOND(len > 0);
	PRECOND(elm <= 4096);
	PRECOND(SIZE_MAX / elm >= len);

	len = sizeof(*entry) + len;
	len = (len + (POOL_ALIGN - 1)) & ~(POOL_ALIGN - 1);

	total = (sizeof(*pool) + (POOL_ALIGN - 1)) & ~(POOL_ALIGN - 1);
	total = total + (len * elm);

	pool = sanctum_alloc_shared(total, NULL);

	memset(pool, 0, sizeof(*pool));
	pool->len = len;

	sanctum_ring_init(&pool->queue, elm);

	total = (sizeof(*pool) + (POOL_ALIGN - 1)) & ~(POOL_ALIGN - 1);
	pool->base = (u_int8_t *)pool + total;

	for (idx = 0; idx < elm; idx++) {
		entry = (struct entry *)(pool->base + (idx * pool->len));

		entry->free = 1;
		entry->uptr = (u_int8_t *)entry + sizeof(*entry);

		if (sanctum_ring_queue(&pool->queue, entry) == -1)
			fatal("failed to queue %zu", idx);
	}

	return (pool);
}

/*
 * Return the first free entry of the pool, could return NULL if
 * no more free entries are available.
 */
void *
sanctum_pool_get(struct sanctum_pool *pool)
{
	struct entry		*entry;

	PRECOND(pool != NULL);

	if ((entry = sanctum_ring_dequeue(&pool->queue)) == NULL)
		return (NULL);

	if (!sanctum_atomic_cas_simple(&entry->free, 1, 0))
		fatal("failed to mark entry as busy");

	return (entry->uptr);
}

/*
 * Place a element from the pool back into the freelist.
 */
void
sanctum_pool_put(struct sanctum_pool *pool, void *ptr)
{
	uintptr_t		uptr;
	struct entry		*entry;

	PRECOND(pool != NULL);
	PRECOND(ptr != NULL);

	uptr = (uintptr_t)ptr - sizeof(*entry);
	entry = (struct entry *)uptr;

	if (!sanctum_atomic_cas_simple(&entry->free, 0, 1))
		fatal("failed to mark %p as free", ptr);

	if (sanctum_ring_queue(&pool->queue, (void *)uptr) == -1)
		fatal("failed to requeue a free element");
}
