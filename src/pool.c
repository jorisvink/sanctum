/*
 * Copyright (c) 2023-2026 Joris Vink <joris@sanctorum.se>
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
#define POOL_HDR_LEN		\
    ((sizeof(struct entry) + (POOL_ALIGN - 1)) & ~(POOL_ALIGN - 1))

struct entry {
	volatile u_int32_t	free;
};

static struct entry	*pool_entry_from_idx(struct sanctum_pool *, u_int32_t);

/*
 * Allocate a pool that can be shared between different processes.
 */
struct sanctum_pool *
sanctum_pool_init(size_t elm, size_t len)
{
	u_int32_t		idx;
	struct sanctum_pool	*pool;
	struct entry		*entry;

	PRECOND(len > 0);
	PRECOND(elm > 0 && elm <= SANCTUM_RING_MAX);
	PRECOND(len <= SIZE_MAX - POOL_HDR_LEN - POOL_ALIGN);

	if ((pool = calloc(1, sizeof(*pool))) == NULL)
		fatal("calloc: failed to allocate pool");

	len = POOL_HDR_LEN + len;
	len = (len + (POOL_ALIGN - 1)) & ~(POOL_ALIGN - 1);

	PRECOND(SIZE_MAX / elm >= len);

	pool->elm = elm;
	pool->len = len;
	pool->queue = sanctum_ring_alloc(elm);
	pool->base = sanctum_alloc_shared(len * elm);

	for (idx = 0; idx < elm; idx++) {
		entry = pool_entry_from_idx(pool, idx);
		entry->free = 1;

		if (sanctum_ring_queue(pool->queue, idx) == -1)
			fatal("failed to queue %u", idx);
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
	u_int32_t		idx;
	struct entry		*entry;

	PRECOND(pool != NULL);

	if (sanctum_ring_dequeue(pool->queue, &idx) == -1)
		return (NULL);

	if ((entry = pool_entry_from_idx(pool, idx)) == NULL)
		fatal("invalid pool index %u", idx);

	if (!sanctum_atomic_cas_simple(&entry->free, 1, 0))
		fatal("failed to mark entry as busy");

	return ((u_int8_t *)entry + POOL_HDR_LEN);
}

/*
 * Place a element from the pool back into the freelist.
 */
void
sanctum_pool_put(struct sanctum_pool *pool, void *ptr)
{
	u_int32_t		idx;
	struct entry		*entry;

	PRECOND(pool != NULL);
	PRECOND(ptr != NULL);

	idx = sanctum_pool_index(pool, ptr);
	entry = pool_entry_from_idx(pool, idx);
	VERIFY(entry != NULL);

	if (!sanctum_atomic_cas_simple(&entry->free, 0, 1))
		fatal("failed to mark %p as free", ptr);

	if (sanctum_ring_queue(pool->queue, idx) == -1)
		fatal("failed to requeue a free element");
}

/*
 * Return the expected pointer in the pool for the given index.
 */
void *
sanctum_pool_ptr(struct sanctum_pool *pool, u_int32_t idx)
{
	struct entry		*entry;

	PRECOND(pool != NULL);

	if ((entry = pool_entry_from_idx(pool, idx)) == NULL)
		return (NULL);

	return ((u_int8_t *)entry + POOL_HDR_LEN);
}

/*
 * Return the expected index in the pool for the given pointer.
 */
u_int32_t
sanctum_pool_index(struct sanctum_pool *pool, const void *ptr)
{
	uintptr_t		off, base;

	PRECOND(pool != NULL);
	PRECOND(ptr != NULL);

	base = (uintptr_t)pool->base + POOL_HDR_LEN;

	if ((uintptr_t)ptr < base)
		fatal("%p is not part of the pool", ptr);

	off = (uintptr_t)ptr - base;

	if ((off % pool->len) != 0 || (off / pool->len) >= pool->elm)
		fatal("%p is not part of the pool", ptr);

	return ((u_int32_t)(off / pool->len));
}

/*
 * Returns the pool entry for the given index.
 */
static struct entry *
pool_entry_from_idx(struct sanctum_pool *pool, u_int32_t idx)
{
	PRECOND(pool != NULL);

	if (idx >= pool->elm)
		return (NULL);

	return ((struct entry *)(pool->base + ((size_t)idx * pool->len)));
}
