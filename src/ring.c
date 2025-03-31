/*
 * Copyright (c) 2023-2025 Joris Vink <joris@sanctorum.se>
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
 * A multi-producer, multi-consumer ring queue.
 */

/*
 * Allocate a new ring of the given number of elements. This must
 * be a power of 2 and must be maximum 4096. This is checked in
 * the sanctum_ring_init() function.
 */
struct sanctum_ring *
sanctum_ring_alloc(size_t elm)
{
	struct sanctum_ring	*ring;

	ring = sanctum_alloc_shared(sizeof(*ring), NULL);
	sanctum_ring_init(ring, elm);

	return (ring);
}

/*
 * Initialise the given ring queue with the number of elements.
 * The number of elements must be a power of 2 and must maximum
 * be 4096.
 */
void
sanctum_ring_init(struct sanctum_ring *ring, size_t elm)
{
	PRECOND(ring != NULL);
	PRECOND(elm > 0 && (elm & (elm - 1)) == 0);

	memset(ring, 0, sizeof(*ring));

	ring->elm = elm;
	ring->mask = elm - 1;
}

/*
 * Returns the number of entries that are ready to be dequeued from the queue.
 * This is intended for the consumers of the ring queue.
 */
size_t
sanctum_ring_pending(struct sanctum_ring *ring)
{
	u_int32_t	head, tail;

	PRECOND(ring != NULL);

	head = sanctum_atomic_read(&ring->consumer.head);
	tail = sanctum_atomic_read(&ring->producer.tail);

	return (tail - head);
}

/*
 * Returns the number of available entries in the queue.
 * This is intended for the producers of the ring queue.
 */
size_t
sanctum_ring_available(struct sanctum_ring *ring)
{
	u_int32_t	head, tail;

	PRECOND(ring != NULL);

	head = sanctum_atomic_read(&ring->producer.head);
	tail = sanctum_atomic_read(&ring->consumer.tail);

	return (ring->elm + (tail - head));
}

/*
 * Dequeue an item from the given ring queue. If no items were
 * available to be dequeued, NULL is returned to the caller.
 */
void *
sanctum_ring_dequeue(struct sanctum_ring *ring)
{
	uintptr_t	uptr;
	u_int32_t	slot, head, tail, next;

	PRECOND(ring != NULL);

dequeue_again:
	head = sanctum_atomic_read(&ring->consumer.head);
	tail = sanctum_atomic_read(&ring->producer.tail);

	if ((tail - head) == 0)
		return (NULL);

	next = head + 1;
	if (!sanctum_atomic_cas(&ring->consumer.head, &head, &next))
		goto dequeue_again;

	slot = head & ring->mask;
	uptr = sanctum_atomic_read(&ring->data[slot]);

	while (!sanctum_atomic_cas_simple(&ring->consumer.tail, head, next))
		sanctum_cpu_pause();

	return ((void *)uptr);
}

/*
 * Queue the given item into the given ring queue. If no available
 * slots were available, this function will return -1.
 */
int
sanctum_ring_queue(struct sanctum_ring *ring, void *ptr)
{
	u_int32_t	slot, head, tail, next;

queue_again:
	head = sanctum_atomic_read(&ring->producer.head);
	tail = sanctum_atomic_read(&ring->consumer.tail);

	if ((ring->elm + (tail - head)) == 0)
		return (-1);

	next = head + 1;
	if (!sanctum_atomic_cas(&ring->producer.head, &head, &next))
		goto queue_again;

	slot = head & ring->mask;
	sanctum_atomic_write(&ring->data[slot], (uintptr_t)ptr);

	while (!sanctum_atomic_cas_simple(&ring->producer.tail, head, next))
		sanctum_cpu_pause();

	return (0);
}
