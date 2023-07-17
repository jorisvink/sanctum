/*
 * Copyright (c) 2023 Joris Vink <joris@coders.se>
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

#include "sanctum.h"

/*
 * Shared pool of packets that are to be processed.
 *
 * The clear and crypto io processes will for each received packet grab
 * one from the pool and hand them over to either the encryption or decryption
 * processes who in turn hand them over to the crypto or clear io processes.
 */
struct sanctum_pool	*pktpool;

/*
 * Setup the packet pool, the 1024 could maybe be tuneable.
 */
void
sanctum_packet_init(void)
{
	pktpool = sanctum_pool_init(1024, sizeof(struct sanctum_packet));
}

/*
 * Obtain a new packet from the packet pool. If no packets are
 * available NULL is returned to the caller.
 */
struct sanctum_packet *
sanctum_packet_get(void)
{
	struct sanctum_packet	*pkt;

	if ((pkt = sanctum_pool_get(pktpool)) == NULL)
		return (NULL);

#if defined(SANCTUM_HIGH_PERFORMANCE)
	pkt->length = 0;
	pkt->target = 0;
#else
	sanctum_mem_zero(pkt, sizeof(*pkt));
#endif

	return (pkt);
}

/*
 * Place a packet back into the packet pool, making it available again
 * for clear or crypto.
 */
void
sanctum_packet_release(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	sanctum_pool_put(pktpool, pkt);
}

/*
 * Returns a pointer to the packet header (the location of the ESP header).
 */
void *
sanctum_packet_head(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->buf[0]);
}

/*
 * Returns a pointer to the packet data (immediately after the ESP header).
 */
void *
sanctum_packet_data(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->buf[SANCTUM_PACKET_HEAD_LEN]);
}

/*
 * Returns a pointer to the packet tail (immediately after the packet data).
 */
void *
sanctum_packet_tail(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);
	PRECOND(pkt->length <= SANCTUM_PACKET_DATA_LEN);

	return (&pkt->buf[SANCTUM_PACKET_HEAD_LEN + pkt->length]);
}

/*
 * Check if the given packet contains enough data to satisfy
 * an IPSec header, tail and cipher overhead.
 */
int
sanctum_packet_crypto_checklen(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	if (pkt->length < sizeof(struct sanctum_ipsec_hdr) +
	    sizeof(struct sanctum_ipsec_tail) + sanctum_cipher_overhead())
		return (-1);

	return (0);
}
