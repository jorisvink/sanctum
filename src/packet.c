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

#include "sanctum.h"

static void	packet_shroud_xor(struct sanctum_packet *,
		    const void *, size_t, int);

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

	nyfe_mem_zero(pkt, sizeof(*pkt));

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
 * Returns a pointer to the start of the entire packet buffer.
 */
void *
sanctum_packet_start(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->buf[0]);
}

/*
 * Returns a pointer to the packet header (the location of the sanctum header).
 */
void *
sanctum_packet_head(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->buf[SANCTUM_PACKET_HEAD_OFFSET]);
}

/*
 * Returns a pointer to the packet data (immediately after the sanctum header).
 */
void *
sanctum_packet_data(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->buf[SANCTUM_PACKET_DATA_OFFSET]);
}

/*
 * Returns a pointer to the packet tail (immediately after the packet data).
 */
void *
sanctum_packet_tail(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);
	PRECOND(pkt->length <= SANCTUM_PACKET_DATA_LEN);

	return (&pkt->buf[SANCTUM_PACKET_DATA_OFFSET + pkt->length]);
}

/*
 * Check if the given packet contains enough data to satisfy
 * sanctum protocol header, tail and cipher overhead.
 *
 * The minimum requirement depends on wether or not shroud is
 * enabled and what process is calling this function.
 */
int
sanctum_packet_crypto_checklen(struct sanctum_packet *pkt)
{
	size_t			min;
	struct sanctum_proc	*proc;

	PRECOND(pkt != NULL);

	min = sizeof(struct sanctum_proto_hdr) +
	    sizeof(struct sanctum_proto_tail) + SANCTUM_TAG_LENGTH;

	proc = sanctum_process();

	if (proc->type == SANCTUM_PROC_PURGATORY_RX) {
		if (sanctum->flags & SANCTUM_FLAG_SHROUD)
			min += sizeof(struct sanctum_shroud_hdr);
	}

	if (pkt->length < min)
		return (-1);

	return (0);
}

/*
 * Check if a given packet comes from our current cathedral or not.
 * We check both the origin of the packet and the length. The origin must
 * match our current cathedral origin and the packet size must be at least
 * the size of an offer (tfc might pad this out).
 */
int
sanctum_packet_from_cathedral(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	if (pkt->addr.sin_addr.s_addr != sanctum->cathedral.sin_addr.s_addr ||
	    pkt->addr.sin_port != sanctum->cathedral.sin_port) {
		sanctum_log(LOG_NOTICE,
		    "cathedral packet from unexpected source %s",
		    sanctum_inet_string(&pkt->addr));
		return (-1);
	}

	if (pkt->length < sizeof(struct sanctum_offer)) {
		sanctum_log(LOG_NOTICE,
		    "cathedral packet of invalid size (%zu)", pkt->length);
		return (-1);
	}

	return (0);
}

/*
 * Shroud a packet using a unique mask we derive from the given key
 * and seed. The mask is applied over the entire packet minus the
 * shroud header.
 *
 * Before do the actual shrouding we randomize the packet length
 * to hide the actual size (if possible).
 */
void
sanctum_packet_shroud(struct sanctum_packet *pkt, const u_int8_t *id,
    size_t ilen, const u_int8_t *seed, size_t slen, const u_int8_t *key,
    size_t klen)
{
	u_int16_t			mtu;
	struct sanctum_shroud_hdr	*hdr;
	size_t				total;
	u_int8_t			*data;
	u_int32_t			min, avail, grow;

	PRECOND(pkt != NULL);
	PRECOND(id != NULL);
	PRECOND(ilen == SANCTUM_SHROUD_ID_LENGTH);
	PRECOND(seed != NULL);
	PRECOND(slen == SANCTUM_SHROUD_SEED_LENGTH);
	PRECOND(key != NULL);
	PRECOND(klen == SANCTUM_KEY_LENGTH);
	VERIFY(sanctum->flags & SANCTUM_FLAG_SHROUD);

	total = sizeof(*hdr) + pkt->length + SANCTUM_SHROUD_TRAIL_LEN;
	VERIFY(total > pkt->length && total < SANCTUM_PACKET_MAX_LEN);

	hdr = sanctum_packet_start(pkt);
	data = sanctum_packet_head(pkt);

	nyfe_memcpy(hdr->id, id, ilen);
	nyfe_memcpy(hdr->seed_id, seed, slen);
	sanctum_random_bytes(hdr->seed_data, sizeof(hdr->seed_data));

	data[pkt->length++] = 0xff;
	pkt->length += sizeof(*hdr);

	mtu = sanctum_atomic_read(&sanctum->mtu_size);
	if (pkt->length < mtu) {
		avail = mtu - pkt->length;
		if (avail >= 2) {
			min = -avail % avail;

			for (;;) {
				sanctum_random_bytes(&grow, sizeof(grow));
				if (grow >= min)
					break;
			}
		} else {
			grow = 0;
		}

		grow = grow % avail;
		pkt->length += grow;

		VERIFY(pkt->length < SANCTUM_PACKET_MAX_LEN);
	}

	packet_shroud_xor(pkt, key, klen, 0);
}

/*
 * Unshrouds a packet to bring the entire original packet.
 *
 * If unshrouding reduces the remaining packet left to an unexpected
 * amount we return an error as the packet should be dropped.
 */
int
sanctum_packet_unshroud(struct sanctum_packet *pkt, const void *key, size_t len)
{
	PRECOND(pkt != NULL);
	PRECOND(key != NULL);
	PRECOND(len == SANCTUM_KEY_LENGTH);
	VERIFY(sanctum->flags & SANCTUM_FLAG_SHROUD);

	if (pkt->length <=
	    sizeof(struct sanctum_shroud_hdr) + SANCTUM_SHROUD_TRAIL_LEN)
		return (-1);

	packet_shroud_xor(pkt, key, len, 1);

	if (pkt->length < sizeof(struct sanctum_proto_hdr) +
	    sizeof(struct sanctum_proto_tail) + SANCTUM_TAG_LENGTH) {
		sanctum_log(LOG_NOTICE,
		    "bad packet size after unshroud (len=%zu)", pkt->length);
		return (-1);
	}

	return (0);
}

/*
 * We calculate the required shroud mask and xor it onto the packet.
 * This function should be called with the length of the shroud header
 * included in the packet length.
 *
 * If we are unshrouding we remove the padding bytes from the end of
 * the packet to recover the original one.
 */
static void
packet_shroud_xor(struct sanctum_packet *pkt, const void *key, size_t len,
    int unshroud)
{
	struct nyfe_kmac256		kdf;
	struct sanctum_shroud_hdr	*hdr;
	u_int8_t			*data;
	int				steps;
	size_t				idx, length, orig;
	u_int8_t			mask[SANCTUM_SHROUD_MASK_MAX];

	PRECOND(pkt != NULL);
	PRECOND(key != NULL);
	PRECOND(len == SANCTUM_KEY_LENGTH);
	VERIFY(sanctum->flags & SANCTUM_FLAG_SHROUD);
	VERIFY(pkt->length >= sizeof(*hdr));

	hdr = sanctum_packet_start(pkt);
	data = sanctum_packet_head(pkt);
	length = pkt->length - sizeof(*hdr);

	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_kmac256_init(&kdf, key, len, SANCTUM_SHROUD_LABEL,
	    sizeof(SANCTUM_SHROUD_LABEL) - 1);
	nyfe_kmac256_update(&kdf, hdr, sizeof(*hdr));
	nyfe_kmac256_final(&kdf, mask, length);
	nyfe_zeroize(&kdf, sizeof(kdf));

	for (idx = 0; idx < length; idx++)
		data[idx] ^= mask[idx];

	if (unshroud) {
		pkt->length -= sizeof(*hdr);
		orig = pkt->length;

		steps = 0;
		while (pkt->length > 0 && data[pkt->length - 1] == 0x00) {
			pkt->length--;
			steps++;
		}

		if (pkt->length == 0)
			return;

		if (steps > 0 && data[pkt->length - 1] != 0xff)
			pkt->length = orig;
		else if (steps > 0 || data[pkt->length - 1] == 0xff)
			pkt->length--;
	}
}
