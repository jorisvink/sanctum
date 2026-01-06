/*
 * Copyright (c) 2024-2026 Joris Vink <joris@sanctorum.se>
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

#ifndef __H_SANCTUM_AMBRY_H
#define __H_SANCTUM_AMBRY_H

/* Length of a seed using for deriving Ambry wrapping keys. */
#define SANCTUM_AMBRY_SEED_LEN			64

/* Length of a KEK used for an Ambry. */
#define SANCTUM_AMBRY_KEK_LEN			SANCTUM_KEY_LENGTH

/* Length of the key carried in an Ambry. */
#define SANCTUM_AMBRY_KEY_LEN			SANCTUM_KEY_LENGTH

/* Length of an authentication tag for an Ambry. */
#define SANCTUM_AMBRY_TAG_LEN			SANCTUM_TAG_LENGTH

/* The epoch for when expiration time accounting begins. */
#define SANCTUM_AMBRY_AGE_EPOCH			1697855580

/* Much like TAI and the dark side we deal in absolutes. */
#define SANCTUM_AMBRY_AGE_SECONDS_PER_DAY	86400

/*
 * The ambry AAD data per entry.
 */
struct sanctum_ambry_aad {
	u_int16_t	tunnel;
	u_int16_t	expires;
	u_int64_t	flock_src;
	u_int64_t	flock_dst;
	u_int32_t	generation;
	u_int8_t	seed[SANCTUM_AMBRY_SEED_LEN];
} __attribute__((packed));

/*
 * The ambry header.
 *
 * The header includes the current generation (4 bytes) and the
 * 64-byte seed that is used in combination with individual KEKs
 * to generate the encryption key under which the shared secrets are wrapped.
 *
 * The expiration time is counted in days (with 86400 seconds per day)
 * and from SANCTUM_AMBRY_AGE_EPOCH. Clients will not accept keys that
 * are expired.
 */
struct sanctum_ambry_head {
	u_int16_t	expires;
	u_int32_t	generation;
	u_int8_t	seed[SANCTUM_AMBRY_SEED_LEN];
} __attribute__((packed));

/* 
 * An ambry entry, consisting of the tunnel ID, the flock it belongs too,
 * the wrapped key and the authentication tag calculated over the key
 * ciphertext and sanctum_ambry_aad.
 */
struct sanctum_ambry_entry {
	u_int64_t	flock;
	u_int16_t	tunnel;
	u_int8_t	key[SANCTUM_AMBRY_KEY_LEN];
	u_int8_t	tag[SANCTUM_AMBRY_TAG_LEN];
} __attribute__((packed));

#endif
