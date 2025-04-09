/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
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

#ifndef __H_SANCTUM_CIPHER_H
#define __H_SANCTUM_CIPHER_H

/* Length of our symmetrical keys, in bytes. */
#define SANCTUM_KEY_LENGTH		32

/* Length for an encapsulation key in hex. */
#define SANCTUM_ENCAP_HEX_LEN		(SANCTUM_KEY_LENGTH * 2)

/* The nonce size, in our case 96-bit. */
#define SANCTUM_NONCE_LENGTH		12

/* The tag size, in our case 128-bit. */
#define SANCTUM_TAG_LENGTH		16

/*
 * Data structure used when calling sanctum_traffic_kdf().
 */
struct sanctum_kex {
	u_int8_t		pub1[32];
	u_int8_t		pub2[32];
	u_int8_t		remote[32];
	u_int8_t		private[32];
};

/*
 * Represents a key that is used either by bless, confess or potentially
 * key processes when doing offers.
 */
struct sanctum_key {
	volatile u_int32_t	spi;
	volatile u_int32_t	salt;
	volatile int		state;
	u_int8_t		key[SANCTUM_KEY_LENGTH];
};

/*
 * Used to interface with the cipher backends.
 */
struct sanctum_cipher {
	void			*pt;
	void			*ct;
	void			*aad;
	void			*ctx;
	void			*tag;
	void			*nonce;
	size_t			aad_len;
	size_t			data_len;
	size_t			nonce_len;

};

/* The cipher API. */
void	sanctum_cipher_init(void);
void	sanctum_cipher_cleanup(void *);
void	*sanctum_cipher_setup(struct sanctum_key *);
void	sanctum_cipher_encrypt(struct sanctum_cipher *);
int	sanctum_cipher_decrypt(struct sanctum_cipher *);

#endif
