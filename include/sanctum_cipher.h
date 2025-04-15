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

/* The KDF domain separation byte for RX keys. */
#define SANCTUM_KEY_DIRECTION_RX		0x01

/* The KDF domain separation byte for TX keys. */
#define SANCTUM_KEY_DIRECTION_TX		0x02

/* Length of our symmetrical keys, in bytes. */
#define SANCTUM_KEY_LENGTH			32

/* Length of x25519 scalars. */
#define SANCTUM_X25519_SCALAR_BYTES		SANCTUM_KEY_LENGTH

/* Length of the ML-KEM-768 shared secret. */
#define SANCTUM_MLKEM_768_KEY_BYTES		SANCTUM_KEY_LENGTH

/* Length for an encapsulation key in hex. */
#define SANCTUM_ENCAP_HEX_LEN			(SANCTUM_KEY_LENGTH * 2)

/* The nonce size, in our case 96-bit. */
#define SANCTUM_NONCE_LENGTH			12

/* The tag size, in our case 128-bit. */
#define SANCTUM_TAG_LENGTH			16

/* Number of bytes for the ML-KEM-768 secret key. */
#define SANCTUM_MLKEM768_SECRETKEYBYTES		2400

/* Number of bytes for the ML-KEM-768 public key we share. */
#define SANCTUM_MLKEM768_PUBLICKEYBYTES		1184

/* Number of bytes for the ML-KEM-768 ciphertext we share. */
#define SANCTUM_MLKEM768_CIPHERTEXTBYTES	1088

/*
 * Data structure used when calling sanctum_traffic_kdf().
 */
struct sanctum_kex {
	u_int8_t		kem[SANCTUM_MLKEM_768_KEY_BYTES];
	u_int8_t		pub1[SANCTUM_X25519_SCALAR_BYTES];
	u_int8_t		pub2[SANCTUM_X25519_SCALAR_BYTES];
	u_int8_t		remote[SANCTUM_X25519_SCALAR_BYTES];
	u_int8_t		private[SANCTUM_X25519_SCALAR_BYTES];
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

/*
 * Used to interface with the ML-KEM-768 api.
 */
struct sanctum_mlkem768 {
	u_int8_t	ss[SANCTUM_KEY_LENGTH];
	u_int8_t	sk[SANCTUM_MLKEM768_SECRETKEYBYTES];
	u_int8_t	pk[SANCTUM_MLKEM768_PUBLICKEYBYTES];
	u_int8_t	ct[SANCTUM_MLKEM768_CIPHERTEXTBYTES];
};

/* The ML-KEM-768 API. */
void	sanctum_mlkem768_selftest(void);
void	sanctum_mlkem768_keypair(struct sanctum_mlkem768 *);
void	sanctum_mlkem768_encapsulate(struct sanctum_mlkem768 *);
void	sanctum_mlkem768_decapsulate(struct sanctum_mlkem768 *);

/* The mlkem768 backend api. */
int	pqcrystals_kyber768_ref_keypair(u_int8_t *, u_int8_t *);
int	pqcrystals_kyber768_ref_keypair_derand(u_int8_t *, u_int8_t *,
	    const u_int8_t *);
int	pqcrystals_kyber768_ref_enc(u_int8_t *, u_int8_t *, const u_int8_t *);
int	pqcrystals_kyber768_ref_enc_derand(u_int8_t *, u_int8_t *,
	    const u_int8_t *, const u_int8_t *);
int	pqcrystals_kyber768_ref_dec(u_int8_t *, const u_int8_t *,
	    const u_int8_t *);

/* The cipher API. */
void	sanctum_cipher_init(void);
void	sanctum_cipher_cleanup(void *);
void	*sanctum_cipher_setup(struct sanctum_key *);
void	sanctum_cipher_encrypt(struct sanctum_cipher *);
int	sanctum_cipher_decrypt(struct sanctum_cipher *);

/* The asymmetry API. */
void	sanctum_asymmetry_keygen(u_int8_t *, size_t, u_int8_t *, size_t);
void	sanctum_asymmetry_derive(struct sanctum_kex *, u_int8_t *, size_t);

#endif
