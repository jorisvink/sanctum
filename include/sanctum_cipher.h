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

/* The RX direction for session key derivation. */
#define SANCTUM_KEY_DIRECTION_RX		0x01

/* The TX direction for session key derivation. */
#define SANCTUM_KEY_DIRECTION_TX		0x02

/* Length of our symmetrical keys, in bytes. */
#define SANCTUM_KEY_LENGTH			32

/* Length of x25519 scalars. */
#define SANCTUM_X25519_SCALAR_BYTES		SANCTUM_KEY_LENGTH

/* Length of the ML-KEM-1024 shared secret. */
#define SANCTUM_MLKEM_1024_KEY_BYTES		SANCTUM_KEY_LENGTH

/* Length for an encapsulation key in hex. */
#define SANCTUM_ENCAP_HEX_LEN			(SANCTUM_KEY_LENGTH * 2)

/* The nonce size, in our case 96-bit. */
#define SANCTUM_NONCE_LENGTH			12

/*
 * The packet tag size depends on the select cipher. For AES-GCM the tag
 * size is 128-bit while for Agelas we have a 256-bit tag.
 */
#if defined(SANCTUM_USE_AGELAS)
#define SANCTUM_TAG_LENGTH			32
#else
#define SANCTUM_TAG_LENGTH			16
#endif

/* Number of bytes for the ML-KEM-1024 secret key. */
#define SANCTUM_MLKEM_1024_SECRETKEYBYTES	3168

/* Number of bytes for the ML-KEM-1024 public key we share. */
#define SANCTUM_MLKEM_1024_PUBLICKEYBYTES	1568

/* Number of bytes for the ML-KEM-1024 ciphertext we share. */
#define SANCTUM_MLKEM_1024_CIPHERTEXTBYTES	\
    SANCTUM_MLKEM_1024_PUBLICKEYBYTES

/*
 * Data structure used when calling sanctum_traffic_kdf().
 */
struct sanctum_kex {
	u_int32_t		purpose;
	u_int8_t		kem[SANCTUM_MLKEM_1024_KEY_BYTES];
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
 * Used to interface with the ML-KEM-1024 api.
 */
struct sanctum_mlkem1024 {
	u_int8_t	ss[SANCTUM_KEY_LENGTH];
	u_int8_t	sk[SANCTUM_MLKEM_1024_SECRETKEYBYTES];
	u_int8_t	pk[SANCTUM_MLKEM_1024_PUBLICKEYBYTES];
	u_int8_t	ct[SANCTUM_MLKEM_1024_CIPHERTEXTBYTES];
};

/* The ML-KEM-1024 API. */
void	sanctum_mlkem1024_selftest(void);
void	sanctum_mlkem1024_keypair(struct sanctum_mlkem1024 *);
void	sanctum_mlkem1024_encapsulate(struct sanctum_mlkem1024 *);
void	sanctum_mlkem1024_decapsulate(struct sanctum_mlkem1024 *);

/* The mlkem1024 backend api. */
int	pqcrystals_kyber1024_ref_keypair(u_int8_t *, u_int8_t *);
int	pqcrystals_kyber1024_ref_keypair_derand(u_int8_t *, u_int8_t *,
	    const u_int8_t *);
int	pqcrystals_kyber1024_ref_enc(u_int8_t *, u_int8_t *, const u_int8_t *);
int	pqcrystals_kyber1024_ref_enc_derand(u_int8_t *, u_int8_t *,
	    const u_int8_t *, const u_int8_t *);
int	pqcrystals_kyber1024_ref_dec(u_int8_t *, const u_int8_t *,
	    const u_int8_t *);

/* The cipher API. */
void	sanctum_cipher_init(void);
void	sanctum_cipher_cleanup(void *);
void	*sanctum_cipher_setup(struct sanctum_key *);
void	sanctum_cipher_encrypt(struct sanctum_cipher *);
int	sanctum_cipher_decrypt(struct sanctum_cipher *);

/* The asymmetry API. */
int	sanctum_asymmetry_keygen(u_int8_t *, size_t, u_int8_t *, size_t);
int	sanctum_asymmetry_derive(struct sanctum_kex *, u_int8_t *, size_t);

/* The random API. */
void	sanctum_random_init(void);
void	sanctum_random_bytes(void *, size_t);

#endif
