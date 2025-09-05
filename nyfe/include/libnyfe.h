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

#ifndef __H_LIBNYFE_H
#define __H_LIBNYFE_H

#if defined(NYFE_PLATFORM_WINDOWS)
#include "portable_win.h"
#endif

/* Keccak1600 defines. */
#define NYFE_KECCAK_1600_RATE		1600
#define NYFE_KECCAK_1600_MIN_BITS	256
#define NYFE_KECCAK_1600_MAX_RATE	\
    ((NYFE_KECCAK_1600_RATE - NYFE_KECCAK_1600_MIN_BITS) / 8)

/* File operations. */
#define NYFE_FILE_READ			1
#define NYFE_FILE_CREATE		2

/* Constants for certain primitives. */
#define NYFE_KEY_ID_LEN		16
#define NYFE_TAG_LEN		32
#define NYFE_SEED_LEN		64
#define NYFE_KEY_LEN		64
#define NYFE_OKM_LEN		NYFE_KEY_LEN

/*
 * Half of the seed is used as a salt into nyfe_passphrase_kdf() while
 * half of it is used as seed for key_kdf().
 */
#define NYFE_KEY_FILE_SALT_LEN		(NYFE_SEED_LEN / 2)

/*
 * Our keccak1600 context.
 */
struct nyfe_keccak1600 {
	u_int64_t	A[5][5];

	size_t		rate;
	u_int8_t	padding;
};

/*
 * Our SHA3 context, builds on the Keccak1600 context.
 */
struct nyfe_sha3 {
	struct nyfe_keccak1600		keccak;
	size_t				offset;
	size_t				digest_len;
	u_int8_t			buf[NYFE_KECCAK_1600_MAX_RATE];
};

/*
 * Our KMAC256 context, builds on the SHA3 context.
 */
struct nyfe_kmac256 {
	struct nyfe_sha3		sha3;
	int				isxof;
};

/*
 * The agelas stream cipher context.
 */
struct nyfe_agelas {
	struct nyfe_keccak1600	sponge;
	size_t			offset;
	u_int64_t		clen;
	u_int64_t		alen;
	u_int64_t		counter;
	u_int8_t		k2[136];
	u_int8_t		state[136];
};

/* src/agelas.c */
void	nyfe_agelas_aad(struct nyfe_agelas *, const void *, size_t);
void	nyfe_agelas_init(struct nyfe_agelas *, const void *, size_t);
void	nyfe_agelas_authenticate(struct nyfe_agelas *, u_int8_t *, size_t);
void	nyfe_agelas_encrypt(struct nyfe_agelas *, const void *, void *, size_t);
void	nyfe_agelas_decrypt(struct nyfe_agelas *, const void *, void *, size_t);

/* src/mem.c */
void	nyfe_zeroize_all(void);
void	nyfe_zeroize_warn(void);
void	nyfe_zeroize_init(void);
void	nyfe_zeroize(void *, size_t);
void	nyfe_mem_zero(void *, size_t);
void	nyfe_zeroize_register(void *, size_t);
void	nyfe_memcpy(void *, const void *, size_t);
int	nyfe_mem_cmp(const void *, const void *, size_t);

/* src/keccak1600.c */
void	nyfe_keccak1600_init(struct nyfe_keccak1600 *, u_int8_t, size_t);
void	nyfe_keccak1600_squeeze(struct nyfe_keccak1600 *, void *, size_t);
size_t	nyfe_keccak1600_absorb(struct nyfe_keccak1600 *,
	    const void *, size_t);

/* src/sha3.c */
void	nyfe_sha3_init256(struct nyfe_sha3 *);
void	nyfe_sha3_init512(struct nyfe_sha3 *);
void	nyfe_xof_shake128_init(struct nyfe_sha3 *);
void	nyfe_xof_shake256_init(struct nyfe_sha3 *);
void	nyfe_sha3_final(struct nyfe_sha3 *, u_int8_t *, size_t);
void	nyfe_sha3_update(struct nyfe_sha3 *, const void *, size_t);

/* src/kmac256.c */
void	nyfe_kmac256_xof(struct nyfe_kmac256 *);
void	nyfe_kmac256_final(struct nyfe_kmac256 *, u_int8_t *, size_t);
void	nyfe_kmac256_update(struct nyfe_kmac256 *, const void *, size_t);
void	nyfe_kmac256_init(struct nyfe_kmac256 *, const void *, size_t,
	    const void *, size_t);

/* src/passphrase.c */
void	nyfe_passphrase_kdf(const void *, u_int32_t, const void *, size_t,
	    u_int8_t *, size_t, const char *, size_t);

/* src/random.c */
void	nyfe_random_init(void);
void	nyfe_random_bytes(void *, size_t);

/* src/file.c */
u_int64_t	nyfe_file_size(int);
void		nyfe_file_init(void);
void		nyfe_file_close(int);
void		nyfe_file_remove_lingering(void);
int		nyfe_file_open(const char *, int);
size_t		nyfe_file_read(int, void *, size_t);
void		nyfe_file_write(int, const void *, size_t);

/* src/utils.c */
void	nyfe_fatal_callback(void (*)(const char *, va_list));
void	nyfe_fatal(const char *, ...) __attribute__((noreturn));

#endif
