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

#ifndef __H_NYFE_H
#define __H_NYFE_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnyfe.h"

/* Apple .. */
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe32(x)		OSSwapHostToBigInt32(x)
#define htobe64(x)		OSSwapHostToBigInt64(x)
#endif

/* Some handy macros. */
#define errno_s			strerror(errno)

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			fatal("precondition failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

#define VERIFY(x)							\
	do {								\
		if (!(x)) {						\
			fatal("verification failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

/* Constants for certain primitives. */
#define NYFE_KEY_ID_LEN		16
#define NYFE_TAG_LEN		32
#define NYFE_SEED_LEN		64
#define NYFE_KEY_LEN		64
#define NYFE_OKM_LEN		NYFE_KEY_LEN

/*
 * A key loaded from a keyfile.
 */
struct nyfe_key {
	u_int8_t		id[NYFE_KEY_ID_LEN];
	u_int8_t		data[NYFE_KEY_LEN];
	u_int8_t		tag[NYFE_TAG_LEN];
} __attribute__((packed));

/* src/nyfe.c */
void	nyfe_output_spin(void);
int	nyfe_signal_pending(void);
void	nyfe_read_passphrase(void *, size_t);
void	fatal(const char *, ...) __attribute__((noreturn));
void	nyfe_output(const char *, ...) __attribute__((format (printf, 1, 2)));

const char	*nyfe_entropy_path(void);

/* src/crypto.c */
void	nyfe_crypto_decrypt(const char *, const char *, const char *);
void	nyfe_crypto_encrypt(const char *, const char *, const char *);

/* src/keys.c */
void	nyfe_key_clone(const char *, const char *);
void	nyfe_key_load(struct nyfe_key *, const char *);
void	nyfe_key_generate(const char *, struct nyfe_key *);

/* src/selftests.c */
void	nyfe_selftest_kmac256(void);

/* version information. */
extern const char	*nyfe_version;
extern const char	*nyfe_build_date;

#endif
