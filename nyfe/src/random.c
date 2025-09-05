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

#include <sys/param.h>
#include <sys/types.h>

#if defined(__APPLE__)
#include <sys/random.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "nyfe.h"

/*
 * The nyfe random system, based on our Agelas implementation.
 *
 * A temporary Agelas state is initialized with a key derived
 * via KMAC256(K, L)[64] where K is 64 bytes of entropy pulled
 * via getentropy() and L is 64.
 *
 * This state is used to generate 1024 of keystream into 'ks' which is
 * what ends up being copied out when random bytes are requested.
 *
 * After the keystream is generated the state is wiped.
 */
#define RANDOM_ADD_SIZE		64
#define RANDOM_KEYSTREAM_LEN	1024
#define RANDOM_LABEL		"NYFE.RANDOM"

static void	random_rekey(void);

/* The keystream and number of bytes left of it. */
size_t					ks_available = 0;
static u_int8_t				ks[RANDOM_KEYSTREAM_LEN];

/* Set to 1 once we are initialized */
static u_int32_t			random_setup = 0;

/*
 * Setup the random system by doing the initial keystream generation.
 */
void
nyfe_random_init(void)
{
	random_rekey();
	random_setup = 1;
}

/*
 * Generate a number of random bytes, rekeying when needed.
 */
void
nyfe_random_bytes(void *buf, size_t len)
{
	size_t		tocopy;
	u_int8_t	*ptr, *ksp;

	PRECOND(buf != NULL);
	PRECOND(len > 0);
	PRECOND(random_setup == 1);
	PRECOND(ks_available <= sizeof(ks));

	if (ks_available == 0)
		random_rekey();

	ptr = buf;
	ksp = &ks[sizeof(ks) - ks_available];

	while (len > 0) {
		tocopy = MIN(ks_available, len);
		nyfe_memcpy(ptr, ksp, tocopy);
		nyfe_mem_zero(ksp, tocopy);

		ptr += tocopy;
		ksp += tocopy;

		len -= tocopy;
		ks_available -= tocopy;

		if (ks_available == 0) {
			random_rekey();
			ksp = &ks[sizeof(ks) - ks_available];
		}
	}
}

/*
 * Helper function that will do the actual rekeying and keystream generation.
 */
static void
random_rekey(void)
{
#if !defined(NYFE_LIBRARY_ONLY)
	int				fd;
#endif
	u_int8_t			len;
	struct nyfe_kmac256		kmac;
	struct nyfe_agelas		state;
	u_int8_t			add[RANDOM_ADD_SIZE];
	u_int8_t			seed[64], key[NYFE_KEY_LEN];

#if !defined(NYFE_LIBRARY_ONLY)
	/* Load in the entropy file, if its not present, complain. */
	if ((fd = open(nyfe_entropy_path(), O_RDWR)) == -1) {
		if (errno != ENOENT) {
			nyfe_fatal("open(%s): %s",
			    nyfe_entropy_path(), errno_s);
		}
		nyfe_output("warning: no entropy file present, "
		    "only system entropy will be used\n");
	} else {
		if (nyfe_file_read(fd, add, sizeof(add)) != sizeof(add))
			nyfe_fatal("failed to read entropy file");
	}
#endif

#if defined(NYFE_PLATFORM_WINDOWS)
	/* XXX */
	if (RtlGenRandom(seed, sizeof(seed)) == 0)
		nyfe_fatal("RtlGenRandom: failed");
#else
	/* Obtain some system entropy. */
	if (getentropy(seed, sizeof(seed)) == -1)
		nyfe_fatal("getentropy: %s", errno_s);
#endif

	/*
	 * Derive key and nonce material using KMAC256 with the seed
	 * from getentropy() as the key and the additional entropy data.
	 */
	nyfe_kmac256_init(&kmac, seed, sizeof(seed),
	    RANDOM_LABEL, sizeof(RANDOM_LABEL) - 1);

	len = RANDOM_ADD_SIZE;
	nyfe_kmac256_update(&kmac, &len, sizeof(len));
	nyfe_kmac256_update(&kmac, add, sizeof(add));

	/* Derive a key for Agelas. */
	nyfe_kmac256_final(&kmac, key, sizeof(key));
	nyfe_mem_zero(&kmac, sizeof(kmac));

	/* Setup the Agelas state using the derived key. */
	nyfe_agelas_init(&state, key, sizeof(key));
	nyfe_mem_zero(key, sizeof(key));

	/* Generate new keystream. */
	ks_available = sizeof(ks);
	nyfe_mem_zero(ks, sizeof(ks));
	nyfe_agelas_encrypt(&state, ks, ks, sizeof(ks));

	/* We don't need state anymore. */
	nyfe_mem_zero(&state, sizeof(state));

#if !defined(NYFE_LIBRARY_ONLY)
	/*
	 * Take the first RANDOM_ADD_SIZE bytes of keystream and overwrite
	 * the existing entropy file.
	 */
	if (fd != -1) {
		if (lseek(fd, 0, SEEK_SET) == -1)
			nyfe_fatal("lseek: %s", errno_s);

		nyfe_file_write(fd, ks, RANDOM_ADD_SIZE);

		if (close(fd) == -1) {
			nyfe_output("warning: entropy file close failed (%s)",
			    errno_s);
		}

		ks_available -= RANDOM_ADD_SIZE;
	}
#endif
}
