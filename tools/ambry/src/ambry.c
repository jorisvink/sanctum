/*
 * Copyright (c) 2024-2025 Joris Vink <joris@sanctorum.se>
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
#include <sys/stat.h>

#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum_portability.h"
#include "sanctum_cipher.h"
#include "sanctum_ambry.h"
#include "libnyfe.h"

#define AMBRY_KEK_DIRECTORY	"kek-data"
#define errno_s			strerror(errno)

void			fatal(const char *, ...) __attribute__((noreturn));
static void		usage(void) __attribute__((noreturn));

static void		ambry_mkdir(u_int64_t, const char *, int);

static void		ambry_kek_gen(const char *);
static void		ambry_kek_path(u_int64_t, u_int8_t, char *, size_t);
static void		ambry_key_wrap(struct sanctum_ambry_head *, int,
			    const u_int8_t *, size_t, u_int64_t, u_int64_t,
			    u_int8_t, u_int16_t);

static int		ambry_kek_renew(int, char **);
static int		ambry_kek_generate(int, char **);
static int		ambry_bundle_generate(int, char **);

static u_int64_t	ambry_string_to_flock(const char *);

static const struct {
	const char	*name;
	int		(*cb)(int, char **);
} cmds[] = {
	{ "generate",		ambry_kek_generate },
	{ "bundle",		ambry_bundle_generate },
	{ "renew",		ambry_kek_renew },
	{ NULL,			NULL },
};

static void
usage(void)
{
	fprintf(stderr, "usage: ambry [cmd]\n");
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "  bundle        - Generates a new ambry bundle\n");
	fprintf(stderr, "  generate      - Generates all new device KEKs\n");
	fprintf(stderr, "  renew         - Renews a given device KEK\n");

	exit(1);
}

int
main(int argc, char *argv[])
{
	int		idx, ret;

	if (argc < 2)
		usage();

	argc--;
	argv++;
	ret = 1;

	for (idx = 0; cmds[idx].name != NULL; idx++) {
		if (!strcmp(cmds[idx].name, argv[0])) {
			argc--;
			argv++;
			ret = cmds[idx].cb(argc, argv);
			break;
		}
	}

	if (cmds[idx].name == NULL)
		fatal("unknown command '%s'", argv[0]);

	nyfe_zeroize_all();

	return (ret);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	nyfe_zeroize_all();

	fprintf(stderr, "ambry: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

static int
ambry_kek_generate(int argc, char **argv)
{
	int		idx;
	u_int64_t	flock;
	char		path[1024];

	if (argc != 1)
		fatal("Usage: generate [flock]");

	flock = ambry_string_to_flock(argv[0]);
	ambry_mkdir(flock, AMBRY_KEK_DIRECTORY, 0);

	printf("generating KEKs under %" PRIx64 "\n", flock);

	for (idx = 1; idx <= 0xff; idx++) {
		ambry_kek_path(flock, idx, path, sizeof(path));
		ambry_kek_gen(path);
	}

	return (0);
}

static int
ambry_kek_renew(int argc, char **argv)
{
	unsigned long		kek;
	char			*ep;
	u_int64_t		flock;
	char			path[1024];

	if (argc != 2)
		fatal("Usage: renew [flock] [id]");

	flock = ambry_string_to_flock(argv[0]);

	errno = 0;
	kek = strtoul(argv[1], &ep, 16);
	if (errno != 0 || argv[1] == ep || *ep != '\0')
		fatal("not a number: %s", argv[1]);

	if (kek > UCHAR_MAX)
		fatal("'%s': out of range", argv[1]);

	ambry_mkdir(flock, AMBRY_KEK_DIRECTORY, 1);
	ambry_kek_path(flock, kek, path, sizeof(path));

	if (unlink(path) == -1 && errno != ENOENT)
		fatal("failed to remove '%s' (%s)", path, errno_s);

	ambry_kek_gen(path);

	return (0);
}

static int
ambry_bundle_generate(int argc, char **argv)
{
	struct sanctum_ambry_head	hdr;
	u_int32_t			gen;
	int				fd, src, dst;
	u_int8_t			seen[USHRT_MAX];
	u_int64_t			flock_a, flock_b;
	u_int16_t			tunnel, reverse, count;
	u_int8_t			key[SANCTUM_AMBRY_KEY_LEN];

	if (argc != 3)
		fatal("Usage: bundle [flock-A] [flock-B] [file]");

	flock_a = ambry_string_to_flock(argv[0]);
	flock_b = ambry_string_to_flock(argv[1]);

	if (unlink(argv[2]) == -1 && errno != ENOENT)
		fatal("failed to unlink '%s': %s", argv[2], errno_s);

	nyfe_mem_zero(&hdr, sizeof(hdr));
	fd = nyfe_file_open(argv[2], NYFE_FILE_CREATE);

	sanctum_random_init();
	sanctum_random_bytes(&gen, sizeof(gen));
	sanctum_random_bytes(hdr.seed, sizeof(hdr.seed));

	hdr.generation = htobe32(gen);
	nyfe_file_write(fd, &hdr, sizeof(hdr));

	count = 0;
	memset(seen, 0, sizeof(seen));
	nyfe_zeroize_register(key, sizeof(key));

	for (src = 1; src <= 0xff; src++) {
		for (dst = 1; dst <= 0xff; dst++) {
			if (flock_a == flock_b) {
				if (src == dst)
					continue;
			}

			tunnel = src << 8 | dst;
			reverse = dst << 8 | src;

			if (flock_a == flock_b) {
				if (seen[tunnel] || seen[reverse])
					continue;
			}

			sanctum_random_init();
			sanctum_random_bytes(key, sizeof(key));
			sanctum_random_init();

			ambry_key_wrap(&hdr, fd, key, sizeof(key),
			    flock_a, flock_b, src, tunnel);
			ambry_key_wrap(&hdr, fd, key, sizeof(key),
			    flock_b, flock_a, dst, reverse);

			if (flock_a == flock_b) {
				seen[tunnel] = 1;
				seen[reverse] = 1;
			}

			count++;
		}
	}

	nyfe_file_close(fd);

	fprintf(stderr, "%s: generated %u tunnels, generation 0x%x\n",
	    argv[2], count, gen);
	nyfe_zeroize(key, sizeof(key));

	return (0);
}

static void
ambry_key_wrap(struct sanctum_ambry_head *hdr, int out, const u_int8_t *key,
    size_t len, u_int64_t flock_src, u_int64_t flock_dst, u_int8_t id,
    u_int16_t tunnel)
{
	int				fd;
	struct nyfe_kmac256		kdf;
	struct sanctum_key		okm;
	struct sanctum_ambry_aad	aad;
	struct sanctum_ambry_entry	entry;
	struct sanctum_cipher		cipher;
	u_int8_t			in_len;
	char				path[1024];
	u_int8_t			kek[SANCTUM_AMBRY_KEK_LEN];
	u_int8_t			nonce[SANCTUM_NONCE_LENGTH];

	if (len != sizeof(entry.key))
		fatal("len != entry.key");

	ambry_kek_path(flock_src, id, path, sizeof(path));

	flock_src = htobe64(flock_src);
	flock_dst = htobe64(flock_dst);
	fd = nyfe_file_open(path, NYFE_FILE_READ);

	nyfe_zeroize_register(kek, sizeof(kek));
	nyfe_zeroize_register(&okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(&entry, sizeof(entry));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	entry.flock = flock_src;
	entry.tunnel = htobe16(tunnel);
	nyfe_memcpy(entry.key, key, len);

	if (nyfe_file_read(fd, kek, sizeof(kek)) != sizeof(kek))
		fatal("bad read on KEK file %s", path);

	(void)close(fd);

	nyfe_kmac256_init(&kdf, kek, sizeof(kek),
	    SANCTUM_AMBRY_KDF, strlen(SANCTUM_AMBRY_KDF));
	nyfe_zeroize(kek, sizeof(kek));

	in_len = sizeof(hdr->seed);
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, hdr->seed, sizeof(hdr->seed));

	in_len = sizeof(flock_src);
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, &flock_src, sizeof(flock_src));
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, &flock_dst, sizeof(flock_dst));

	in_len = sizeof(hdr->generation);
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, &hdr->generation, sizeof(hdr->generation));

	in_len = sizeof(tunnel);
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, &entry.tunnel, sizeof(entry.tunnel));

	nyfe_kmac256_final(&kdf, okm.key, sizeof(okm.key));
	nyfe_zeroize(&kdf, sizeof(kdf));

	cipher.ctx = sanctum_cipher_setup(&okm);
	nyfe_zeroize(&okm, sizeof(okm));

	aad.tunnel = entry.tunnel;
	aad.flock_src = flock_src;
	aad.flock_dst = flock_dst;
	aad.generation = hdr->generation;
	nyfe_memcpy(aad.seed, hdr->seed, sizeof(hdr->seed));

	nyfe_mem_zero(nonce, sizeof(nonce));
	nonce[SANCTUM_NONCE_LENGTH - 1] = 0x01;

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	cipher.pt = entry.key;
	cipher.ct = entry.key;
	cipher.tag = &entry.tag[0];
	cipher.data_len = sizeof(entry.key);

	sanctum_cipher_encrypt(&cipher);
	nyfe_zeroize(&cipher, sizeof(cipher));

	nyfe_file_write(out, &entry, sizeof(entry));
	nyfe_zeroize(&entry, sizeof(entry));
}

static void
ambry_kek_gen(const char *path)
{
	int		fd;
	u_int8_t	kek[SANCTUM_AMBRY_KEK_LEN];

	sanctum_random_init();
	nyfe_zeroize_register(kek, sizeof(kek));

	fd = nyfe_file_open(path, NYFE_FILE_CREATE);

	sanctum_random_bytes(kek, sizeof(kek));
	nyfe_file_write(fd, kek, sizeof(kek));
	nyfe_file_close(fd);

	nyfe_zeroize(kek, sizeof(kek));
}

static void
ambry_kek_path(u_int64_t flock, u_int8_t kek, char *buf, size_t buflen)
{
	int		len;

	len = snprintf(buf, buflen, "%" PRIx64 "/%s/kek-0x%02x",
	    flock, AMBRY_KEK_DIRECTORY, kek);
	if (len == -1 || (size_t)len >= buflen)
		fatal("failed to construct path to kek");
}

static void
ambry_mkdir(u_int64_t flock, const char *dir, int exists_ok)
{
	int		len;
	char		path[1024];

	len = snprintf(path, sizeof(path), "%" PRIx64, flock);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("failed to construct flock dir");

	if (mkdir(path, 0700) == -1 && errno != EEXIST)
		fatal("failed to create '%s': %s", path, errno_s);

	len = snprintf(path, sizeof(path), "%" PRIx64 "/%s", flock, dir);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("failed to construct flock/%s dir", dir);

	if (mkdir(path, 0700) == -1) {
		if (exists_ok && errno == EEXIST)
			return;
		fatal("failed to create '%s': %s", path, errno_s);
	}
}

static u_int64_t
ambry_string_to_flock(const char *str)
{
	char		*ep;
	u_int64_t	flock;

	errno = 0;
	flock = strtoull(str, &ep, 16);
	if (errno != 0 || str == ep || *ep != '\0')
		fatal("not a number: %s", str);

	return (flock & ~(0xff));
}
