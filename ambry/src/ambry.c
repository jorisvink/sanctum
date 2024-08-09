/*
 * Copyright (c) 2024 Joris Vink <joris@sanctorum.se>
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
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum_ambry.h"
#include "libnyfe.h"

#define AMBRY_KEK_DIRECTORY	"kek-data"
#define errno_s			strerror(errno)

struct entry {
	u_int16_t	tunnel;
	u_int8_t	seed[SANCTUM_AMBRY_SEED_LEN];
	u_int8_t	key[SANCTUM_AMBRY_KEY_LEN];
	u_int8_t	tag[SANCTUM_AMBRY_TAG_LEN];
} __attribute__((packed));

void		fatal(const char *, ...) __attribute__((noreturn));
static void	usage(void) __attribute__((noreturn));

static void	ambry_mkdir(const char *, int);

static void	ambry_kek_gen(const char *);
static void	ambry_kek_path(char *, size_t, u_int8_t);
static void	ambry_key_wrap(int, const u_int8_t *, size_t,
		    u_int8_t, u_int16_t, u_int32_t);

static int	ambry_generate_kek(int, char **);
static int	ambry_generate_ambry(int, char **);

static const struct {
	const char	*name;
	int		(*cb)(int, char **);
} cmds[] = {
	{ "generate-kek",	ambry_generate_kek },
	{ "generate-ambry",	ambry_generate_ambry },
	{ NULL,			NULL },
};

static void
usage(void)
{
	fprintf(stderr, "usage: ambry [cmd]\n");
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "  generate-kek      - Generates all new KEKs\n");
	fprintf(stderr, "  generate-ambry    - Generates an ambry file\n");

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
ambry_generate_kek(int argc, char **argv)
{
	int		idx;
	char		path[1024];

	if (argc != 0)
		fatal("Usage: generate-kek");

	ambry_mkdir(AMBRY_KEK_DIRECTORY, 0);

	for (idx = 0; idx <= 0xff; idx++) {
		ambry_kek_path(path, sizeof(path), idx);
		ambry_kek_gen(path);
	}

	return (0);
}

static int
ambry_generate_ambry(int argc, char **argv)
{
	struct sanctum_ambry_head	hdr;
	u_int32_t			gen;
	int				fd, src, dst;
	u_int8_t			seen[USHRT_MAX];
	u_int16_t			tunnel, reverse, count;
	u_int8_t			key[SANCTUM_AMBRY_KEY_LEN];

	if (argc != 1)
		fatal("Usage: generate-ambry [file]");

	if (unlink(argv[0]) == -1 && errno != ENOENT)
		fatal("failed to unlink '%s': %s", argv[0], errno_s);

	fd = nyfe_file_open(argv[0], NYFE_FILE_CREATE);

	nyfe_random_init();
	nyfe_random_bytes(&gen, sizeof(gen));

	hdr.generation = htonl(gen);
	nyfe_file_write(fd, &hdr, sizeof(hdr));

	count = 0;
	memset(seen, 0, sizeof(seen));
	nyfe_zeroize_register(key, sizeof(key));

	for (src = 0; src <= 0xff; src++) {
		for (dst = 0; dst <= 0xff; dst++) {
			if (src == dst)
				continue;

			nyfe_random_init();
			nyfe_random_bytes(key, sizeof(key));
			nyfe_random_init();

			tunnel = src << 8 | dst;
			reverse = dst << 8 | src;

			if (seen[tunnel] || seen[reverse])
				continue;

			ambry_key_wrap(fd, key, sizeof(key), src, tunnel, gen);
			ambry_key_wrap(fd, key, sizeof(key), dst, reverse, gen);

			seen[tunnel] = 1;
			seen[reverse] = 1;
			count++;
		}
	}

	nyfe_file_close(fd);

	fprintf(stderr, "generated %u tunnels, generation 0x%x\n", count, gen);
	nyfe_zeroize(key, sizeof(key));

	return (0);
}

static void
ambry_key_wrap(int out, const u_int8_t *key, size_t len, u_int8_t id,
    u_int16_t tunnel, u_int32_t gen)
{
	int			fd;
	struct nyfe_kmac256	kdf;
	struct entry		entry;
	struct nyfe_agelas	cipher;
	u_int8_t		okm_len;
	char			path[1024];
	u_int8_t		kek[SANCTUM_AMBRY_KEK_LEN];
	u_int8_t		okm[SANCTUM_AMBRY_OKM_LEN];

	if (len != sizeof(entry.key))
		fatal("len != entry.key");

	ambry_kek_path(path, sizeof(path), id);
	fd = nyfe_file_open(path, NYFE_FILE_READ);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(kek, sizeof(kek));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(&entry, sizeof(entry));

	entry.tunnel = htons(tunnel);
	nyfe_memcpy(entry.key, key, len);
	nyfe_random_bytes(entry.seed, sizeof(entry.seed));

	if (nyfe_file_read(fd, kek, sizeof(kek)) != sizeof(kek))
		fatal("bad read on KEK file %s", path);

	(void)close(fd);

	okm_len = SANCTUM_AMBRY_OKM_LEN;

	nyfe_kmac256_init(&kdf, kek, sizeof(kek),
	    SANCTUM_AMBRY_KDF, strlen(SANCTUM_AMBRY_KDF));
	nyfe_zeroize(kek, sizeof(kek));

	nyfe_kmac256_update(&kdf, &okm_len, sizeof(okm_len));
	nyfe_kmac256_update(&kdf, entry.seed, sizeof(entry.seed));
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));

	nyfe_agelas_init(&cipher, okm, sizeof(okm));
	nyfe_zeroize(okm, sizeof(okm));

	gen = htonl(gen);
	nyfe_agelas_aad(&cipher, &gen, sizeof(gen));
	nyfe_agelas_aad(&cipher, entry.seed, sizeof(entry.seed));
	nyfe_agelas_aad(&cipher, &entry.tunnel, sizeof(entry.tunnel));

	nyfe_agelas_encrypt(&cipher, entry.key, entry.key, sizeof(entry.key));
	nyfe_agelas_authenticate(&cipher, entry.tag, sizeof(entry.tag));

	nyfe_file_write(out, &entry, sizeof(entry));
	nyfe_zeroize(&entry, sizeof(entry));
}

static void
ambry_kek_gen(const char *path)
{
	int		fd;
	u_int8_t	kek[SANCTUM_AMBRY_KEK_LEN];

	nyfe_random_init();
	nyfe_zeroize_register(kek, sizeof(kek));

	printf("generating KEK in %s\n", path);
	fd = nyfe_file_open(path, NYFE_FILE_CREATE);

	nyfe_random_bytes(kek, sizeof(kek));
	nyfe_file_write(fd, kek, sizeof(kek));
	nyfe_file_close(fd);

	nyfe_zeroize(kek, sizeof(kek));
}

static void
ambry_kek_path(char *buf, size_t buflen, u_int8_t kek)
{
	int		len;

	len = snprintf(buf, buflen, "%s/kek-0x%02x", AMBRY_KEK_DIRECTORY, kek);
	if (len == -1 || (size_t)len >= buflen)
		fatal("failed to construct path to kek");
}

static void
ambry_mkdir(const char *path, int exists_ok)
{
	if (mkdir(path, 0700) == -1) {
		if (exists_ok && errno == EEXIST)
			return;
		fatal("failed to create '%s': %s", path, errno_s);
	}
}
