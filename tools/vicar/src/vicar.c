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

/*
 * The vicar tool is an administrative tool that is part of the sanctum project.
 *
 * It is used to generate encrypted sanctum configurations that contain
 * a device its cathedral id, flock id, Key-Encryption-Key and cathedral
 * secret. It also holds the initial cathedral to bootstrap a device.
 */

#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "libnyfe.h"
#include "sanctum_cipher.h"

#define VICAR_KEY_LEN			64
#define VICAR_SALT_LEN			32
#define VICAR_TAG_LEN			32

#define KDF_LABEL			"VICAR.PASSPHRASE.PBKDF"

struct config {
	u_int8_t	salt[VICAR_SALT_LEN];

	struct {
		u_int32_t	id;
		u_int32_t	ip;
		u_int64_t	flock;
		u_int16_t	port;
		u_int16_t	tunnel;
		u_int8_t	kek[32];
		u_int8_t	secret[32];
	} data;

	u_int8_t	tag[VICAR_TAG_LEN];
} __attribute__((packed));

void		usage(void) __attribute__((noreturn));
void		fatal(const char *, ...) __attribute__((noreturn));

u_int64_t	vicar_strtonum(const char *, int);
void		vicar_wrap_config(struct config *);
void		vicar_read_passphrase(void *, size_t);
void		vicar_config_write(const char *, struct config *);
void		vicar_read_secret(const char *, u_int8_t *, size_t);

void
usage(void)
{
	printf("usage: vicar [arguments]\n");
	printf("\n");
	printf("Creates a configuration file that can be used with certain\n");
	printf("types of applications using sanctum.\n");
	printf("\n");
	printf("arguments:\n");
	printf("  [tunnel] [flock] [cid] [kek-path] [cs-path] "
	    "[ip] [port] [out]\n");
	printf("\n");
	printf("  tunnel     - The device ID (matches your KEK)\n");
	printf("  flock      - The flock the device belongs too\n");
	printf("  cid        - The device its cathedral ID\n");
	printf("  kek-path   - The path to the KEK secret\n");
	printf("  cs-path    - The path to the cathedral secret\n");
	printf("  ip         - The ip address of the initial cathedral\n");
	printf("  port       - The port of the initial cathedral\n");
	printf("  out        - The file where to save the configuration\n");
	printf("\n");
	printf("Example:\n");
	printf("  $ vicar 0x0200 2e976eddb2203a0c 1af4279e cfg/kek-0x02 \\\n");
	printf("          cfg/id-1af4279e 127.0.0.1 4500 phone-2.cfg\n");

	exit(1);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	nyfe_zeroize_all();

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

int
main(int argc, char *argv[])
{
	struct config		cfg;

	if (argc != 9)
		usage();

	sanctum_random_init();

	memset(&cfg, 0, sizeof(cfg));
	nyfe_zeroize_register(&cfg, sizeof(cfg));

	cfg.data.tunnel = vicar_strtonum(argv[1], 16);
	cfg.data.flock = vicar_strtonum(argv[2], 16);
	cfg.data.id = vicar_strtonum(argv[3], 16);

	vicar_read_secret(argv[4], cfg.data.kek, sizeof(cfg.data.kek));
	vicar_read_secret(argv[5], cfg.data.secret, sizeof(cfg.data.secret));

	cfg.data.ip = inet_addr(argv[6]);
	cfg.data.port = vicar_strtonum(argv[7], 10);
	cfg.data.port = htons(cfg.data.port);

	vicar_wrap_config(&cfg);
	vicar_config_write(argv[8], &cfg);

	nyfe_zeroize(&cfg, sizeof(cfg));
	nyfe_zeroize_all();

	printf("configuration written:\n");
	printf("   flock       %s\n", argv[2]);
	printf("   tunnel      %s\n", argv[1]);
	printf("   identity    %s\n", argv[3]);
	printf("   kek-path    %s\n", argv[4]);
	printf("   cs-path     %s\n", argv[5]);
	printf("   cathedral   %s:%s\n", argv[6], argv[7]);

	return (0);
}

u_int64_t
vicar_strtonum(const char *nptr, int base)
{
	char		*ep;
	u_int64_t	ret;

	errno = 0;
	ret = strtoull(nptr, &ep, base);
	if (errno != 0 || *ep != '\0')
		fatal("%s feels like an odd base %d number", nptr, base);

	return (ret);
}

void
vicar_config_write(const char *path, struct config *cfg)
{
	int		fd, saved_errno;

	fd = nyfe_file_open(path, NYFE_FILE_CREATE);
	nyfe_file_write(fd, cfg, sizeof(*cfg));

	if (close(fd) == -1) {
		saved_errno = errno;
		(void)unlink(path);
		fatal("failed to write %s: %d", path, saved_errno);
	}
}

void
vicar_read_secret(const char *path, u_int8_t *secret, size_t len)
{
	int		fd;
	size_t		ret;

	if (len != 32)
		fatal("read: invalid length of %zu given", len);

	fd = nyfe_file_open(path, NYFE_FILE_READ);

	if ((ret = nyfe_file_read(fd, secret, len)) != len)
		fatal("failed to read secret (%zu/%zu)", ret, len);

	(void)close(fd);
}

void
vicar_wrap_config(struct config *cfg)
{
	const char		*pass;
	struct nyfe_agelas	cipher;
	u_int8_t		okm[VICAR_KEY_LEN], passphrase[256];

	sanctum_random_bytes(cfg->salt, sizeof(cfg->salt));

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	nyfe_zeroize_register(passphrase, sizeof(passphrase));

	nyfe_mem_zero(passphrase, sizeof(passphrase));

	if ((pass = getenv("VICAR_PASSPHRASE")) != NULL) {
		if (strlen(pass) >= sizeof(passphrase))
			fatal("VICAR_PASSPHRASE too long");
		memcpy(passphrase, pass, strlen(pass));
		printf("using VICAR_PASSPHRASE\n");
	} else {
		vicar_read_passphrase(passphrase, sizeof(passphrase));
	}

	nyfe_passphrase_kdf(passphrase, sizeof(passphrase),
	    cfg->salt, sizeof(cfg->salt), okm, sizeof(okm),
	    KDF_LABEL, sizeof(KDF_LABEL) - 1);
	nyfe_zeroize(passphrase, sizeof(passphrase));

	nyfe_agelas_init(&cipher, okm, sizeof(okm));
	nyfe_zeroize(okm, sizeof(okm));

	nyfe_agelas_aad(&cipher, cfg->salt, sizeof(cfg->salt));
	nyfe_agelas_encrypt(&cipher, &cfg->data, &cfg->data, sizeof(cfg->data));
	nyfe_agelas_authenticate(&cipher, cfg->tag, sizeof(cfg->tag));

	nyfe_zeroize(&cipher, sizeof(cipher));
}

void
vicar_read_passphrase(void *buf, size_t len)
{
	int			fd;
	size_t			off;
	u_int8_t		*ptr;
	struct termios		cur, old;

	if ((fd = open(_PATH_TTY, O_RDWR)) == -1)
		fatal("open(%s): %s", _PATH_TTY, strerror(errno));

	if (tcgetattr(fd, &old) == -1)
		fatal("tcgetattr: %s", strerror(errno));

	cur = old;
	cur.c_lflag &= ~(ECHO | ECHONL);

	if (tcsetattr(fd, TCSAFLUSH, &cur) == -1) {
		(void)tcsetattr(fd, TCSANOW, &old);
		fatal("tcsetattr: %s", strerror(errno));
	}

	fprintf(stderr, "passphrase: ");
	fflush(stderr);

	off = 0;
	ptr = buf;

	while (off != (len - 1)) {
		if (read(fd, &ptr[off], 1) == -1) {
			if (errno == EINTR)
				continue;
			fatal("%s: read failed: %s", __func__, strerror(errno));
		}

		if (ptr[off] == '\n')
			break;

		off++;
	}

	ptr[off] = '\0';

	if (tcsetattr(fd, TCSANOW, &old) == -1)
		fatal("tcsetattr: %s", strerror(errno));

	fprintf(stderr, "\n");

	(void)close(fd);
}
