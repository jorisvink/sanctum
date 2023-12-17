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

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnyfe.h"

void		fatal(const char *, ...);

static void	usage(void) __attribute__((noreturn));
static void	usage_keygen(void) __attribute__((noreturn));

static int	hymn_keygen(int, char **);

static const struct {
	const char	*name;
	int		(*cb)(int, char **);
} cmds[] = {
	{ "keygen",		hymn_keygen },
	{ NULL,			NULL },
};

static void
usage(void)
{
	fprintf(stderr, "usage: hymn [cmd]\n");
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "  keygen   - generate keys for sanctum\n");

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

	fprintf(stderr, "error: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

static void
usage_keygen(void)
{
	fprintf(stderr, "usage: hymn keygen [key1] [key2] [keyN] ...\n");
	exit(1);
}

static int
hymn_keygen(int argc, char *argv[])
{
	u_int8_t	key[32];
	int		idx, fd;

	if (argc == 0)
		usage_keygen();

	nyfe_random_init();
	nyfe_zeroize_register(key, sizeof(key));

	for (idx = 0; idx < argc; idx++) {
		printf("generating key in %s\n", argv[idx]);

		fd = nyfe_file_open(argv[idx], NYFE_FILE_CREATE);

		nyfe_random_bytes(key, sizeof(key));
		nyfe_file_write(fd, key, sizeof(key));
		nyfe_file_close(fd);
	}

	nyfe_zeroize(key, sizeof(key));

	return (0);
}
