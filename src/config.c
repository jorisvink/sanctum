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
#include <sys/socket.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__)
#include <bsd/stdlib.h>
#endif

#include "sanctum.h"

static void	config_parse_peer(char *);
static void	config_parse_local(char *);
static void	config_parse_runas(char *);
static void	config_parse_keying(char *);
static void	config_parse_status(char *);
static void	config_parse_instance(char *);
static void	config_parse_host(char *, struct sockaddr_in *);
static void	config_parse_unix(char *, struct sanctum_sun *);

static void	config_unix_set(struct sanctum_sun *,
		    const char *, const char *);
static char	*config_read_line(FILE *, char *, size_t);

static const struct {
	const char		*option;
	void			(*cb)(char *);
} keywords[] = {
	{ "peer",		config_parse_peer },
	{ "local",		config_parse_local },
	{ "run",		config_parse_runas },
	{ "keying",		config_parse_keying },
	{ "status",		config_parse_status },
	{ "instance",		config_parse_instance },
	{ NULL,			NULL },
};

static const struct {
	const char		*name;
	u_int16_t		type;
} proctab[] = {
	{ "clear",		SANCTUM_PROC_HAVEN },
	{ "crypto",		SANCTUM_PROC_PURGATORY },
	{ "keying",		SANCTUM_PROC_CHAPEL },
	{ "encrypt",		SANCTUM_PROC_BLESS },
	{ "decrypt",		SANCTUM_PROC_CONFESS },
	{ "status",		SANCTUM_PROC_STATUS },
	{ NULL,			0 },
};

void
sanctum_config_init(void)
{
	PRECOND(sanctum != NULL);

	config_unix_set(&sanctum->status, "/tmp/sanctum-status", "root");
	config_unix_set(&sanctum->keying, "/tmp/sanctum-keying", "root");
}

void
sanctum_config_load(const char *file)
{
	FILE		*fp;
	int		idx;
	char		buf[BUFSIZ], *option, *value;

	PRECOND(file != NULL);
	PRECOND(sanctum != NULL);

	if ((fp = fopen(file, "r")) == NULL)
		fatal("failed to open '%s': %s", file, errno_s);

	while ((option = config_read_line(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(option) == 0)
			continue;

		if ((value = strchr(option, ' ')) == NULL)
			fatal("malformed option '%s'", option);

		*(value)++ = '\0';

		for (idx = 0; keywords[idx].option != NULL; idx++) {
			if (!strcmp(keywords[idx].option, option)) {
				keywords[idx].cb(value);
				break;
			}
		}

		if (keywords[idx].option == NULL)
			fatal("unknown option '%s'", option);
	}

	if (ferror(fp))
		fatal("error reading the configuration file");

	fclose(fp);
}

static char *
config_read_line(FILE *fp, char *in, size_t len)
{
	char		*p, *t;

	PRECOND(fp != NULL);
	PRECOND(in != NULL);

	if (fgets(in, len, fp) == NULL)
		return (NULL);

	p = in;
	in[strcspn(in, "\n")] = '\0';

	while (isspace(*(unsigned char *)p))
		p++;

	if (p[0] == '#' || p[0] == '\0') {
		p[0] = '\0';
		return (p);
	}

	for (t = p; *t != '\0'; t++) {
		if (*t == '\t')
			*t = ' ';
	}

	return (p);
}

static void
config_parse_peer(char *peer)
{
	PRECOND(peer != NULL);

	config_parse_host(peer, &sanctum->peer);

	sanctum_atomic_write(&sanctum->peer_port, sanctum->peer.sin_port);
	sanctum_atomic_write(&sanctum->peer_ip, sanctum->peer.sin_addr.s_addr);
}

static void
config_parse_local(char *local)
{
	PRECOND(local != NULL);

	config_parse_host(local, &sanctum->local);
}

static void
config_parse_runas(char *runas)
{
	int		idx;
	u_int16_t	type;
	char		proc[16], user[32];

	PRECOND(runas != NULL);

	memset(proc, 0, sizeof(proc));
	memset(user, 0, sizeof(user));

	if (sscanf(runas, "%15s as %31s", proc, user) != 2)
		fatal("option 'run %s' invalid", runas);

	for (idx = 0; proctab[idx].name != NULL; idx++) {
		if (!strcmp(proctab[idx].name, proc))
			break;
	}

	if (proctab[idx].name == NULL)
		fatal("process '%s' is unknown", proc);

	type = proctab[idx].type;

	if (sanctum->runas[type] != NULL)
		fatal("process '%s' user already set", proc);

	if ((sanctum->runas[type] = strdup(user)) == NULL)
		fatal("strdup");
}

static void
config_parse_keying(char *path)
{
	PRECOND(path != NULL);

	config_parse_unix(path, &sanctum->keying);
}

static void
config_parse_status(char *path)
{
	PRECOND(path != NULL);

	config_parse_unix(path, &sanctum->status);
}

static void
config_parse_instance(char *opt)
{
	int		len;

	PRECOND(opt != NULL);

	len = snprintf(sanctum->instance, sizeof(sanctum->instance), "%s", opt);
	if (len == -1 || (size_t)len >= sizeof(sanctum->instance))
		fatal("instance name '%s' too long", opt);
}

static void
config_parse_unix(char *path, struct sanctum_sun *sun)
{
	char		*owner;

	PRECOND(path != NULL);
	PRECOND(sun != NULL);

	if ((owner = strrchr(path, ' ')) == NULL)
		fatal("option '%s' invalid", path);

	*(owner)++ = '\0';

	config_unix_set(sun, path, owner);
}

static void
config_unix_set(struct sanctum_sun *sun, const char *path, const char *owner)
{
	int		len;
	struct passwd	*pw;

	PRECOND(sun != NULL);
	PRECOND(path != NULL);
	PRECOND(owner != NULL);

	if ((pw = getpwnam(owner)) == NULL)
		fatal("user '%s' does not exist", owner);

	len = snprintf(sun->path, sizeof(sun->path), "%s", path);
	if (len == -1 || (size_t)len >= sizeof(sun->path))
		fatal("path '%s' too long", path);

	sun->uid = pw->pw_uid;
	sun->gid = pw->pw_gid;
}

static void
config_parse_host(char *host, struct sockaddr_in *sin)
{
	char		*port;
	const char	*errstr;

	PRECOND(host != NULL);
	PRECOND(sin != NULL);

	if ((port = strchr(host, ':')) == NULL)
		fatal("'%s': argument must be in format ip:port", host);
	*(port)++ = '\0';

	if (inet_pton(AF_INET, host, &sin->sin_addr.s_addr) == -1)
		fatal("ip '%s' invalid", host);

	sin->sin_port = strtonum(port, 1, USHRT_MAX, &errstr);
	if (errstr)
		fatal("port '%s' invalid: %s", port, errstr);

	sin->sin_port = htons(sin->sin_port);
}
