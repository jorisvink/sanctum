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
#include <unistd.h>

#include "sanctum.h"

struct route {
	struct sockaddr_in	net;
	struct sockaddr_in	mask;
	LIST_ENTRY(route)	list;
};

static void	config_parse_spi(char *);
static void	config_parse_mode(char *);
static void	config_parse_peer(char *);
static void	config_parse_local(char *);
static void	config_parse_route(char *);
static void	config_parse_runas(char *);
static void	config_parse_accept(char *);
static void	config_parse_tunnel(char *);
static void	config_parse_secret(char *);
static void	config_parse_control(char *);
static void	config_parse_instance(char *);
static void	config_parse_cathedral(char *);
static void	config_parse_secretdir(char *);
static void	config_parse_federation(char *);
static void	config_parse_cathedral_id(char *);
static void	config_parse_cathedral_secret(char *);
static void	config_parse_unix(char *, struct sanctum_sun *);

static void	config_parse_ip_port(char *, struct sockaddr_in *);
static void	config_parse_ip_mask(char *, struct sockaddr_in *,
		    struct sockaddr_in *);
static void	config_unix_set(struct sanctum_sun *,
		    const char *, const char *);

static const struct {
	const char		*option;
	void			(*cb)(char *);
} keywords[] = {
	{ "spi",		config_parse_spi },
	{ "mode",		config_parse_mode },
	{ "peer",		config_parse_peer },
	{ "local",		config_parse_local },
	{ "route",		config_parse_route },
	{ "run",		config_parse_runas },
	{ "accept",		config_parse_accept },
	{ "tunnel",		config_parse_tunnel },
	{ "secret",		config_parse_secret },
	{ "control",		config_parse_control },
	{ "instance",		config_parse_instance },
	{ "cathedral",		config_parse_cathedral },
	{ "secretdir",		config_parse_secretdir },
	{ "federation",		config_parse_federation },
	{ "cathedral_id",	config_parse_cathedral_id },
	{ "cathedral_secret",	config_parse_cathedral_secret },
	{ NULL,			NULL },
};

static const struct {
	const char		*name;
	u_int16_t		type;
} proctab[] = {
	{ "heaven",		SANCTUM_PROC_HEAVEN },
	{ "purgatory",		SANCTUM_PROC_PURGATORY },
	{ "chapel",		SANCTUM_PROC_CHAPEL },
	{ "bless",		SANCTUM_PROC_BLESS },
	{ "confess",		SANCTUM_PROC_CONFESS },
	{ "control",		SANCTUM_PROC_CONTROL },
	{ "pilgrim",		SANCTUM_PROC_PILGRIM },
	{ "shrine",		SANCTUM_PROC_SHRINE },
	{ "cathedral",		SANCTUM_PROC_CATHEDRAL },
	{ NULL,			0 },
};

/* List of routes and routable networks. */
static LIST_HEAD(, route)	routes;
static LIST_HEAD(, route)	routable;

/* The peer can only be set once, either via peer or cathedral. */
static int	peer_set = 0;

/*
 * Setup the default configuration options.
 */
void
sanctum_config_init(void)
{
	PRECOND(sanctum != NULL);

	LIST_INIT(&routes);
	LIST_INIT(&routable);

	config_unix_set(&sanctum->control, "/tmp/sanctum-control", "root");
}

/*
 * Load a configuration parsing it line by line.
 */
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

	while ((option = sanctum_config_read(fp, buf, sizeof(buf))) != NULL) {
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

	if (peer_set > 1)
		fatal("peer and cathedral are mutually exclusive options");

	if (sanctum->secret == NULL)
		fatal("no traffic secret has been set");

	switch (sanctum->mode) {
	case SANCTUM_MODE_CATHEDRAL:
		if (sanctum->secretdir == NULL)
			fatal("cathedral: no secretdir configured");
		break;
	default:
		if (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE) {
			if (sanctum->cathedral_secret == NULL)
				fatal("cathedral given but no secret set");
			if (sanctum->cathedral_id == 0)
				fatal("cathedral given but no id set");
		}
		break;
	}

	if (sanctum->peer_ip == 0)
		sanctum->flags |= SANCTUM_FLAG_PEER_AUTO;

	if (sanctum->instance[0] == '\0')
		fatal("no instance name was specified in the configuation");
}

/*
 * Route all routes from the configuration into the tunnel device.
 */
void
sanctum_config_routes(void)
{
	struct route	*rt;

	while ((rt = LIST_FIRST(&routes)) != NULL) {
		LIST_REMOVE(rt, list);
		sanctum_platform_tundev_route(&rt->net, &rt->mask);
		free(rt);
	}
}

/*
 * Check if an ip was routable based on our configuration.
 */
int
sanctum_config_routable(in_addr_t ip)
{
	struct route	*rt;

	LIST_FOREACH(rt, &routable, list) {
		if ((ip & rt->mask.sin_addr.s_addr) == rt->net.sin_addr.s_addr)
			return (0);
	}

	return (-1);
}

/*
 * Read a single line from the given FILE, stripping away comments
 * and trimming whitespace.
 */
char *
sanctum_config_read(FILE *fp, char *in, size_t len)
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

/*
 * Parse the spi configuration option.
 */
static void
config_parse_spi(char *opt)
{
	u_int16_t	spi;

	PRECOND(opt != NULL);

	if (sscanf(opt, "0x%hx", &spi) != 1)
		fatal("spi <0xffff>");

	sanctum->tun_spi = spi;
}

/*
 * Parse the mode configuration option.
 */
static void
config_parse_mode(char *mode)
{
	PRECOND(mode != NULL);

	if (!strcmp(mode, "tunnel") || !strcmp(mode, "default")) {
		sanctum->mode = SANCTUM_MODE_TUNNEL;
	} else if (!strcmp(mode, "pilgrim")) {
		sanctum->mode = SANCTUM_MODE_PILGRIM;
	} else if (!strcmp(mode, "shrine")) {
		sanctum->mode = SANCTUM_MODE_SHRINE;
	} else if (!strcmp(mode, "cathedral")) {
		sanctum->mode = SANCTUM_MODE_CATHEDRAL;
	} else {
		fatal("unknown mode '%s'", mode);
	}
}

/*
 * Parse the peer configuration option.
 * Note that peer is mutually exclusive with the cathedral option.
 */
static void
config_parse_peer(char *peer)
{
	PRECOND(peer != NULL);

	if (!strcmp(peer, "auto")) {
		sanctum->flags |= SANCTUM_FLAG_PEER_AUTO;
		return;
	}

	peer_set++;

	config_parse_ip_port(peer, &sanctum->peer);
	sanctum_atomic_write(&sanctum->peer_port, sanctum->peer.sin_port);
	sanctum_atomic_write(&sanctum->peer_ip, sanctum->peer.sin_addr.s_addr);
}

/*
 * Parse the local configuration option.
 */
static void
config_parse_local(char *local)
{
	PRECOND(local != NULL);

	config_parse_ip_port(local, &sanctum->local);
}

/*
 * Parse a runas configuration option.
 */
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

/*
 * Parse the tunnel configuration option.
 */
static void
config_parse_tunnel(char *opt)
{
	u_int16_t	mtu;
	char		ip[INET_ADDRSTRLEN + 3];

	PRECOND(opt != NULL);

	if (sscanf(opt, "%18s %hu", ip, &mtu) != 2)
		fatal("tunnel <ip/mask> <mtu>");

	if (mtu > 1500 || mtu < 576)
		fatal("mtu (%u) invalid", mtu);

	sanctum->tun_mtu = mtu;

	config_parse_ip_mask(ip, &sanctum->tun_ip, &sanctum->tun_mask);
}

/*
 * Parse a route configuration option.
 */
static void
config_parse_route(char *opt)
{
	struct route		*rt;

	PRECOND(opt != NULL);

	if ((rt = calloc(1, sizeof(*rt))) == NULL)
		fatal("calloc");

	config_parse_ip_mask(opt, &rt->net, &rt->mask);

	LIST_INSERT_HEAD(&routes, rt, list);
}

/*
 * Parse an accept configuration option.
 */
static void
config_parse_accept(char *opt)
{
	struct route		*rt;

	PRECOND(opt != NULL);

	if ((rt = calloc(1, sizeof(*rt))) == NULL)
		fatal("calloc");

	config_parse_ip_mask(opt, &rt->net, &rt->mask);

	rt->net.sin_addr.s_addr &= rt->mask.sin_addr.s_addr;

	LIST_INSERT_HEAD(&routable, rt, list);
}

/*
 * Parse the control configuration option.
 */
static void
config_parse_control(char *path)
{
	PRECOND(path != NULL);

	config_parse_unix(path, &sanctum->control);
}

/*
 * Parse the secret configuration option.
 */
static void
config_parse_secret(char *path)
{
	if (sanctum->secret != NULL)
		fatal("secret already specified");

	if (access(path, R_OK) == -1)
		fatal("secret at path '%s' not readable", path);

	if ((sanctum->secret = strdup(path)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the instance configuration option.
 */
static void
config_parse_instance(char *opt)
{
	int		len;
	size_t		optlen, idx;

	PRECOND(opt != NULL);

	optlen = strlen(opt);
	for (idx = 0; idx < optlen; idx++) {
		if (!isalnum((unsigned char)opt[idx]) && opt[idx] != '-')
			fatal("instance name is alnum and '-'");
	}

	len = snprintf(sanctum->instance, sizeof(sanctum->instance), "%s", opt);
	if (len == -1 || (size_t)len >= sizeof(sanctum->instance))
		fatal("instance name '%s' too long", opt);
}

/*
 * Parse the cathedral configuration option.
 */
static void
config_parse_cathedral(char *cathedral)
{
	PRECOND(cathedral != NULL);

	if (sanctum->tun_spi == 0)
		fatal("no spi prefix has been configured");

	peer_set++;
	sanctum->flags |= SANCTUM_FLAG_CATHEDRAL_ACTIVE;

	config_parse_ip_port(cathedral, &sanctum->peer);
	sanctum_atomic_write(&sanctum->peer_port, sanctum->peer.sin_port);
	sanctum_atomic_write(&sanctum->peer_ip, sanctum->peer.sin_addr.s_addr);
}

/*
 * Parse the cathedral_id configuration option.
 */
static void
config_parse_cathedral_id(char *opt)
{
	PRECOND(opt != NULL);

	if (sanctum->tun_spi == 0)
		fatal("no spi prefix has been configured");

	if (sscanf(opt, "0x%08x", &sanctum->cathedral_id) != 1)
		fatal("cathedral_id <0xff>");
}

/*
 * Parse the cathedral_secret configuration option.
 */
static void
config_parse_cathedral_secret(char *secret)
{
	PRECOND(secret != NULL);

	if (sanctum->tun_spi == 0)
		fatal("no spi prefix has been configured");

	if (access(secret, R_OK) == -1)
		fatal("cathedral secret at path '%s' not readable", secret);

	if ((sanctum->cathedral_secret = strdup(secret)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the secretdir configuration option.
 */
static void
config_parse_secretdir(char *opt)
{
	PRECOND(opt != NULL);

	if (sanctum->mode != SANCTUM_MODE_CATHEDRAL)
		fatal("secretdir is only for cathedral mode");

	if (sanctum->secretdir != NULL)
		fatal("secretdir already specified");

	if (access(opt, R_OK | X_OK) == -1)
		fatal("secretdir '%s' not readable", opt);

	if ((sanctum->secretdir = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the federation configuration option.
 */
static void
config_parse_federation(char *opt)
{
	PRECOND(opt != NULL);

	if (sanctum->mode != SANCTUM_MODE_CATHEDRAL)
		fatal("federation is only for cathedral mode");

	if (sanctum->federation != NULL)
		fatal("federation already specified");

	if (access(opt, R_OK) == -1)
		fatal("federation '%s' not readable", opt);

	if ((sanctum->federation = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Helper function to convert a path into a sockaddr_un.
 */
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

/*
 * Helper initialize a sockaddr_un with the given path and owner.
 */
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

/*
 * Helper function to convert the given ipv4 host in the format of ip:port
 * into a sockaddr_in.
 */
static void
config_parse_ip_port(char *host, struct sockaddr_in *sin)
{
	unsigned long long	value;
	char			*port, *ep;

	PRECOND(host != NULL);
	PRECOND(sin != NULL);

	if ((port = strchr(host, ':')) == NULL)
		fatal("'%s': argument must be in format ip:port", host);

	*(port)++ = '\0';

	sanctum_inet_addr(sin, host);

	errno = 0;
	value = strtoull(port, &ep, 10);
	if (errno != 0 || *ep != '\0')
		fatal("port '%s' invalid", port);

	sin->sin_port = htons(value);
}

/*
 * Helper function to convert the given ipv4 host and mask into a sockaddr_in.
 */
static void
config_parse_ip_mask(char *in, struct sockaddr_in *ip, struct sockaddr_in *mask)
{
	u_int8_t	val;
	char		*ep, *p;

	PRECOND(in != NULL);
	PRECOND(ip != NULL);
	PRECOND(mask != NULL);

	if ((p = strchr(in, '/')) == NULL)
		fatal("ip '%s' is missing a netmask", in);

	*(p)++ = '\0';
	if (*p == '\0')
		fatal("ip '%s' is missing a netmask", in);

	errno = 0;
	val = strtol(p, &ep, 10);
	if (errno != 0 || p == ep || *ep != '\0')
		fatal("netmask '%s' is invalid", p);

	if (val > 32)
		fatal("netmask '%s' is invalid", p);

	sanctum_inet_addr(ip, in);
	sanctum_inet_mask(mask, val);
}
