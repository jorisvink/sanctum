/*
 * Copyright (c) 2023-2025 Joris Vink <joris@sanctorum.se>
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
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <ctype.h>
#include <limits.h>
#include <inttypes.h>
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

static void	config_parse_kek(char *);
static void	config_parse_spi(char *);
static void	config_parse_tap(char *);
static void	config_parse_tfc(char *);
static void	config_parse_mode(char *);
static void	config_parse_peer(char *);
static void	config_parse_local(char *);
static void	config_parse_route(char *);
static void	config_parse_descr(char *);
static void	config_parse_runas(char *);
static void	config_parse_accept(char *);
static void	config_parse_tunnel(char *);
static void	config_parse_secret(char *);
static void	config_parse_control(char *);
static void	config_parse_pidfile(char *);
static void	config_parse_instance(char *);
static void	config_parse_secretdir(char *);
static void	config_parse_cathedral(char *);
static void	config_parse_settings(char *);
static void	config_parse_encapsulation(char *);
static void	config_parse_liturgy_group(char *);
static void	config_parse_liturgy_prefix(char *);
static void	config_parse_cathedral_id(char *);
static void	config_parse_cathedral_flock(char *);
static void	config_parse_cathedral_secret(char *);
static void	config_parse_cathedral_nat_port(char *);
static void	config_parse_cathedral_p2p_sync(char *);
static void	config_parse_cathedral_flock_dst(char *);
static void	config_parse_liturgy_discoverable(char *);
static void	config_parse_cathedral_remembrance(char *);
static void	config_parse_unix(char *, struct sanctum_sun *);

static void	config_parse_ip_port(char *, struct sockaddr_in *);
static void	config_parse_ip_mask(char *, struct sockaddr_in *,
		    struct sockaddr_in *);

static void	config_mtu_check(void);
static void	config_cathedral_check(void);
static void	config_unix_set(struct sanctum_sun *,
		    const char *, const char *);

static const struct {
	const char		*option;
	void			(*cb)(char *);
} keywords[] = {
	{ "kek",			config_parse_kek },
	{ "spi",			config_parse_spi },
	{ "tap",			config_parse_tap },
	{ "tfc",			config_parse_tfc },
	{ "mode",			config_parse_mode },
	{ "peer",			config_parse_peer },
	{ "local",			config_parse_local },
	{ "route",			config_parse_route },
	{ "run",			config_parse_runas },
	{ "descr",			config_parse_descr },
	{ "accept",			config_parse_accept },
	{ "tunnel",			config_parse_tunnel },
	{ "secret",			config_parse_secret },
	{ "control",			config_parse_control },
	{ "pidfile",			config_parse_pidfile },
	{ "instance",			config_parse_instance },
	{ "cathedral",			config_parse_cathedral },
	{ "secretdir",			config_parse_secretdir },
	{ "settings",			config_parse_settings },
	{ "encapsulation",		config_parse_encapsulation },
	{ "liturgy_group",		config_parse_liturgy_group },
	{ "liturgy_prefix",		config_parse_liturgy_prefix },
	{ "liturgy_discoverable",	config_parse_liturgy_discoverable },
	{ "cathedral_id",		config_parse_cathedral_id },
	{ "cathedral_flock",		config_parse_cathedral_flock },
	{ "cathedral_secret",		config_parse_cathedral_secret },
	{ "cathedral_nat_port",		config_parse_cathedral_nat_port },
	{ "cathedral_p2p_sync",		config_parse_cathedral_p2p_sync },
	{ "cathedral_flock_dst",	config_parse_cathedral_flock_dst },
	{ "cathedral_remembrance",	config_parse_cathedral_remembrance },
	{ NULL,			NULL },
};

static const struct {
	const char		*name;
	u_int16_t		type;
} proctab[] = {
	{ "heaven-rx",		SANCTUM_PROC_HEAVEN_RX },
	{ "heaven-tx",		SANCTUM_PROC_HEAVEN_TX },
	{ "purgatory-rx",	SANCTUM_PROC_PURGATORY_RX },
	{ "purgatory-tx",	SANCTUM_PROC_PURGATORY_TX },
	{ "chapel",		SANCTUM_PROC_CHAPEL },
	{ "bless",		SANCTUM_PROC_BLESS },
	{ "confess",		SANCTUM_PROC_CONFESS },
	{ "control",		SANCTUM_PROC_CONTROL },
	{ "pilgrim",		SANCTUM_PROC_PILGRIM },
	{ "shrine",		SANCTUM_PROC_SHRINE },
	{ "cathedral",		SANCTUM_PROC_CATHEDRAL },
	{ "liturgy",		SANCTUM_PROC_LITURGY },
	{ "bishop",		SANCTUM_PROC_BISHOP },
	{ NULL,			0 },
};

/* List of routes and routable networks. */
static LIST_HEAD(, route)	routes;
static LIST_HEAD(, route)	routable;

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
	size_t		len;
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

		while (isspace((unsigned char)*value))
			value++;

		if ((len = strlen(value)) == 0)
			fatal("no value given for '%s'", option);

		for (idx = len - 1; idx >= 0; idx--) {
			if (!isspace((unsigned char)value[idx]))
				break;
			value[idx] = '\0';
		}

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

	if (sanctum->instance[0] == '\0')
		fatal("no instance name has been set");

	if (sanctum->mode != SANCTUM_MODE_LITURGY && sanctum->secret == NULL)
		fatal("no traffic secret has been set");

	switch (sanctum->mode) {
	case SANCTUM_MODE_CATHEDRAL:
		if (sanctum->flags & SANCTUM_FLAG_USE_TAP)
			fatal("cathedral: cannot use tap");
		if (sanctum->secretdir == NULL)
			fatal("cathedral: no secretdir configured");
		break;
	case SANCTUM_MODE_LITURGY:
		config_cathedral_check();
		if (sanctum->liturgy_prefix.sin_addr.s_addr == 0)
			fatal("no liturgy_prefix has been set");
		break;
	case SANCTUM_MODE_TUNNEL:
		if (sanctum->kek != NULL &&
		    !(sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE))
			fatal("kek configured but no cathedral set");
		if (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE)
			config_cathedral_check();
		config_mtu_check();
		break;
	case SANCTUM_MODE_SHRINE:
	case SANCTUM_MODE_PILGRIM:
		config_mtu_check();
		break;
	default:
		break;
	}

	if ((sanctum->flags & SANCTUM_FLAG_TFC_ENABLED) &&
	    (sanctum->flags & SANCTUM_FLAG_ENCAPSULATE) &&
	    sanctum->tun_mtu == 0)
		fatal("tfc/encap is enabled but no mtu has been set");

	if (sanctum->mode != SANCTUM_MODE_CATHEDRAL &&
	    sanctum->mode != SANCTUM_MODE_LITURGY &&
	    !(sanctum->flags & SANCTUM_FLAG_USE_TAP)) {
		if (sanctum->tun_ip.sin_addr.s_addr == 0)
			fatal("no tunnel configuration specified");
	}

	if (sanctum->mode != SANCTUM_MODE_TUNNEL &&
	    sanctum->mode != SANCTUM_MODE_LITURGY) {
		if (sanctum->kek != NULL)
			fatal("kek is only used in tunnel mode");
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
 * Parse the kek configuration option.
 */
static void
config_parse_kek(char *path)
{
	PRECOND(path != NULL);

	if (sanctum->kek != NULL)
		fatal("kek already specified");

	if (access(path, R_OK) == -1)
		fatal("kek at path '%s' not readable (%s)", path, errno_s);

	if ((sanctum->kek = strdup(path)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the spi configuration option.
 */
static void
config_parse_spi(char *opt)
{
	PRECOND(opt != NULL);

	if (sscanf(opt, "%hx", &sanctum->tun_spi) != 1)
		fatal("spi <16-bit hex value>");
}

/*
 * Parse the tap configuration option.
 */
static void
config_parse_tap(char *opt)
{
	PRECOND(opt != NULL);

	if (!strcmp(opt, "yes")) {
		sanctum->flags |= SANCTUM_FLAG_USE_TAP;
	} else if (strcmp(opt, "no")) {
		fatal("unknown tap option '%s'", opt);
	}
}

/*
 * Parse the tfc configuration option.
 */
static void
config_parse_tfc(char *opt)
{
	PRECOND(opt != NULL);

	if (!strcmp(opt, "on")) {
		sanctum->flags |= SANCTUM_FLAG_TFC_ENABLED;
	} else if (strcmp(opt, "off")) {
		fatal("unknown tfc option '%s'", opt);
	}
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
	} else if (!strcmp(mode, "liturgy")) {
		sanctum->mode = SANCTUM_MODE_LITURGY;
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
	struct sockaddr_in	addr;

	PRECOND(peer != NULL);

	if (!strcmp(peer, "auto")) {
		sanctum->flags |= SANCTUM_FLAG_PEER_AUTO;
		return;
	}

	config_parse_ip_port(peer, &addr);
	sanctum_atomic_write(&sanctum->peer_port, addr.sin_port);
	sanctum_atomic_write(&sanctum->peer_ip, addr.sin_addr.s_addr);

	sanctum->flags |= SANCTUM_FLAG_PEER_CONFIGURED;
}

/*
 * Parse the local configuration option.
 */
static void
config_parse_local(char *local)
{
	PRECOND(local != NULL);

	config_parse_ip_port(local, &sanctum->local);

	if (sanctum->mode == SANCTUM_MODE_CATHEDRAL &&
	    sanctum->local.sin_addr.s_addr == 0)
		fatal("cathedrals require a non-null ipv4 address in local");
}

/*
 * Parse the description configuration option.
 */
static void
config_parse_descr(char *opt)
{
	int		len;
	size_t		optlen, idx;

	PRECOND(opt != NULL);

	optlen = strlen(opt);
	for (idx = 0; idx < optlen; idx++) {
		if (!isalnum((unsigned char)opt[idx]) && opt[idx] != '-')
			fatal("description is alnum and '-'");
	}

	len = snprintf(sanctum->descr, sizeof(sanctum->descr), "%s", opt);
	if (len == -1 || (size_t)len >= sizeof(sanctum->descr))
		fatal("description '%s' too long", opt);
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

	if (mtu > SANCTUM_PACKET_DATA_LEN || mtu < 576)
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
 * Parse the pidfile configuration option.
 */
static void
config_parse_pidfile(char *path)
{
	PRECOND(path != NULL);

	if (sanctum->pidfile != NULL)
		fatal("pidfile already specified");

	if ((sanctum->pidfile = strdup(path)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the secret configuration option.
 */
static void
config_parse_secret(char *path)
{
	PRECOND(path != NULL);

	if (sanctum->secret != NULL)
		fatal("secret already specified");

	if (sanctum->kek == NULL) {
		if (access(path, R_OK) == -1) {
			fatal("secret at path '%s' not readable (%s)",
			    path, errno_s);
		}
	}

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

	sanctum->flags |= SANCTUM_FLAG_CATHEDRAL_ACTIVE;
	config_parse_ip_port(cathedral, &sanctum->cathedral);
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

	if (sscanf(opt, "%x", &sanctum->cathedral_id) != 1)
		fatal("cathedral_id <32-bit hex value>");
}

/*
 * Parse the cathedral_remembrance configuration option.
 */
static void
config_parse_cathedral_remembrance(char *opt)
{
	PRECOND(opt != NULL);

	if (sanctum->cathedral_remembrance != NULL)
		fatal("cathedral_remembrance already specified");

	if ((sanctum->cathedral_remembrance = strdup(opt)) == NULL)
		fatal("strdup");
}

/*
 * Parse the cathedral_nat_port configuration option.
 */
static void
config_parse_cathedral_nat_port(char *opt)
{
	PRECOND(opt != NULL);

	if (sscanf(opt, "%hu", &sanctum->cathedral_nat_port) != 1)
		fatal("spi <16-bit hex value>");
}

/*
 * Parse the cathedral_p2p_sync configuration option.
 */
static void
config_parse_cathedral_p2p_sync(char *opt)
{
	PRECOND(opt != NULL);

	if (!strcmp(opt, "yes")) {
		sanctum->flags |= SANCTUM_FLAG_CATHEDRAL_P2P_SYNC;
	} else if (!strcmp(opt, "no")) {
		sanctum->flags &= ~SANCTUM_FLAG_CATHEDRAL_P2P_SYNC;
	} else {
		fatal("invalid value '%s' for cathedral_p2p_sync", opt);
	}
}

/*
 * Parse the cathedral_flock configuration option.
 */
static void
config_parse_cathedral_flock(char *opt)
{
	PRECOND(opt != NULL);

	if (sscanf(opt, "%" PRIx64, &sanctum->cathedral_flock) != 1)
		fatal("cathedral_flock <64-bit hex value>");
}

/*
 * Parse the cathedral_flock configuration option.
 */
static void
config_parse_cathedral_flock_dst(char *opt)
{
	PRECOND(opt != NULL);

	if (sscanf(opt, "%" PRIx64, &sanctum->cathedral_flock_dst) != 1)
		fatal("cathedral_flock_dst <64-bit hex value>");
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

	if (access(secret, R_OK) == -1) {
		fatal("cathedral secret at path '%s' not readable (%s)",
		    secret, errno_s);
	}

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
		fatal("secretdir '%s' not readable (%s)", opt, errno_s);

	if ((sanctum->secretdir = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the settings option.
 */
static void
config_parse_settings(char *opt)
{
	PRECOND(opt != NULL);

	if (sanctum->mode != SANCTUM_MODE_CATHEDRAL)
		fatal("settings is only for cathedral mode");

	if (sanctum->settings != NULL)
		fatal("setttings already specified");

	if (access(opt, R_OK) == -1)
		fatal("file '%s' not readable (%s)", opt, errno_s);

	if ((sanctum->settings = strdup(opt)) == NULL)
		fatal("strdup failed");
}

/*
 * Parse the encapsulation option.
 */
static void
config_parse_encapsulation(char *opt)
{
	size_t		idx, i;
	char		hex[5], *ep;

	PRECOND(opt != NULL);

	if (strlen(opt) != SANCTUM_ENCAP_HEX_LEN) {
		fatal("encapsulation key must be a %d-bit hex value",
		    SANCTUM_KEY_LENGTH * 8);
	}

	hex[0] = '0';
	hex[1] = 'x';
	hex[4] = '\0';

	i = 0;

	for (idx = 0; idx < SANCTUM_ENCAP_HEX_LEN; idx += 2) {
		hex[2] = opt[idx];
		hex[3] = opt[idx + 1];

		errno = 0;
		sanctum->tek[i++] = strtoul(hex, &ep, 16);
		if (errno != 0 || *ep != '\0')
			fatal("hex byte '%s' invalid", hex);
	}

	sanctum->flags |= SANCTUM_FLAG_ENCAPSULATE;
}

/*
 * Parse the liturgy_discoverable option.
 */
static void
config_parse_liturgy_discoverable(char *opt)
{
	PRECOND(opt != NULL);

	if (!strcmp(opt, "yes")) {
		sanctum->flags &= ~SANCTUM_FLAG_LITURGY_HIDE;
	} else if (!strcmp(opt, "no")) {
		sanctum->flags |= SANCTUM_FLAG_LITURGY_HIDE;
	} else {
		fatal("liturgy_discoverable '%s' is invalid (yes|no)", opt);
	}
}

/*
 * Parse the liturgy_group option.
 */
static void
config_parse_liturgy_group(char *group)
{
	PRECOND(group != NULL);

	if (sscanf(group, "%hx", &sanctum->liturgy_group) != 1)
		fatal("liturgy_group <16-bit hex value>");
}

/*
 * Parse the liturgy_prefix option.
 */
static void
config_parse_liturgy_prefix(char *net)
{
	PRECOND(net != NULL);

	sanctum_inet_addr(&sanctum->liturgy_prefix, net);

	if (sanctum->liturgy_prefix.sin_addr.s_addr & 0xffff0000)
		fatal("liturgy_prefix should be x.x.0.0");
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

/*
 * Check that the configured tunnel MTU makes sense in correlation
 * to the overhead required by the crypto side.
 */
static void
config_mtu_check(void)
{
	size_t		overhead;

	PRECOND(sanctum->mode == SANCTUM_MODE_TUNNEL ||
	    sanctum->mode == SANCTUM_MODE_SHRINE ||
	    sanctum->mode == SANCTUM_MODE_PILGRIM);

	overhead = sizeof(struct ip) + sizeof(struct udphdr) +
	    sizeof(struct sanctum_proto_hdr) +
	    sizeof(struct sanctum_proto_tail) + SANCTUM_TAG_LENGTH;

	if (sanctum->flags & SANCTUM_FLAG_ENCAPSULATE)
		overhead += sizeof(struct sanctum_encap_hdr);

	VERIFY(SANCTUM_PACKET_DATA_LEN > overhead);

	if (sanctum->tun_mtu > SANCTUM_PACKET_DATA_LEN - overhead) {
		fatal("mtu misconfigured, %d cannot be set (%zu max)",
		    sanctum->tun_mtu, SANCTUM_PACKET_DATA_LEN - overhead);
	}
}

/*
 * Check that the configuration is as expected when wanting to
 * use a cathedral as there are some requirements on what should
 * be configured.
 */
static void
config_cathedral_check(void)
{
	if (sanctum->cathedral_secret == NULL)
		fatal("cathedral given but no secret set");

	if (sanctum->cathedral_id == 0)
		fatal("cathedral given but no id set");

	if (sanctum->cathedral_flock == 0)
		fatal("cathedral given but no flock set");

	if (sanctum->cathedral_flock_dst == 0)
		sanctum->cathedral_flock_dst = sanctum->cathedral_flock;

	if (sanctum->mode == SANCTUM_MODE_TUNNEL) {
		if (sanctum->peer_ip == 0) {
			sanctum_atomic_write(&sanctum->peer_port,
			    sanctum->cathedral.sin_port);
			sanctum_atomic_write(&sanctum->peer_ip,
			    sanctum->cathedral.sin_addr.s_addr);
		}
	}
}
