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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnyfe.h"

#define errno_s			strerror(errno)

#define HYMN_BASE_PATH		"/etc/hymn"
#define HYMN_RUN_PATH		"/var/run/hymn"

struct addr {
	in_addr_t		ip;
	in_addr_t		mask;
	LIST_ENTRY(addr)	list;
};

struct config {
	u_int8_t		src;
	u_int8_t		dst;

	struct addr		tun;
	u_int16_t		tun_mtu;

	in_addr_t		peer_ip;
	u_int16_t		peer_port;

	u_int32_t		cathedral_id;
	int			peer_cathedral;

	LIST_HEAD(, addr)	routes;
};

void		fatal(const char *, ...) __attribute__((noreturn));

static void	usage(void) __attribute__((noreturn));
static void	usage_add(void) __attribute__((noreturn));
static void	usage_del(void) __attribute__((noreturn));
static void	usage_route(void) __attribute__((noreturn));
static void	usage_keygen(void) __attribute__((noreturn));
static void	usage_up_down(void) __attribute__((noreturn));

static void	hymn_mkdir(const char *, int);
static void	hymn_unlink(const char *, ...)
		    __attribute__((format (printf, 1, 2)));

static void	hymn_pid_path(char *, size_t, u_int8_t, u_int8_t);
static void	hymn_key_path(char *, size_t, u_int8_t, u_int8_t);
static void	hymn_conf_path(char *, size_t, u_int8_t, u_int8_t);

static int	hymn_up(int, char **);
static int	hymn_add(int, char **);
static int	hymn_del(int, char **);
static int	hymn_down(int, char **);
static int	hymn_route(int, char **);
static int	hymn_keygen(int, char **);

static void	hymn_config_init(struct config *);
static void	hymn_config_write(int, const char *, ...)
		    __attribute__((format (printf, 2, 3)));
static char	*hymn_config_read(FILE *, char *, size_t);
static void	hymn_config_save(const char *, struct config *);
static void	hymn_config_load(const char *, struct config *);

static void	hymn_config_set_mtu(struct config *, const char *);
static void	hymn_config_set_peer(struct config *, const char *);
static void	hymn_config_set_cathedral(struct config *, const char *);

static void	hymn_config_parse_peer(struct config *, char *);
static void	hymn_config_parse_route(struct config *, char *);
static void	hymn_config_parse_tunnel(struct config *, char *);
static void	hymn_config_parse_cathedral(struct config *, char *);
static void	hymn_config_parse_cathedral_id(struct config *, char *);

static struct addr	*hymn_route_parse(const char *);
static const char	*hymn_ip_mask_str(struct addr *);
static unsigned long	hymn_number(const char *, int, unsigned long,
			    unsigned long);
static void		hymn_ip_mask_parse(struct addr *, const char *);

static const struct {
	const char	*name;
	int		(*cb)(int, char **);
} cmds[] = {
	{ "up",			hymn_up },
	{ "add",		hymn_add },
	{ "del",		hymn_del },
	{ "down",		hymn_down },
	{ "route",		hymn_route },
	{ "keygen",		hymn_keygen },
	{ NULL,			NULL },
};

static const struct {
	const char		*option;
	void			(*cb)(struct config *, char *);
} keywords[] = {
	{ "peer",		hymn_config_parse_peer },
	{ "route",		hymn_config_parse_route },
	{ "tunnel",		hymn_config_parse_tunnel },
	{ "cathedral",		hymn_config_parse_cathedral },
	{ "cathedral_id",	hymn_config_parse_cathedral_id },
	{ NULL,			NULL },
};

static void
usage(void)
{
	fprintf(stderr, "usage: hymn [cmd]\n");
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "  add      - add a new tunnel\n");
	fprintf(stderr, "  del      - delete an existing tunnel\n");
	fprintf(stderr, "  route    - modify tunnel routing rules\n");

	exit(1);
}

int
main(int argc, char *argv[])
{
	int		idx, ret;

	if (getuid() != 0)
		fatal("Only root may change hymn configurations");

	if (argc < 2)
		usage();

	umask(0077);
	hymn_mkdir(HYMN_RUN_PATH, 1);
	hymn_mkdir(HYMN_BASE_PATH, 1);

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

	fprintf(stderr, "hymn: ");

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

static void
usage_add(void)
{
	fprintf(stderr,
	    "usage: hymn add <src>-<dst> tunnel <ip/mask> mtu <mtu> \\\n");
	fprintf(stderr, "    [peer | cathedral] <ip:port>\n");
	exit(1);
}

static int
hymn_add(int argc, char *argv[])
{
	int			i;
	struct config		config;
	char			confpath[PATH_MAX], keypath[PATH_MAX];

	if (argc != 7 && argc != 9)
		usage_add();

	hymn_config_init(&config);

	if (sscanf(argv[0], "%02hhx-%02hhx", &config.src, &config.dst) != 2)
		usage_add();

	hymn_key_path(keypath, sizeof(keypath), config.src, config.dst);
	hymn_conf_path(confpath, sizeof(confpath), config.src, config.dst);

	if (access(confpath, R_OK) != -1)
		fatal("tunnel %02x-%02x config exists", config.src, config.dst);

	if (access(keypath, R_OK) != -1)
		fatal("tunnel %02x-%02x key exists", config.src, config.dst);

	argc--;
	argv++;

	if (argc & 0x01)
		usage_add();

	/* XXX set flags in config to indicate whats present. */
	for (i = 0; i < argc; i += 2) {
		if (!strcmp(argv[i], "tunnel")) {
			hymn_ip_mask_parse(&config.tun, argv[i + 1]);
		} else if (!strcmp(argv[i], "mtu")) {
			hymn_config_set_mtu(&config, argv[i + 1]);
		} else if (!strcmp(argv[i], "peer")) {
			hymn_config_set_peer(&config, argv[i + 1]);
		} else if (!strcmp(argv[i], "cathedral")) {
			hymn_config_set_cathedral(&config, argv[i + 1]);
		} else if (!strcmp(argv[i], "identity")) {
			if (config.peer_cathedral == 0)
				fatal("identity only relevant for cathedral");
			config.cathedral_id = hymn_number(argv[i + 1], 16,
			    0, UINT_MAX);
		}
	}

	hymn_config_save(confpath, &config);

	argv[0] = keypath;
	argv[1] = NULL;

	return (hymn_keygen(1, argv));
}

static void
usage_del(void)
{
	fprintf(stderr, "usage: hymn del <src>-<dst>\n");
	exit(1);
}

static int
hymn_del(int argc, char *argv[])
{
	u_int8_t	src, dst;

	if (argc != 1)
		usage_del();

	if (sscanf(argv[0], "%02hhx-%02hhx", &src, &dst) != 2)
		usage_del();

	hymn_unlink("%s/hymn-%02x-%02x.key", HYMN_BASE_PATH, src, dst);
	hymn_unlink("%s/hymn-%02x-%02x.conf", HYMN_BASE_PATH, src, dst);

	return (0);
}

static void
usage_route(void)
{
	fprintf(stderr,
	    "usage: hymn route [add | delete] <net/mask> via <src>-<dst>\n");
	exit(1);
}

static int
hymn_route(int argc, char *argv[])
{
	struct config		config;
	struct addr		*rt, *old;
	char			path[PATH_MAX];

	if (argc != 4)
		usage_route();

	if (strcmp(argv[2], "via"))
		usage_route();

	hymn_config_init(&config);

	if (sscanf(argv[3], "%02hhx-%02hhx", &config.src, &config.dst) != 2)
		usage_route();

	hymn_conf_path(path, sizeof(path), config.src, config.dst);
	rt = hymn_route_parse(argv[1]);
	hymn_config_load(path, &config);

	if (!strcmp(argv[0], "add")) {
		LIST_FOREACH(old, &config.routes, list) {
			if (old->ip == rt->ip && old->mask && rt->mask)
				fatal("route %s exists", hymn_ip_mask_str(rt));
		}
		LIST_INSERT_HEAD(&config.routes, rt, list);
	} else if (!strcmp(argv[0], "del")) {
		LIST_FOREACH(old, &config.routes, list) {
			if (old->ip == rt->ip && old->mask && rt->mask) {
				LIST_REMOVE(old, list);
				free(old);
				break;
			}
		}
	} else {
		usage_route();
	}

	hymn_config_save(path, &config);
	free(rt);

	return (0);
}

static void
usage_up_down(void)
{
	fprintf(stderr, "usage: hymn [up|down] <src>-<dst>\n");
	exit(1);
}

static int
hymn_up(int argc, char *argv[])
{
	pid_t		pid;
	int		status;
	u_int8_t	src, dst;
	char		path[PATH_MAX], *ap[32];

	if (argc != 1)
		usage_up_down();

	if (sscanf(argv[0], "%02hhx-%02hhx", &src, &dst) != 2)
		usage_add();

	hymn_pid_path(path ,sizeof(path), src, dst);

	if (access(path, R_OK) != -1)
		fatal("hymn tunnel %02x-%02x is up", src, dst);

	if ((pid = fork()) == -1)
		fatal("fork: %s", errno_s);

	if (pid == 0) {
		hymn_conf_path(path, sizeof(path), src, dst);

		ap[0] = "sanctum";
		ap[1] = "-c";
		ap[2] = path;
		ap[3] = "-d";
		ap[4] = NULL;

		execvp(ap[0], ap);
		fatal("failed to execute sanctum: %s", errno_s);
	}

	for (;;) {
		if (waitpid(pid, &status, 0) == -1) {
			if (errno == EINTR)
				continue;
			fatal("waitpid: %s", errno_s);
		}

		break;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fatal("sanctum failed to start");

	printf("waiting for sanctum to start ... ");
	fflush(stdout);

	for (;;) {
		if (access(path, R_OK) != -1)
			break;
		sleep(1);
	}

	printf("done\n");

	return (0);
}

static int
hymn_down(int argc, char *argv[])
{
	FILE		*fp;
	pid_t		pid;
	u_int8_t	src, dst;
	char		path[PATH_MAX], buf[32], *ptr;

	if (argc != 1)
		usage_up_down();

	if (sscanf(argv[0], "%02hhx-%02hhx", &src, &dst) != 2)
		usage_add();

	hymn_pid_path(path, sizeof(path), src, dst);

	if (access(path, R_OK) == -1) {
		if (errno == ENOENT)
			fatal("hymn tunnel %02x-%02x is down", src, dst);
		fatal("failed to access %s: %s", path, errno_s);
	}

	if ((fp = fopen(path, "r")) == NULL)
		fatal("fopen(%s): %s", path, errno_s);

	if ((ptr = hymn_config_read(fp, buf, sizeof(buf))) == NULL)
		fatal("failed to read %s", path);

	pid = hymn_number(ptr, 10, 0, UINT_MAX);
	(void)fclose(fp);

	if (kill(pid, SIGQUIT) == -1)
		fatal("failed to signal %02x-%02x: %s", src, dst, errno_s);

	printf("waiting for hymn-%02x-%02x to go down ... ", src, dst);
	fflush(stdout);

	for (;;) {
		if (access(path, R_OK) == -1 && errno == ENOENT)
			break;
		sleep(1);
	}

	printf("done\n");

	return (0);
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

static void
hymn_mkdir(const char *path, int exists_ok)
{
	if (mkdir(path, 0700) == -1) {
		if (exists_ok && errno == EEXIST)
			return;
		fatal("failed to create '%s': %s", path, errno_s);
	}
}

static void
hymn_unlink(const char *fmt, ...)
{
	int		len;
	va_list		args;
	char		path[PATH_MAX];

	va_start(args, fmt);
	len = vsnprintf(path, sizeof(path), fmt, args);
	va_end(args);

	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("format too long for path");

	if (unlink(path) == -1)
		printf("warning: failed to unlink %s: %s\n", path, errno_s);
}

static struct addr *
hymn_route_parse(const char *route)
{
	struct addr	*rt;

	if ((rt = calloc(1, sizeof(*rt))) == NULL)
		fatal("calloc");

	hymn_ip_mask_parse(rt, route);

	rt->ip = rt->ip & htonl(0xffffffff << (32 - rt->mask));

	return (rt);
}

static void
hymn_ip_mask_parse(struct addr *addr, const char *opt)
{
	char		*p;

	if ((p = strchr(opt, '/')) == NULL)
		fatal("ip '%s' is missing a netmask", opt);

	*(p)++ = '\0';
	if (*p == '\0')
		fatal("ip '%s' is missing a netmask", opt);

	addr->mask = hymn_number(p, 10, 0, UINT_MAX);
	if (addr->mask > 32)
		fatal("netmask '/%s' is invalid", p);

	if (inet_pton(AF_INET, opt, &addr->ip) == 0)
		fatal("ip '%s' is invalid", opt);
}

static const char *
hymn_ip_mask_str(struct addr *addr)
{
	static char	str[INET_ADDRSTRLEN + 3];

	(void)snprintf(str, sizeof(str), "%u.%u.%u.%u/%u",
	    addr->ip & 0xff, (addr->ip >> 8) & 0xff,
	    (addr->ip >> 16) & 0xff, (addr->ip >> 24) & 0xff, addr->mask);

	return (str);
}

static unsigned long
hymn_number(const char *nptr, int base, unsigned long min, unsigned long max)
{
	unsigned long	ret;
	char		*ep;

	errno = 0;
	ret = strtoul(nptr, &ep, base);
	if (errno != 0 || nptr == ep || *ep != '\0')
		fatal("not a number: %s", nptr);

	if (ret < min || ret > max)
		fatal("'%s': out of range", nptr);

	return (ret);
}

static void
hymn_pid_path(char *buf, size_t buflen, u_int8_t src, u_int8_t dst)
{
	int		len;

	len = snprintf(buf, buflen, "%s/hymn-%02x-%02x.pid",
	    HYMN_RUN_PATH, src, dst);
	if (len == -1 || (size_t)len >= buflen)
		fatal("snprintf on tunnel pid path");
}

static void
hymn_key_path(char *buf, size_t buflen, u_int8_t src, u_int8_t dst)
{
	int		len;

	len = snprintf(buf, buflen, "%s/hymn-%02x-%02x.key",
	    HYMN_BASE_PATH, src, dst);
	if (len == -1 || (size_t)len >= buflen)
		fatal("snprintf on tunnel key path");
}

static void
hymn_conf_path(char *buf, size_t buflen, u_int8_t src, u_int8_t dst)
{
	int		len;

	len = snprintf(buf, buflen, "%s/hymn-%02x-%02x.conf",
	    HYMN_BASE_PATH, src, dst);
	if (len == -1 || (size_t)len >= buflen)
		fatal("snprintf on tunnel config path");
}

static void
hymn_config_init(struct config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));

	LIST_INIT(&cfg->routes);

	cfg->tun_mtu = 1422;
}

static void
hymn_config_write(int fd, const char *fmt, ...)
{
	int		len;
	ssize_t		ret;
	va_list		args;
	char		buf[1024];

	va_start(args, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (len == -1 || (size_t)len >= sizeof(buf))
		fatal("%s: fmt too large", __func__);

	for (;;) {
		if ((ret = write(fd, buf, len)) == -1) {
			if (errno == EINTR)
				continue;
			fatal("write: %s", errno_s);
		}

		if (ret != len)
			fatal("partial write %zd/%d", ret, len);

		break;
	}
}

static char *
hymn_config_read(FILE *fp, char *in, size_t len)
{
	char		*p, *t;

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
hymn_config_save(const char *path, struct config *cfg)
{
	struct addr	*rt;
	char		tmp[PATH_MAX];
	int		fd, len, saved_errno;

	len = snprintf(tmp, sizeof(tmp), "%s.new", path);
	if (len == -1 || (size_t)len >= sizeof(tmp))
		fatal("snprintf: failed on tmp path");

	if ((fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0700)) == -1)
		fatal("failed to open '%s': %s", tmp, errno_s);

	hymn_config_write(fd, "# auto generated, do not edit\n");
	hymn_config_write(fd, "spi 0x%02x%02x\n", cfg->src, cfg->dst);
	hymn_config_write(fd, "instance hymn-%02x-%02x\n", cfg->src, cfg->dst);
	hymn_config_write(fd, "pidfile %s/hymn-%02x-%02x.pid\n",
	    HYMN_RUN_PATH, cfg->src, cfg->dst);
	hymn_config_write(fd, "tunnel %s %u\n",
	    hymn_ip_mask_str(&cfg->tun), cfg->tun_mtu);
	hymn_config_write(fd, "secret %s/hymn-%02x-%02x.key\n",
	    HYMN_BASE_PATH, cfg->src, cfg->dst);

	hymn_config_write(fd, "\n");

	if (cfg->peer_cathedral) {
		hymn_config_write(fd, "cathedral_id 0x%08x\n",
		    cfg->cathedral_id);
		hymn_config_write(fd, "cathedral_secret /etc/hymn/id-0x%08x\n",
		    cfg->cathedral_id);
		hymn_config_write(fd, "cathedral ");
	} else {
		hymn_config_write(fd, "peer ");
	}

	hymn_config_write(fd, "%u.%u.%u.%u:%u\n",
	    cfg->peer_ip & 0xff, (cfg->peer_ip >> 8) & 0xff,
	    (cfg->peer_ip >> 16) & 0xff, (cfg->peer_ip >> 24) & 0xff,
	    cfg->peer_port);
	hymn_config_write(fd, "\n");

	LIST_FOREACH(rt, &cfg->routes, list) {
		hymn_config_write(fd, "route %s\n", hymn_ip_mask_str(rt));
		hymn_config_write(fd, "accept %s\n", hymn_ip_mask_str(rt));
	}

	hymn_config_write(fd, "\n");
	hymn_config_write(fd, "run control as %s\n", getlogin());
	hymn_config_write(fd, "control /tmp/hymn-%02x-%02x.control %s\n",
	    cfg->src, cfg->dst, getlogin());

	hymn_config_write(fd, "\n");
	hymn_config_write(fd, "run heaven as %s\n", getlogin());
	hymn_config_write(fd, "run purgatory as %s\n", getlogin());

	hymn_config_write(fd, "\n");
	hymn_config_write(fd, "run bless as root\n");
	hymn_config_write(fd, "run confess as root\n");
	hymn_config_write(fd, "run chapel as root\n");
	hymn_config_write(fd, "run shrine as root\n");
	hymn_config_write(fd, "run pilgrim as root\n");
	hymn_config_write(fd, "run cathedral as root\n");

	if (close(fd) == -1) {
		saved_errno = errno;
		if (unlink(tmp) == -1)
			printf("warning: unlink '%s': %s\n", tmp, errno_s);
		errno = saved_errno;
		fatal("close(%s): %s", tmp, errno_s);
	}

	if (rename(tmp, path) == -1) {
		saved_errno = errno;
		if (unlink(tmp) == -1)
			printf("warning: unlink '%s': %s\n", tmp, errno_s);
		errno = saved_errno;
		fatal("rename(%s, %s): %s", tmp, path, errno_s);
	}
}

static void
hymn_config_load(const char *path, struct config *cfg)
{
	FILE		*fp;
	int		idx;
	char		buf[BUFSIZ], *option, *value;

	if ((fp = fopen(path, "r")) == NULL)
		fatal("failed to open '%s': %s", path, errno_s);

	while ((option = hymn_config_read(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(option) == 0)
			continue;

		if ((value = strchr(option, ' ')) == NULL)
			fatal("malformed option '%s'", option);

		*(value)++ = '\0';

		for (idx = 0; keywords[idx].option != NULL; idx++) {
			if (!strcmp(keywords[idx].option, option)) {
				keywords[idx].cb(cfg, value);
				break;
			}
		}
	}

	if (ferror(fp))
		fatal("error reading the configuration file");

	fclose(fp);
}

static void
hymn_config_parse_tunnel(struct config *cfg, char *peer)
{
	char		*mtu;

	if ((mtu = strrchr(peer, ' ')) == NULL)
		fatal("config has invalid tunnel format");

	*(mtu)++ = '\0';

	hymn_ip_mask_parse(&cfg->tun, peer);
	hymn_config_set_mtu(cfg, mtu);
}

static void
hymn_config_parse_peer(struct config *cfg, char *peer)
{
	hymn_config_set_peer(cfg, peer);
}

static void
hymn_config_parse_cathedral(struct config *cfg, char *cathedral)
{
	hymn_config_set_cathedral(cfg, cathedral);
}

static void
hymn_config_parse_cathedral_id(struct config *cfg, char *id)
{
	cfg->cathedral_id = hymn_number(id, 16, 0, UINT_MAX);
}

static void
hymn_config_parse_route(struct config *cfg, char *route)
{
	struct addr	*rt;

	rt = hymn_route_parse(route);

	LIST_INSERT_HEAD(&cfg->routes, rt, list);
}

static void
hymn_config_set_mtu(struct config *cfg, const char *mtu)
{
	if (sscanf(mtu, "%hu", &cfg->tun_mtu) != 1)
		fatal("invalid mtu '%s'", mtu);

	if (cfg->tun_mtu > 9200 || cfg->tun_mtu < 576)
		fatal("invalid mtu '%s'", mtu);
}

static void
hymn_config_set_peer(struct config *cfg, const char *peer)
{
	char		*p;

	if ((p = strchr(peer, ':')) == NULL)
		fatal("peer '%s' not in ip:port format", peer);

	*(p)++ = '\0';

	errno = 0;
	cfg->peer_port = hymn_number(p, 10, 1, USHRT_MAX);
	if (cfg->peer_port == 0)
		fatal("peer port '%s' invalid", p);

	if (inet_pton(AF_INET, peer, &cfg->peer_ip) == 0)
		fatal("peer ip '%s' is invalid", peer);
}

static void
hymn_config_set_cathedral(struct config *cfg, const char *cathedral)
{
	cfg->peer_cathedral = 1;
	hymn_config_set_peer(cfg, cathedral);
}
