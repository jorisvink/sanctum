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
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/queue.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "libnyfe.h"
#include "sanctum_ctl.h"

#define errno_s			strerror(errno)

#define HYMN_BASE_PATH		"/etc/hymn"
#define HYMN_RUN_PATH		"/var/run/hymn"
#define HYMN_CLIENT_SOCKET	"/tmp/hymn.client"

#define HYMN_TUNNEL		(1 << 1)
#define HYMN_PEER		(1 << 2)
#define HYMN_SECRET		(1 << 3)
#define HYMN_KEK		(1 << 4)
#define HYMN_CATHEDRAL		(1 << 5)
#define HYMN_IDENTITY		(1 << 6)
#define HYMN_REQUIRED		(HYMN_TUNNEL | HYMN_PEER | HYMN_SECRET)

struct addr {
	in_addr_t		ip;
	in_addr_t		mask;
	u_int16_t		port;
	LIST_ENTRY(addr)	list;
};

LIST_HEAD(addrlist, addr);

struct config {
	u_int8_t		src;
	u_int8_t		dst;

	struct addr		tun;
	u_int16_t		tun_mtu;

	struct addr		peer;
	struct addr		local;
	struct addr		cathedral;

	u_int32_t		cathedral_id;
	u_int64_t		cathedral_flock;
	u_int16_t		cathedral_nat_port;

	int			peer_cathedral;

	const char		*flock;

	char			*kek;
	char			*descr;
	char			*secret;
	char			*identity_path;

	struct addrlist		routes;
	struct addrlist		accepts;
};

struct tunnel {
	struct config		config;
	TAILQ_ENTRY(tunnel)	list;
};

TAILQ_HEAD(tunnels, tunnel);

void		fatal(const char *, ...) __attribute__((noreturn));

static void	usage(void) __attribute__((noreturn));
static void	usage_simple(const char *) __attribute__((noreturn));

static void	usage_add(void) __attribute__((noreturn));
static void	usage_del(void) __attribute__((noreturn));
static void	usage_route(void) __attribute__((noreturn));
static void	usage_keygen(void) __attribute__((noreturn));

static void	hymn_mkdir(const char *, int);
static void	hymn_unlink(const char *, ...)
		    __attribute__((format (printf, 1, 2)));

static void	hymn_pid_path(char *, size_t, const char *,
		    u_int8_t, u_int8_t);
static void	hymn_conf_path(char *, size_t, const char *,
		    u_int8_t, u_int8_t);
static void	hymn_control_path(char *, size_t, const char *,
		    u_int8_t, u_int8_t);

static int	hymn_tunnel_list(struct tunnels *);
static int	hymn_tunnel_parse(char *, const char **,
		    u_int8_t *, u_int8_t *, int);

static int	hymn_up(int, char **);
static int	hymn_add(int, char **);
static int	hymn_del(int, char **);
static int	hymn_list(int, char **);
static int	hymn_down(int, char **);
static int	hymn_route(int, char **);
static int	hymn_status(int, char **);
static int	hymn_accept(int, char **);
static int	hymn_keygen(int, char **);

static void	hymn_config_init(struct config *);
static void	hymn_config_write(int, const char *, ...)
		    __attribute__((format (printf, 2, 3)));
static char	*hymn_config_read(FILE *, char *, size_t);
static void	hymn_config_load(const char *, struct config *);
static void	hymn_config_save(const char *, const char *, struct config *);

static void	hymn_config_set_mtu(struct config *, const char *);
static void	hymn_config_set_descr(struct config *, const char *);

static void	hymn_config_parse_kek(struct config *, char *);
static void	hymn_config_parse_peer(struct config *, char *);
static void	hymn_config_parse_descr(struct config *, char *);
static void	hymn_config_parse_local(struct config *, char *);
static void	hymn_config_parse_route(struct config *, char *);
static void	hymn_config_parse_tunnel(struct config *, char *);
static void	hymn_config_parse_accept(struct config *, char *);
static void	hymn_config_parse_secret(struct config *, char *);
static void	hymn_config_parse_cathedral(struct config *, char *);
static void	hymn_config_parse_cathedral_id(struct config *, char *);
static void	hymn_config_parse_cathedral_flock(struct config *, char *);
static void	hymn_config_parse_cathedral_nat_port(struct config *, char *);

static void	hymn_ctl_status(const char *,
		    struct sanctum_ctl_status_response *);
static void	hymn_ctl_response(int, void *, size_t);
static void	hymn_ctl_request(int, const char *, const void *, size_t);

static void	hymn_unix_socket(struct sockaddr_un *, const char *);
static void	hymn_dump_ifstat(const char *, struct sanctum_ifstat *);

static void	hymn_netlist_add(const char *,
		    struct addrlist *, struct addr *);
static void	hymn_netlist_del(const char *,
		    struct addrlist *, struct addr *);

static struct addr	*hymn_net_parse(const char *);
static const char	*hymn_ip_mask_str(struct addr *);
static const char	*hymn_ip_port_str(struct addr *);
static void		hymn_ip_port_parse(struct addr *, char *);
static void		hymn_ip_mask_parse(struct addr *, const char *);

static int		hymn_split_string(char *, const char *,
			    char **, size_t);
static unsigned long	hymn_number(const char *, int, unsigned long,
			    unsigned long);

static const struct {
	const char	*name;
	int		(*cb)(int, char **);
} cmds[] = {
	{ "up",			hymn_up },
	{ "add",		hymn_add },
	{ "del",		hymn_del },
	{ "status",		hymn_status },
	{ "list",		hymn_list },
	{ "down",		hymn_down },
	{ "route",		hymn_route },
	{ "accept",		hymn_accept },
	{ "keygen",		hymn_keygen },
	{ NULL,			NULL },
};

static const struct {
	const char		*option;
	void			(*cb)(struct config *, char *);
} keywords[] = {
	{ "kek",		hymn_config_parse_kek },
	{ "peer",		hymn_config_parse_peer },
	{ "descr",		hymn_config_parse_descr },
	{ "local",		hymn_config_parse_local },
	{ "route",		hymn_config_parse_route },
	{ "accept",		hymn_config_parse_accept },
	{ "tunnel",		hymn_config_parse_tunnel },
	{ "secret",		hymn_config_parse_secret },
	{ "cathedral",		hymn_config_parse_cathedral },
	{ "cathedral_id",	hymn_config_parse_cathedral_id },
	{ "cathedral_flock",	hymn_config_parse_cathedral_flock },
	{ "cathedral_nat_port",	hymn_config_parse_cathedral_nat_port },
	{ NULL,			NULL },
};

static void
usage(void)
{
	fprintf(stderr, "usage: hymn [cmd]\n");
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "  add      - add a new tunnel\n");
	fprintf(stderr, "  del      - delete an existing tunnel\n");
	fprintf(stderr, "  down     - kills the given tunnel\n");
	fprintf(stderr, "  list     - list all configured tunnels\n");
	fprintf(stderr, "  status   - show a specific tunnel its info\n");
	fprintf(stderr, "  route    - modify tunnel routing rules\n");
	fprintf(stderr, "  up       - starts the given tunnel\n");

	exit(1);
}

static void
usage_simple(const char *cmd)
{
	fprintf(stderr,
	    "usage: hymn %s [descr | [<flock>-]<src>-<dst>]\n", cmd);
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
	    "usage: hymn add [<flock>-]<src>-<dst> "
	    "tunnel <ip/mask> [mtu <mtu>] \\\n");
	fprintf(stderr, "    local <ip:port> secret <path> "
	    "[peer <ip:port>] [cathedral] <ip:port> \\\n");
	fprintf(stderr, "    [kek <path>] [descr <description>] ");
	fprintf(stderr, "[identity <32-bit hexint>:<path>]\n");
	fprintf(stderr, "    [natport <port>]\n");

	exit(1);
}

static int
hymn_add(int argc, char *argv[])
{
	char			*p;
	u_int32_t		which;
	struct config		config;
	int			i, len;
	const char		*flock;
	char			secret[PATH_MAX];
	char			confpath[PATH_MAX];

	if (argc < 5)
		usage_add();

	hymn_config_init(&config);

	if (hymn_tunnel_parse(argv[0],
	    &flock, &config.src, &config.dst, 0) == -1)
		usage_add();

	argc--;
	argv++;

	if (argc & 0x01)
		usage_add();

	which = 0;

	for (i = 0; i < argc; i += 2) {
		if (!strcmp(argv[i], "tunnel")) {
			which |= HYMN_TUNNEL;
			hymn_ip_mask_parse(&config.tun, argv[i + 1]);
		} else if (!strcmp(argv[i], "secret")) {
			which |= HYMN_SECRET;
			if (config.secret != NULL)
				fatal("duplicate secret");
			if ((config.secret = strdup(argv[i + 1])) == NULL)
				fatal("strdup");
		} else if (!strcmp(argv[i], "kek")) {
			which |= HYMN_KEK;
			if (config.kek != NULL)
				fatal("duplicate kek");
			if ((config.kek = strdup(argv[i + 1])) == NULL)
				fatal("strdup");
		} else if (!strcmp(argv[i], "descr")) {
			hymn_config_set_descr(&config, argv[i + 1]);
		} else if (!strcmp(argv[i], "mtu")) {
			hymn_config_set_mtu(&config, argv[i + 1]);
		} else if (!strcmp(argv[i], "peer")) {
			which |= HYMN_PEER;
			hymn_ip_port_parse(&config.peer, argv[i + 1]);
		} else if (!strcmp(argv[i], "local")) {
			hymn_ip_port_parse(&config.local, argv[i + 1]);
		} else if (!strcmp(argv[i], "cathedral")) {
			which |= HYMN_CATHEDRAL;
			hymn_ip_port_parse(&config.cathedral, argv[i + 1]);
			config.peer_cathedral = 1;
		} else if (!strcmp(argv[i], "natport")) {
			if (config.peer_cathedral == 0)
				fatal("natport only relevant for cathedral");
			config.cathedral_nat_port = hymn_number(argv[i + 1],
			    10, 0, USHRT_MAX);
		} else if (!strcmp(argv[i], "identity")) {
			if (config.peer_cathedral == 0)
				fatal("identity only relevant for cathedral");
			if ((p = strchr(argv[i + 1], ':')) != NULL) {
				*(p)++ = '\0';
				if ((config.identity_path = strdup(p)) == NULL)
					fatal("strdup");
			}
			which |= HYMN_IDENTITY;
			config.cathedral_id = hymn_number(argv[i + 1], 16,
			    0, UINT_MAX);
		} else {
			printf("unknown keyword '%s'\n", argv[i]);
			usage_add();
		}
	}

	if (strcmp(flock, "hymn")) {
		if (config.peer_cathedral == 0)
			fatal("a flock is only relevant for a cathedral");
		config.cathedral_flock = hymn_number(flock, 16, 0, UINT64_MAX);
	}

	if (which & HYMN_KEK) {
		if (config.peer_cathedral == 0)
			fatal("kek is only relevant with a cathedral");

		if (which & HYMN_SECRET)
			fatal("no need to specify a secret when using a kek");

		len = snprintf(secret, sizeof(secret), "%s/%02x-%02x.secret",
		    HYMN_BASE_PATH, config.src, config.dst);
		if (len == -1 || (size_t)len >= sizeof(secret))
			fatal("snprintf on tunnel secret path");

		if ((config.secret = strdup(secret)) == NULL)
			fatal("strdup");

		which |= HYMN_SECRET;
	}

	if (!(which & HYMN_PEER) && (which & HYMN_CATHEDRAL))
		which |= HYMN_PEER;

	if (!(which & HYMN_TUNNEL))
		printf("missing tunnel\n");

	if (which & HYMN_CATHEDRAL) {
		if (!(which & HYMN_IDENTITY))
			fatal("no cathedral identity given");

		if (!(which & HYMN_KEK) && !(which & HYMN_SECRET))
			printf("cathedral configured but no kek / secret\n");
	} else {
		if (!(which & HYMN_SECRET))
			printf("missing secret\n");
		if (!(which & HYMN_PEER))
			printf("missing peer\n");
	}

	if ((which & HYMN_REQUIRED) != HYMN_REQUIRED)
		usage_add();

	hymn_conf_path(confpath,
	    sizeof(confpath), flock, config.src, config.dst);

	if (access(confpath, R_OK) != -1) {
		fatal("tunnel %s-%02x-%02x config exists",
		    flock, config.src, config.dst);
	}

	hymn_config_save(confpath, flock, &config);

	return (0);
}

static void
usage_del(void)
{
	fprintf(stderr, "usage: hymn del [descr | [<flock>-]<src>-<dst>]\n");
	exit(1);
}

static int
hymn_del(int argc, char *argv[])
{
	const char	*flock;
	u_int8_t	src, dst;
	char		path[PATH_MAX];

	if (argc != 1)
		usage_del();

	if (hymn_tunnel_parse(argv[0], &flock, &src, &dst, 1) == -1)
		usage_del();

	hymn_pid_path(path ,sizeof(path), flock, src, dst);

	if (access(path, R_OK) != -1)
		fatal("tunnel %s-%02x-%02x still up", flock, src, dst);

	hymn_unlink("%s/%s-%02x-%02x.conf", HYMN_BASE_PATH, flock, src, dst);

	return (0);
}

static void
usage_route(void)
{
	fprintf(stderr,
	    "usage: hymn route [add | del] <net/mask> via "
	    "[descr | [<flock>-]<src>-<dst>]\n");
	exit(1);
}

static int
hymn_route(int argc, char *argv[])
{
	struct addr		*net;
	struct config		config;
	const char		*flock;
	char			path[PATH_MAX];

	if (argc != 4)
		usage_route();

	if (strcmp(argv[2], "via"))
		usage_route();

	hymn_config_init(&config);

	if (hymn_tunnel_parse(argv[3],
	    &flock, &config.src, &config.dst, 1) == -1)
		usage_route();

	hymn_conf_path(path, sizeof(path), flock, config.src, config.dst);

	net = hymn_net_parse(argv[1]);
	hymn_config_load(path, &config);

	if (!strcmp(argv[0], "add")) {
		hymn_netlist_add("route", &config.routes, net);
		hymn_netlist_add("accept", &config.accepts, net);
	} else if (!strcmp(argv[0], "del")) {
		hymn_netlist_del("route", &config.routes, net);
		hymn_netlist_del("accept", &config.accepts, net);
	} else {
		usage_route();
	}

	hymn_config_save(path, flock, &config);
	free(net);

	return (0);
}

static void
usage_accept(void)
{
	fprintf(stderr,
	    "usage: hymn accept [add | del] <net/mask> on "
	    "[descr | [<flock>-]<src>-<dst>]\n");
	exit(1);
}

static int
hymn_accept(int argc, char *argv[])
{
	struct addr		*net;
	struct config		config;
	const char		*flock;
	char			path[PATH_MAX];

	if (argc != 4)
		usage_accept();

	if (strcmp(argv[2], "on"))
		usage_accept();

	hymn_config_init(&config);

	if (hymn_tunnel_parse(argv[3],
	    &flock, &config.src, &config.dst, 1) == -1)
		usage_accept();

	hymn_conf_path(path, sizeof(path), flock, config.src, config.dst);

	net = hymn_net_parse(argv[1]);
	hymn_config_load(path, &config);

	if (!strcmp(argv[0], "add")) {
		hymn_netlist_add("accept", &config.accepts, net);
	} else if (!strcmp(argv[0], "del")) {
		hymn_netlist_del("accept", &config.accepts, net);
	} else {
		usage_accept();
	}

	hymn_config_save(path, flock, &config);
	free(net);

	return (0);
}

static int
hymn_up(int argc, char *argv[])
{
	pid_t		pid;
	int		status;
	const char	*flock;
	u_int8_t	src, dst;
	char		path[PATH_MAX], *ap[32];

	if (argc != 1)
		usage_simple("[up | down]");

	if (hymn_tunnel_parse(argv[0], &flock, &src, &dst, 1) == -1)
		usage_simple("[up | down]");

	hymn_pid_path(path ,sizeof(path), flock, src, dst);

	if (access(path, R_OK) != -1)
		fatal("hymn tunnel %02x-%02x is up", src, dst);

	if ((pid = fork()) == -1)
		fatal("fork: %s", errno_s);

	if (pid == 0) {
		hymn_conf_path(path, sizeof(path), flock, src, dst);

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
hymn_status(int argc, char *argv[])
{
	struct in_addr				in;
	struct addr				*net;
	struct sanctum_ctl_status_response	resp;
	struct config				config;
	u_int8_t				src, dst;
	char					path[PATH_MAX];
	const char				*flock, *status;

	if (argc != 1)
		usage_simple("status");

	if (hymn_tunnel_parse(argv[0], &flock, &src, &dst, 1) == -1)
		usage_simple("status");

	hymn_conf_path(path, sizeof(path), flock, src, dst);

	hymn_config_init(&config);
	hymn_config_load(path, &config);

	hymn_pid_path(path, sizeof(path), flock, src, dst);
	if (access(path, R_OK) == -1)
		status = "  not active";
	else
		status = NULL;

	if (status == NULL) {
		hymn_control_path(path, sizeof(path), flock, src, dst);
		hymn_ctl_status(path, &resp);
	}

	printf("%s-%02x-%02x:\n", flock, src, dst);

	if (config.descr != NULL)
		printf("  name\t\t%s\n", config.descr);

	printf("  local\t\t%s\n", hymn_ip_port_str(&config.local));
	printf("  tunnel\t%s (mtu %u)\n", hymn_ip_mask_str(&config.tun),
	    config.tun_mtu);

	if (config.peer_cathedral) {
		printf("  cathedral\t%s", hymn_ip_port_str(&config.cathedral));
	} else {
		printf("  peer\t\t%s", hymn_ip_port_str(&config.peer));
	}

	if (status == NULL && resp.ip != config.peer.ip) {
		in.s_addr = resp.ip;
		printf(" (%s:%u)",
		    inet_ntoa(in), ntohs(resp.port));
	}

	printf("\n");

	if (config.peer_cathedral) {
		printf("    flock\t%" PRIx64 "\n", config.cathedral_flock);
		printf("    identity\t%" PRIx32 "\n", config.cathedral_id);
	}

	printf("\n");
	printf("  routes\n");
	if (LIST_EMPTY(&config.routes)) {
		printf("    none\n");
	} else {
		LIST_FOREACH(net, &config.routes, list)
			printf("    %s\n", hymn_ip_mask_str(net));
	}

	printf("\n");
	printf("  accepts\n");
	if (LIST_EMPTY(&config.accepts)) {
		printf("    none\n");
	} else {
		LIST_FOREACH(net, &config.accepts, list)
			printf("    %s\n", hymn_ip_mask_str(net));
	}

	printf("\n");

	if (status != NULL) {
		printf("%s\n", status);
	} else {
		hymn_dump_ifstat("tx", &resp.tx);
		hymn_dump_ifstat("rx", &resp.rx);
	}

	return (0);
}

static int
hymn_list(int argc, char *argv[])
{
	struct tunnels				list;
	struct tunnel				*tun;
	struct sanctum_ctl_status_response	resp;
	int					normal_tunnels;
	char					path[PATH_MAX];

	if (argc != 0)
		fatal("Usage: hymn list");

	normal_tunnels = hymn_tunnel_list(&list);

	if (normal_tunnels)
		printf("normal tunnels:\n");

	while ((tun = TAILQ_FIRST(&list)) != NULL) {
		TAILQ_REMOVE(&list, tun, list);

		if (strcmp(tun->config.flock, "hymn") && normal_tunnels) {
			normal_tunnels = 0;
			printf("cathedral tunnels:\n");
		}

		printf("    %s-%02x-%02x - ",
		    tun->config.flock, tun->config.src, tun->config.dst);
		hymn_pid_path(path, sizeof(path),
		    tun->config.flock, tun->config.src, tun->config.dst);

		if (access(path, R_OK) == -1) {
			printf("down");
		} else {
			hymn_control_path(path, sizeof(path),
			    tun->config.flock, tun->config.src,
			    tun->config.dst);
			hymn_ctl_status(path, &resp);

			if (resp.tx.spi != 0 && resp.rx.spi != 0)
				printf("online");
			else
				printf("pending");
		}

		if (tun->config.descr != NULL)
			printf(" (%s)\n", tun->config.descr);
		else
			printf("\n");
	}

	return (0);
}

static int
hymn_down(int argc, char *argv[])
{
	FILE		*fp;
	pid_t		pid;
	const char	*flock;
	u_int8_t	src, dst;
	char		path[PATH_MAX], buf[32], *ptr;

	if (argc != 1)
		usage_simple("[up | down]");

	if (hymn_tunnel_parse(argv[0], &flock, &src, &dst, 1) == -1)
		usage_simple("[up | down]");

	hymn_pid_path(path, sizeof(path), flock, src, dst);

	if ((fp = fopen(path, "r")) == NULL) {
		if (errno == ENOENT)
			fatal("tunnel %s-%02x-%02x is down", flock, src, dst);
		fatal("fopen(%s): %s", path, errno_s);
	}

	if ((ptr = hymn_config_read(fp, buf, sizeof(buf))) == NULL)
		fatal("failed to read %s", path);

	pid = hymn_number(ptr, 10, 0, UINT_MAX);
	(void)fclose(fp);

	if (kill(pid, SIGQUIT) == -1)
		fatal("failed to signal %02x-%02x: %s", src, dst, errno_s);

	printf("waiting for %s-%02x-%02x to go down ... ", flock, src, dst);
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
hymn_netlist_add(const char *name, struct addrlist *list, struct addr *net)
{
	struct addr	*old;

	LIST_FOREACH(old, list, list) {
		if (old->ip == net->ip && old->mask == net->mask)
			fatal("%s %s exists", name, hymn_ip_mask_str(net));
	}
	LIST_INSERT_HEAD(list, net, list);
}

static void
hymn_netlist_del(const char *name, struct addrlist *list, struct addr *net)
{
	struct addr	*old;

	LIST_FOREACH(old, list, list) {
		if (old->ip == net->ip && old->mask == net->mask) {
			LIST_REMOVE(old, list);
			free(old);
			return;
		}
	}
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
hymn_net_parse(const char *route)
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

static void
hymn_ip_port_parse(struct addr *addr, char *ip)
{
	char		*p;

	if ((p = strchr(ip, ':')) == NULL)
		fatal("'%s' not in ip:port format", ip);

	*(p)++ = '\0';

	errno = 0;
	addr->port = hymn_number(p, 10, 0, USHRT_MAX);

	if (inet_pton(AF_INET, ip, &addr->ip) == 0)
		fatal("ip '%s' is invalid", ip);
}

static const char *
hymn_ip_port_str(struct addr *addr)
{
	static char	str[INET_ADDRSTRLEN + 6];

	(void)snprintf(str, sizeof(str), "%u.%u.%u.%u:%u",
	    addr->ip & 0xff, (addr->ip >> 8) & 0xff,
	    (addr->ip >> 16) & 0xff, (addr->ip >> 24) & 0xff, addr->port);

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

static int
hymn_split_string(char *input, const char *delim, char **out, size_t ele)
{
	int		count;
	char		**ap;

	if (ele == 0)
		return (0);

	count = 0;
	for (ap = out; ap < &out[ele - 1] &&
	    (*ap = strsep(&input, delim)) != NULL;) {
		if (**ap != '\0') {
			ap++;
			count++;
		}
	}

	*ap = NULL;
	return (count);
}

static void
hymn_pid_path(char *buf, size_t buflen, const char *flock,
    u_int8_t src, u_int8_t dst)
{
	int		len;

	len = snprintf(buf, buflen, "%s/%s-%02x-%02x.pid",
	    HYMN_RUN_PATH, flock, src, dst);
	if (len == -1 || (size_t)len >= buflen)
		fatal("snprintf on tunnel pid path");
}

static void
hymn_control_path(char *buf, size_t buflen, const char *flock,
    u_int8_t src, u_int8_t dst)
{
	int		len;

	len = snprintf(buf, buflen, "/tmp/%s-%02x-%02x.control",
	    flock, src, dst);
	if (len == -1 || (size_t)len >= buflen)
		fatal("snprintf on tunnel control path");
}

static void
hymn_conf_path(char *buf, size_t buflen,
    const char *flock, u_int8_t src, u_int8_t dst)
{
	int		len;

	len = snprintf(buf, buflen, "%s/%s-%02x-%02x.conf",
	    HYMN_BASE_PATH, flock, src, dst);
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

static int
hymn_tunnel_parse(char *str, const char **flock,
    u_int8_t *src, u_int8_t *dst, int resolve_descr)
{
	int			nelm;
	struct tunnels		list;
	struct tunnel		*tun;
	char			*elm[4];

	if (resolve_descr) {
		hymn_tunnel_list(&list);

		TAILQ_FOREACH(tun, &list, list) {
			if (tun->config.descr != NULL &&
			    !strcmp(tun->config.descr, str))
				break;
		}

		if (tun != NULL) {
			*src = tun->config.src;
			*dst = tun->config.dst;
			*flock = tun->config.flock;

			return (0);
		}
	}

	nelm = hymn_split_string(str, "-", elm, 4);

	if (nelm == 2) {
		*flock = "hymn";
		*src = hymn_number(elm[0], 16, 0, UCHAR_MAX);
		*dst = hymn_number(elm[1], 16, 0, UCHAR_MAX);
	} else if (nelm == 3) {
		*flock = elm[0];
		*src = hymn_number(elm[1], 16, 0, UCHAR_MAX);
		*dst = hymn_number(elm[2], 16, 0, UCHAR_MAX);
	} else {
		return (-1);
	}

	return (0);
}

static int
hymn_tunnel_list(struct tunnels *list)
{
	struct dirent		*dp;
	DIR			*dir;
	char			*ext;
	const char		*flock;
	u_int8_t		src, dst;
	struct tunnel		*tun, *entry;
	int			normal_tunnels;
	char			path[PATH_MAX];

	if ((dir = opendir(HYMN_BASE_PATH)) == NULL)
		fatal("opendir(%s): %s", HYMN_BASE_PATH, errno_s);

	TAILQ_INIT(list);
	normal_tunnels = 0;

	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_type != DT_REG)
			continue;

		if ((ext = strstr(dp->d_name, ".conf")) == NULL)
			continue;

		*ext = '\0';

		if (hymn_tunnel_parse(dp->d_name, &flock, &src, &dst, 0) == -1)
			continue;

		hymn_conf_path(path, sizeof(path), flock, src, dst);

		/* Yes, we leak here, we aren't long term. */
		if ((tun = calloc(1, sizeof(*tun))) == NULL)
			fatal("calloc failed for tunnel entry");

		hymn_config_init(&tun->config);
		hymn_config_load(path, &tun->config);

		if (!strcmp(flock, "hymn")) {
			normal_tunnels++;
			TAILQ_INSERT_HEAD(list, tun, list);
		} else {
			TAILQ_FOREACH(entry, list, list) {
				if (entry->config.cathedral_flock == 0)
					continue;
				if ((entry->config.cathedral_flock >
				    tun->config.cathedral_flock) ||
				    entry->config.src > src) {
					TAILQ_INSERT_BEFORE(entry, tun, list);
					break;
				}
			}

			if (entry == NULL)
				TAILQ_INSERT_TAIL(list, tun, list);
		}

		tun->config.src = src;
		tun->config.dst = dst;

		if ((tun->config.flock = strdup(flock)) == NULL)
			fatal("strdup");
	}

	(void)closedir(dir);

	return (normal_tunnels);
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
hymn_config_save(const char *path, const char *flock, struct config *cfg)
{
	struct addr	*net;
	char		tmp[PATH_MAX];
	int		fd, len, saved_errno;

	len = snprintf(tmp, sizeof(tmp), "%s.new", path);
	if (len == -1 || (size_t)len >= sizeof(tmp))
		fatal("snprintf: failed on tmp path");

	if ((fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0700)) == -1)
		fatal("failed to open '%s': %s", tmp, errno_s);

	hymn_config_write(fd, "# auto generated, do not edit\n");
	hymn_config_write(fd, "spi %02x%02x\n", cfg->src, cfg->dst);
	hymn_config_write(fd, "instance %s-%02x-%02x\n",
	    flock, cfg->src, cfg->dst);
	hymn_config_write(fd, "pidfile %s/%s-%02x-%02x.pid\n",
	    HYMN_RUN_PATH, flock, cfg->src, cfg->dst);
	hymn_config_write(fd, "tunnel %s %u\n",
	    hymn_ip_mask_str(&cfg->tun), cfg->tun_mtu);

	if (cfg->kek != NULL)
		hymn_config_write(fd, "kek %s\n", cfg->kek);

	hymn_config_write(fd, "secret %s\n", cfg->secret);

	if (cfg->descr != NULL)
		hymn_config_write(fd, "descr %s\n", cfg->descr);

	hymn_config_write(fd, "\n");
	hymn_config_write(fd, "local %s\n", hymn_ip_port_str(&cfg->local));

	if (cfg->peer_cathedral) {
		hymn_config_write(fd, "cathedral_id %x\n",
		    cfg->cathedral_id);
		hymn_config_write(fd, "cathedral_flock %" PRIx64 "\n",
		    cfg->cathedral_flock);
		if (cfg->identity_path != NULL) {
			hymn_config_write(fd,
			    "cathedral_secret %s\n", cfg->identity_path);
		} else {
			hymn_config_write(fd,
			    "cathedral_secret /etc/hymn/id-%x\n",
			    cfg->cathedral_id);
		}
		hymn_config_write(fd, "cathedral_nat_port %u\n",
		    cfg->cathedral_nat_port);
		hymn_config_write(fd, "cathedral ");
		hymn_config_write(fd, "%s\n",
		    hymn_ip_port_str(&cfg->cathedral));
		hymn_config_write(fd, "\n");
	}

	if (cfg->peer.ip != 0) {
		hymn_config_write(fd, "peer ");
		hymn_config_write(fd, "%s\n", hymn_ip_port_str(&cfg->peer));
		hymn_config_write(fd, "\n");
	}

	LIST_FOREACH(net, &cfg->routes, list)
		hymn_config_write(fd, "route %s\n", hymn_ip_mask_str(net));

	LIST_FOREACH(net, &cfg->accepts, list)
		hymn_config_write(fd, "accept %s\n", hymn_ip_mask_str(net));

	hymn_config_write(fd, "\n");
	hymn_config_write(fd, "run heaven-rx as %s\n", getlogin());
	hymn_config_write(fd, "run heaven-tx as %s\n", getlogin());
	hymn_config_write(fd, "run purgatory-rx as %s\n", getlogin());
	hymn_config_write(fd, "run purgatory-tx as %s\n", getlogin());

	hymn_config_write(fd, "\n");
	hymn_config_write(fd, "run control as root\n");
	hymn_config_write(fd, "control /tmp/%s-%02x-%02x.control root\n",
	    flock, cfg->src, cfg->dst);

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
hymn_config_parse_peer(struct config *cfg, char *peer)
{
	hymn_ip_port_parse(&cfg->peer, peer);
}

static void
hymn_config_parse_descr(struct config *cfg, char *descr)
{
	hymn_config_set_descr(cfg, descr);
}

static void
hymn_config_parse_local(struct config *cfg, char *local)
{
	hymn_ip_port_parse(&cfg->local, local);
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
hymn_config_parse_kek(struct config *cfg, char *kek)
{
	if (cfg->kek != NULL)
		fatal("duplicate kek");

	if ((cfg->kek = strdup(kek)) == NULL)
		fatal("strdup");
}

static void
hymn_config_parse_secret(struct config *cfg, char *secret)
{
	if (cfg->secret != NULL)
		fatal("duplicate secret");

	if ((cfg->secret = strdup(secret)) == NULL)
		fatal("strdup");
}

static void
hymn_config_parse_cathedral(struct config *cfg, char *cathedral)
{
	hymn_ip_port_parse(&cfg->cathedral, cathedral);
	cfg->peer_cathedral = 1;
}

static void
hymn_config_parse_cathedral_id(struct config *cfg, char *id)
{
	cfg->cathedral_id = hymn_number(id, 16, 0, UINT_MAX);
}

static void
hymn_config_parse_cathedral_flock(struct config *cfg, char *flock)
{
	cfg->cathedral_flock = hymn_number(flock, 16, 0, UINT64_MAX);
}

static void
hymn_config_parse_cathedral_nat_port(struct config *cfg, char *natport)
{
	cfg->cathedral_nat_port = hymn_number(natport, 10, 0, USHRT_MAX);
}

static void
hymn_config_parse_route(struct config *cfg, char *route)
{
	struct addr	*net;

	net = hymn_net_parse(route);

	LIST_INSERT_HEAD(&cfg->routes, net, list);
}

static void
hymn_config_parse_accept(struct config *cfg, char *accept)
{
	struct addr	*net;

	net = hymn_net_parse(accept);

	LIST_INSERT_HEAD(&cfg->accepts, net, list);
}

static void
hymn_config_set_descr(struct config *cfg, const char *descr)
{
	size_t		len, idx;

	if (cfg->descr != NULL)
		fatal("duplicate descr given");

	len = strlen(descr);
	if (len > 31)
		fatal("descr is too long");

	for (idx = 0; idx < len; idx++) {
		if (!isalnum((unsigned char)descr[idx]) && descr[idx] != '-')
			fatal("descr may only contain alnum and '-'");
	}

	if ((cfg->descr = strdup(descr)) == NULL)
		fatal("strdup");
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
hymn_unix_socket(struct sockaddr_un *sun, const char *path)
{
	int		len;

	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_UNIX;

	len = snprintf(sun->sun_path, sizeof(sun->sun_path), "%s", path);
	if (len == -1 || (size_t)len >= sizeof(sun->sun_path))
		fatal("failed to create path to '%s'", path);
}

static void
hymn_ctl_status(const char *path, struct sanctum_ctl_status_response *out)
{
	int				fd;
	struct sockaddr_un		sun;
	struct sanctum_ctl		ctl;

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	if (unlink(HYMN_CLIENT_SOCKET) && errno != ENOENT)
		fatal("unlink(%s): %s", HYMN_CLIENT_SOCKET, errno_s);

	hymn_unix_socket(&sun, HYMN_CLIENT_SOCKET);

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		fatal("bind: %s", errno_s);

	memset(&ctl, 0, sizeof(ctl));

	ctl.cmd = SANCTUM_CTL_STATUS;

	hymn_ctl_request(fd, path, &ctl, sizeof(ctl));
	hymn_ctl_response(fd, out, sizeof(*out));
}

static void
hymn_ctl_request(int fd, const char *path, const void *req, size_t len)
{
	ssize_t			ret;
	struct sockaddr_un	sun;

	hymn_unix_socket(&sun, path);

	for (;;) {
		if ((ret = sendto(fd, req, len, 0,
		    (const struct sockaddr *)&sun, sizeof(sun))) == -1) {
			if (errno == EINTR)
				continue;
			fatal("send: %s", errno_s);
		}

		if ((size_t)ret != len)
			fatal("short send, %zd/%zu", ret, len);

		break;
	}
}

static void
hymn_ctl_response(int fd, void *resp, size_t len)
{
	ssize_t		ret;

	for (;;) {
		if ((ret = recv(fd, resp, len, 0)) == -1) {
			if (errno == EINTR)
				continue;
			fatal("recv: %s", errno_s);
		}

		if ((size_t)ret != len)
			fatal("short recv, %zd/%zu", ret, len);

		break;
	}
}

static void
hymn_dump_ifstat(const char *name, struct sanctum_ifstat *st)
{
	struct timespec				ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	printf("  %s\n", name);

	if (st->spi == 0) {
		printf("    spi            none\n");
	} else {
		printf("    spi            %08x (age: %" PRIu64 " seconds)\n",
		    st->spi, ts.tv_sec - st->age);
	}

	printf("    pkt            %" PRIu64 " \n", st->pkt);
	printf("    bytes          %" PRIu64 " \n", st->bytes);

	if (st->last == 0) {
		printf("    last packet    never\n");
	} else {
		printf("    last packet    %" PRIu64 " seconds ago\n",
		    ts.tv_sec - st->last);
	}

	printf("\n");
}
