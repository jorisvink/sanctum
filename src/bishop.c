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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

/* The base directory where hymn places its configurations. */
#define HYMN_BASE_PATH		"/etc/hymn"

/*
 * The base directory where hymn configured sanctum instances place their
 * pidfile while they are up and running.
 */
#define HYMN_RUN_PATH		"/var/run/hymn"

/* The format string for adding a new tunnel using the hymn tool. */
#define HYMN_FMT_ADD						\
    "hymn add %" PRIx64 "-%02x-%02x tunnel %s/32 "		\
    "cathedral %s:%u kek %s identity %x:%s cosk %s natport %u"

/* The format string for up/down of a tunnel via the hymn tool. */
#define HYMN_FMT_UP_DOWN	"hymn %s %" PRIx64 "-%02x-%02x"

/* The format string for route add via the hymn tool. */
#define HYMN_FMT_ROUTE_ADD	"hymn route add %s/32 via %" PRIx64 "-%02x-%02x"

static int	bishop_instance_exists(u_int8_t, u_int8_t);
static int	bishop_instance_running(u_int8_t, u_int8_t);

static void	bishop_hymn_read(void);
static void	bishop_hymn_reap(pid_t);
static void	bishop_hymn_run(const char *, u_int8_t, u_int8_t);

static void	bishop_liturgy_request(struct sanctum_packet *);
static void	bishop_liturgy_address(char *, size_t, u_int8_t, u_int8_t);

static int	bishop_split_string(char *, const char *, char **, size_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* Pipe we re-use to read stdout from the forked hymn processes. */
static int			hymn_pipe[2];

/* Quick bookkeeping of the instances that are up. */
static u_int8_t			instances[SANCTUM_PEERS_PER_FLOCK];

/*
 * Bishop - Part of the liturgy.
 *
 * This process uses the 'hymn' tool to configure tunnels and start or
 * stop them. This way tunnels created by liturgy are still able to
 * be managed by the 'hymn' tool its status etc.
 *
 * This process is privileged and does not privsep or sandbox itself.
 */
void
sanctum_bishop(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;
	u_int8_t		local_id, idx;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode == SANCTUM_MODE_LITURGY);

	io = proc->arg;

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	running = 1;
	local_id = sanctum->tun_spi & 0xff;

	if (pipe(hymn_pipe) == -1)
		fatal("pipe: %s", errno_s);

	sanctum_proc_started(proc);

	for (idx = 1; idx < SANCTUM_PEERS_PER_FLOCK; idx++) {
		if (idx == local_id)
			continue;

		if (bishop_instance_exists(local_id, idx) != -1 &&
		    bishop_instance_running(local_id, idx) != -1) {
			instances[idx] = 1;
		} else {
			instances[idx] = 0;
		}
	}

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			case SIGCHLD:
				bishop_hymn_reap(-1);
				break;
			}
		}

		sanctum_proc_suspend(1);

		while ((pkt = sanctum_ring_dequeue(io->bishop)) != NULL) {
			bishop_liturgy_request(pkt);
			sanctum_packet_release(pkt);
		}

		bishop_hymn_read();
	}

	sanctum_log(LOG_NOTICE, "shutting down running instances");

	for (idx = 1; idx < SANCTUM_PEERS_PER_FLOCK; idx++) {
		if (idx == local_id)
			continue;

		if (instances[idx] == 0)
			continue;

		if (bishop_instance_exists(local_id, idx) != -1 &&
		    bishop_instance_running(local_id, idx) != -1)
			bishop_hymn_run("down", local_id, idx);
	}

	bishop_hymn_reap(-1);
	bishop_hymn_read();

	exit(0);
}

/*
 * Process a liturgy request, we get to know if a peer is present
 * or not. Based on this we create new hymn configurations if required
 * and stop or start instances.
 */
static void
bishop_liturgy_request(struct sanctum_packet *pkt)
{
	struct sanctum_liturgy		*info;
	u_int8_t			src, dst;

	PRECOND(pkt != NULL);
	PRECOND(pkt->length == sizeof(*info));

	info = sanctum_packet_head(pkt);

	src = info->instance >> 8;
	dst = info->instance & 0xff;

	if (info->present) {
		if (bishop_instance_exists(src, dst) == -1) {
			bishop_hymn_run("add", src, dst);
			bishop_hymn_run("route", src, dst);
		}

		if (bishop_instance_running(src, dst) == -1) {
			bishop_hymn_run("up", src, dst);
			instances[dst] = 1;
		}
	} else {
		if (bishop_instance_exists(src, dst) != -1 &&
		    bishop_instance_running(src, dst) != -1) {
			bishop_hymn_run("down", src, dst);
			instances[dst] = 0;
		}
	}
}

/*
 * Let the bishop do a hymn, performing the requested command on the tunnel.
 */
static void
bishop_hymn_run(const char *cmd, u_int8_t src, u_int8_t dst)
{
	int		len;
	pid_t		pid;
	char		*argv[32];
	char		buf[2048], ip[INET_ADDRSTRLEN];

	PRECOND(cmd != NULL);
	PRECOND(src != dst);

	if (!strcmp(cmd, "add")) {
		bishop_liturgy_address(ip, sizeof(ip), src, dst);
		len = snprintf(buf, sizeof(buf), HYMN_FMT_ADD,
		    sanctum->cathedral_flock, src, dst, ip,
		    inet_ntoa(sanctum->cathedral.sin_addr),
		    be16toh(sanctum->cathedral.sin_port), sanctum->kek,
		    sanctum->cathedral_id, sanctum->cathedral_secret,
		    sanctum->cathedral_cosk, sanctum->cathedral_nat_port);
	} else if (!strcmp(cmd, "up") || !strcmp(cmd, "down")) {
		len = snprintf(buf, sizeof(buf), HYMN_FMT_UP_DOWN,
		    cmd, sanctum->cathedral_flock, src, dst);
	} else if (!strcmp(cmd, "route")) {
		bishop_liturgy_address(ip, sizeof(ip), dst, src);
		len = snprintf(buf, sizeof(buf), HYMN_FMT_ROUTE_ADD,
		    ip, sanctum->cathedral_flock, src, dst);
	} else {
		fatal("unknown hymn command '%s'", cmd);
	}

	if (len == -1 || (size_t)len >= sizeof(buf))
		fatal("failed to format %s string", cmd);

	if ((pid = fork()) == -1)
		fatal("fork: %s", errno_s);

	if (pid == 0) {
		sanctum_shm_detach(io->bishop);
		(void)bishop_split_string(buf, " ", argv, 32);

		if (dup2(hymn_pipe[1], STDOUT_FILENO) == -1 ||
		    dup2(hymn_pipe[1], STDERR_FILENO) == -1)
			fatal("dup2: %s", errno_s);

		execvp(argv[0], argv);
		sanctum_log(LOG_ERR, "failed to execute: %s", errno_s);
		exit(1);
	}

	sanctum_log(LOG_INFO, "%" PRIx64 ":%02x pid=[%d] cmd=[%s]",
	    sanctum->cathedral_flock, src, pid, buf);

	bishop_hymn_reap(pid);
	bishop_hymn_read();
}

/*
 * Attempt to reap a child process and report on its status.
 */
static void
bishop_hymn_reap(pid_t which)
{
	pid_t		pid;
	int		status, flags;

	if (which == -1)
		flags = WNOHANG;
	else
		flags = 0;

	for (;;) {
		if ((pid = waitpid(which, &status, flags)) == -1) {
			if (errno == EINTR)
				continue;
			if (errno == ECHILD)
				break;
			fatal("waitpid: %s", errno_s);
		}

		if (pid == 0)
			break;

		sanctum_log(LOG_INFO, "pid=[%d] status=[%d]", pid, status);
	}
}

/*
 * Read our hymn_pipe, it contains output from hymn processes that
 * have been running. We log the output.
 */
static void
bishop_hymn_read(void)
{
	struct pollfd		pfd;
	ssize_t			ret;
	char			buf[128];

	pfd.events = POLLIN;
	pfd.fd = hymn_pipe[0];

	if (poll(&pfd, 1, 100) == -1) {
		if (errno == EINTR)
			return;
		fatal("poll: %s", errno_s);
	}

	memset(buf, 0, sizeof(buf));

	if (pfd.revents & POLLIN) {
		if ((ret = read(pfd.fd, buf, sizeof(buf) - 1)) == -1) {
			if (errno == EINTR)
				return;
			fatal("read: %s", errno_s);
		}

		if (ret == 0)
			fatal("somehow eof on pipe");

		buf[strcspn(buf, "\n")] = '\0';
		sanctum_log(LOG_INFO, "%s", buf);
	}
}

/*
 * Check if the sanctum instance its hymn configuration exists.
 */
static int
bishop_instance_exists(u_int8_t src, u_int8_t dst)
{
	int		len;
	char		path[1024];

	len = snprintf(path, sizeof(path), "%s/%" PRIx64 "-%02x-%02x.conf",
	    HYMN_BASE_PATH, sanctum->cathedral_flock, src, dst);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("snprintf on instance config path");

	if (access(path, R_OK) != -1)
		return (0);

	return (-1);
}

/*
 * Check if the sanctum instance is up and running right now. We do this
 * by checking the pid file for the instance.
 */
static int
bishop_instance_running(u_int8_t src, u_int8_t dst)
{
	int		len;
	char		path[1024];

	len = snprintf(path, sizeof(path), "%s/%" PRIx64 "-%02x-%02x.pid",
	    HYMN_RUN_PATH, sanctum->cathedral_flock, src, dst);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("snprintf on instance pid path");

	if (access(path, R_OK) != -1)
		return (0);

	return (-1);
}

/*
 * Helper function that splits a string based on the given delimiter.
 */
static int
bishop_split_string(char *input, const char *delim, char **out, size_t ele)
{
	int		count;
	char		**ap;

	PRECOND(input != NULL);
	PRECOND(delim != NULL);
	PRECOND(out != NULL);
	PRECOND(ele > 1);

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

/*
 * Helper function to create a liturgy_prefix based address based
 * on the src and dst members.
 */
static void
bishop_liturgy_address(char *ip, size_t len, u_int8_t a, u_int8_t b)
{
	struct in_addr		addr;

	PRECOND(ip != NULL);
	PRECOND(len == INET_ADDRSTRLEN);

	addr = sanctum->liturgy_prefix.sin_addr;
	addr.s_addr |= ((u_int32_t)b << 24) | ((u_int32_t)a << 16);

	if (inet_ntop(AF_INET, &addr, ip, len) == NULL)
		fatal("inet_pton: %s", errno_s);
}
