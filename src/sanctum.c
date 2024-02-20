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
#include <sys/shm.h>

#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "sanctum.h"

static void	signal_hdlr(int);
static void	signal_memfault(int);

static void	usage(void) __attribute__((noreturn));
static void	version(void) __attribute__((noreturn));

static void	sanctum_pidfile_check(void);
static void	sanctum_pidfile_write(void);
static void	sanctum_pidfile_unlink(void);

static int			early = 1;
volatile sig_atomic_t		sig_recv = -1;
struct sanctum_state		*sanctum = NULL;

static void
version(void)
{
	fprintf(stderr, "sanctum %s (%s) (%s)\n",
	    sanctum_build_rev, sanctum_build_date, sanctum_cipher);

	exit(1);
}

static void
usage(void)
{
	fprintf(stderr, "sanctum [options]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -c  The configuration file.\n");
	fprintf(stderr, "  -d  Daemonize the parent process.\n");
	fprintf(stderr, "  -h  This amazing help text.\n");
	fprintf(stderr, "  -v  Display version information.\n");

	exit(1);
}

int
main(int argc, char *argv[])
{
	struct timespec		ts;
	sigset_t		sigset;
	const char		*config;
	int			ch, running, sig, foreground;

	config = NULL;
	foreground = 1;

	while ((ch = getopt(argc, argv, "c:dhv")) != -1) {
		switch (ch) {
		case 'c':
			config = optarg;
			break;
		case 'd':
			foreground = 0;
			break;
		case 'v':
			version();
			break;
		default:
			usage();
		}
	}

	if (config == NULL)
		usage();

	sanctum = sanctum_alloc_shared(sizeof(*sanctum), NULL);
	sanctum->mode = SANCTUM_MODE_TUNNEL;

	if (foreground == 0)
		sanctum->flags |= SANCTUM_FLAG_DAEMONIZED;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	sanctum_atomic_write(&sanctum->uptime, ts.tv_sec);

	sanctum_config_init();
	sanctum_config_load(config);
	sanctum_pidfile_check();

	sanctum_signal_trap(SIGINT);
	sanctum_signal_trap(SIGHUP);
	sanctum_signal_trap(SIGCHLD);
	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_trap(SIGSEGV);

	sanctum_platform_init();
	sanctum_proc_init(argv);
	sanctum_packet_init();
	sanctum_proc_start();

	if (sigfillset(&sigset) == -1)
		fatal("sigfillset: %s", errno_s);

	sigdelset(&sigset, SIGINT);
	sigdelset(&sigset, SIGHUP);
	sigdelset(&sigset, SIGCHLD);
	sigdelset(&sigset, SIGQUIT);
	(void)sigprocmask(SIG_BLOCK, &sigset, NULL);

	early = 0;

	if (foreground == 0) {
		if (daemon(1, 0) == -1)
			fatal("daemon: %s", errno_s);
	}

	openlog("sanctum", LOG_NDELAY | LOG_PID, LOG_DAEMON);
	sanctum_proc_title("guardian");

	running = 1;

	if (sanctum_last_signal() == SIGCHLD) {
		if (sanctum_proc_reap()) {
			sanctum_proc_shutdown();
			return (0);
		}
	}

	sig_recv = -1;

	sanctum_pidfile_write();
	sanctum_log(LOG_INFO, "sanctum started (pid=%d)", getpid());

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_INFO, "parent received signal %d", sig);
			switch (sig) {
			case SIGINT:
			case SIGHUP:
			case SIGQUIT:
				running = 0;
				continue;
			case SIGCHLD:
				if (sanctum_proc_reap()) {
					running = 0;
					continue;
				}
				break;
			default:
				break;
			}
		}

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);
		sanctum_atomic_write(&sanctum->uptime, ts.tv_sec);

		sleep(1);
	}

	sanctum_proc_shutdown();
	sanctum_pidfile_unlink();

	return (0);
}

/*
 * Let the given signal be caught by our signal handler.
 */
void
sanctum_signal_trap(int sig)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));

	if (sig == SIGSEGV)
		sa.sa_handler = signal_memfault;
	else
		sa.sa_handler = signal_hdlr;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);

	if (sigaction(sig, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
}

/*
 * Explicitly ignore the given signal.
 */
void
sanctum_signal_ignore(int sig)
{
	(void)signal(sig, SIG_IGN);
}

/*
 * Returns the last received signal to the caller and resets sig_recv.
 */
int
sanctum_last_signal(void)
{
	int	sig;

	sig = sig_recv;
	sig_recv = -1;

	return (sig);
}

/*
 * Bad juju happened.
 */
void
fatal(const char *fmt, ...)
{
	va_list			args;
	struct sanctum_proc	*proc;

	PRECOND(fmt != NULL);

	nyfe_zeroize_all();

	proc = sanctum_process();
	va_start(args, fmt);

	if (early && proc == NULL) {
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
	} else {
		sanctum_logv(LOG_ERR, fmt, args);
	}

	va_end(args);

	if (proc == NULL) {
		sanctum_proc_shutdown();
		sanctum_pidfile_unlink();
	}

	exit(1);
}

/*
 * Our signal handler, doesn't do much more than set sig_recv so it can
 * be obtained by sanctum_last_signal().
 */
static void
signal_hdlr(int sig)
{
	sig_recv = sig;
}

/*
 * The signal handler for when a segmentation fault occurred, we are
 * catching this so we can just cleanup before dying.
 */
static void
signal_memfault(int sig)
{
	nyfe_zeroize_all();
	abort();
}

/*
 * Check if our pidfile already exists, indicating we didn't cleanly
 * shutdown maybe last time, or that something else is using our path.
 */
static void
sanctum_pidfile_check(void)
{
	PRECOND(sanctum != NULL);

	if (sanctum->pidfile == NULL)
		return;

	/* Don't call fatal() here, we don't want to try and remove it. */
	if (access(sanctum->pidfile, R_OK) != -1 && errno != ENOENT) {
		fprintf(stderr, "pidfile '%s' exists\n", sanctum->pidfile);
		exit(1);
	}
}

/*
 * Create the pidfile at the location given in our configuration file.
 * Write the guardian process its PID to it.
 */
static void
sanctum_pidfile_write(void)
{
	int		fd;
	FILE		*fp;

	PRECOND(sanctum != NULL);

	if (sanctum->pidfile == NULL)
		return;

	fd = nyfe_file_open(sanctum->pidfile, NYFE_FILE_CREATE);

	if ((fp = fdopen(fd, "w")) == NULL)
		fatal("fdopen: %s", strerror(errno));

	(void)fprintf(fp, "%d", getpid());

	if (fclose(fp) != 0) {
		sanctum_log(LOG_NOTICE,
		    "close on pidfile failed: %s", strerror(errno));
	}
}

/*
 * Remove our pidfile from disk by unlinking it.
 */
static void
sanctum_pidfile_unlink(void)
{
	PRECOND(sanctum != NULL);

	if (sanctum->pidfile == NULL)
		return;

	if (unlink(sanctum->pidfile) == -1) {
		sanctum_log(LOG_NOTICE, "failed to remove pidfile '%s' (%s)",
		    sanctum->pidfile, strerror(errno));
	}
}
