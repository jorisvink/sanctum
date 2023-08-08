/*
 * Copyright (c) 2023 Joris Vink <joris@coders.se>
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
#include <sys/wait.h>

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

/* List of all worker processes. */
static LIST_HEAD(, sanctum_proc)		proclist;

/* Some human understand process types. */
static const char *proctab[] = {
	"unknown",
	"heaven",
	"purgatory",
	"bless",
	"confess",
	"chapel",
	"status"
};

/* Points to the process its own sanctum_proc, or NULL or parent. */
static struct sanctum_proc	*process = NULL;

/* Used for setting the process titles. */
static size_t		proc_title_max = 0;
static char		**proc_argv = NULL;
extern char		**environ;

/*
 * Initialize the process system so new processes can be started.
 */
void
sanctum_proc_init(char **argv)
{
	int		i;
	char		*p;

	PRECOND(argv != NULL);

	LIST_INIT(&proclist);

	proc_argv = argv;
	proc_title_max = 0;

	for (i = 0; environ[i] != NULL; i++) {
		if ((p = strdup(environ[i])) == NULL)
			fatal("strdup");
		proc_title_max += strlen(environ[i]) + 1;
		environ[i] = p;
	}

	for (i = 0; proc_argv[i] != NULL; i++)
		proc_title_max += strlen(proc_argv[i]) + 1;
}

/*
 * Start the clear and crypto sides.
 *
 * We create all the shared memory queues and pass them to each process.
 * The processes themselves will remove the queues they do not need.
 */
void
sanctum_proc_start(void)
{
	struct sanctum_proc_io		io;

	sanctum_proc_create(SANCTUM_PROC_STATUS, sanctum_status, NULL);

	io.tx = sanctum_alloc_shared(sizeof(struct sanctum_key), NULL);
	io.rx = sanctum_alloc_shared(sizeof(struct sanctum_key), NULL);
	io.arwin = sanctum_alloc_shared(sizeof(struct sanctum_arwin), NULL);

	io.offer = sanctum_ring_alloc(1);
	io.chapel = sanctum_ring_alloc(2);
	io.bless = sanctum_ring_alloc(1024);
	io.heaven = sanctum_ring_alloc(1024);
	io.confess = sanctum_ring_alloc(1024);
	io.purgatory = sanctum_ring_alloc(1024);

	sanctum_proc_create(SANCTUM_PROC_BLESS, sanctum_bless, &io);
	sanctum_proc_create(SANCTUM_PROC_HEAVEN, sanctum_heaven, &io);
	sanctum_proc_create(SANCTUM_PROC_CHAPEL, sanctum_chapel, &io);
	sanctum_proc_create(SANCTUM_PROC_CONFESS, sanctum_confess, &io);
	sanctum_proc_create(SANCTUM_PROC_PURGATORY, sanctum_purgatory, &io);

	sanctum_shm_detach(io.tx);
	sanctum_shm_detach(io.rx);
	sanctum_shm_detach(io.bless);
	sanctum_shm_detach(io.offer);
	sanctum_shm_detach(io.arwin);
	sanctum_shm_detach(io.chapel);
	sanctum_shm_detach(io.heaven);
	sanctum_shm_detach(io.confess);
	sanctum_shm_detach(io.purgatory);
}

/*
 * Create a new process that will start executing at the given entry
 * point. The process is not yet started.
 */
void
sanctum_proc_create(u_int16_t type,
    void (*entry)(struct sanctum_proc *), void *arg)
{
	struct passwd		*pw;
	struct sanctum_proc	*proc;

	PRECOND(type == SANCTUM_PROC_HEAVEN ||
	    type == SANCTUM_PROC_PURGATORY ||
	    type == SANCTUM_PROC_BLESS ||
	    type == SANCTUM_PROC_CONFESS ||
	    type == SANCTUM_PROC_CHAPEL ||
	    type == SANCTUM_PROC_STATUS);
	PRECOND(entry != NULL);
	/* arg is optional. */

	if (sanctum->runas[type] == NULL)
		fatal("no runas user configured for %s", proctab[type]);

	if ((proc = calloc(1, sizeof(*proc))) == NULL)
		fatal("calloc: failed to allocate new proc entry");

	proc->arg = arg;
	proc->type = type;
	proc->entry = entry;
	proc->name = proctab[type];

	if ((pw = getpwnam(sanctum->runas[proc->type])) == NULL)
		fatal("getpwnam(%s): %s", sanctum->runas[proc->type], errno_s);

	proc->uid = pw->pw_uid;
	proc->gid = pw->pw_gid;

	if ((proc->pid = fork()) == -1)
		fatal("failed to fork child: %s", errno_s);

	if (proc->pid == 0) {
		openlog(proc->name, LOG_NDELAY | LOG_PID, LOG_DAEMON);
		sanctum_proc_title(proc->name);

		process = proc;
		proc->pid = getpid(),
		proc->entry(proc);
		/* NOTREACHED */
	}

	syslog(LOG_INFO, "started %s (pid=%d)", proc->name, proc->pid);

	LIST_INSERT_HEAD(&proclist, proc, list);
}

/*
 * Have a process drop its privileges.
 */
void
sanctum_proc_privsep(struct sanctum_proc *proc)
{
	PRECOND(proc != NULL);

	switch (proc->type) {
	case SANCTUM_PROC_HEAVEN:
	case SANCTUM_PROC_PURGATORY:
	case SANCTUM_PROC_CHAPEL:
	case SANCTUM_PROC_STATUS:
	case SANCTUM_PROC_BLESS:
	case SANCTUM_PROC_CONFESS:
		break;
	default:
		fatal("%s: unknown process type %d", __func__, proc->type);
	}

	if (setgroups(1, &proc->gid) == -1 ||
	    setgid(proc->gid) == -1 || setegid(proc->gid) == -1 ||
	    setuid(proc->uid) == -1 || seteuid(proc->uid) == -1)
		fatal("failed to drop privileges (%s)", errno_s);
}

/*
 * Reap a single process.
 */
void
sanctum_proc_reap(void)
{
	pid_t			pid;
	struct sanctum_proc	*proc;
	int			status;

	for (;;) {
		if ((pid = waitpid(-1, &status, WNOHANG)) == -1) {
			if (errno == ECHILD)
				break;
			if (errno == EINTR)
				continue;
			fatal("waitpid: %s", errno_s);
		}

		if (pid == 0)
			break;

		LIST_FOREACH(proc, &proclist, list) {
			if (proc->pid == pid) {
				syslog(LOG_NOTICE, "%s exited (%d)",
				    proc->name, status);
				LIST_REMOVE(proc, list);
				free(proc);
				break;
			}
		}
	}
}

/*
 * Send the given signal to all running processes.
 */
void
sanctum_proc_killall(int sig)
{
	struct sanctum_proc	*proc;

	LIST_FOREACH(proc, &proclist, list) {
		if (kill(proc->pid, sig) == -1) {
			syslog(LOG_NOTICE, "failed to signal proc %u (%s)\n",
			    proc->type, errno_s);
		}
	}
}

/*
 * Shutdown all processes, they each receive a SIGQUIT signal and are
 * given time to cleanup and exit.
 */
void
sanctum_proc_shutdown(void)
{
	sanctum_proc_killall(SIGQUIT);

	while (!LIST_EMPTY(&proclist))
		sanctum_proc_reap();
}

/*
 * Returns the sanctum_process for the active process.
 * Will return NULL on the parent process.
 */
struct sanctum_proc *
sanctum_process(void)
{
	return (process);
}

/*
 * Set a process title by overwriting the argv[] arguments.
 */
void
sanctum_proc_title(const char *name)
{
	int	len;

	PRECOND(name != NULL);

	proc_argv[1] = NULL;

	if (sanctum->instance[0] != '\0') {
		len = snprintf(proc_argv[0], proc_title_max,
		    "%s [%s]", sanctum->instance, name);
	} else {
		len = snprintf(proc_argv[0], proc_title_max,
		    "sanctum [%s]", name);
	}

	if (len == -1 || (size_t)len >= proc_title_max)
		fatal("proctitle 'sanctum-%s' too large", name);

	memset(proc_argv[0] + len, 0, proc_title_max - len);
}
