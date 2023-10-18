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
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "sanctum.h"

/*
 * Log a message to either stdout or sanctum_log, prio is sanctum_log level.
 */
void
sanctum_log(int prio, const char *fmt, ...)
{
	va_list		args;

	PRECOND(prio >= 0);
	PRECOND(fmt != NULL);

	va_start(args, fmt);
	sanctum_logv(prio, fmt, args);
	va_end(args);
}

/*
 * Log a message to either stdout or sanctum_log, prio is sanctum_log level.
 */
void
sanctum_logv(int prio, const char *fmt, va_list args)
{
	struct timespec		ts;
	struct tm		*t;
	struct sanctum_proc	*proc;
	char			tbuf[32];

	PRECOND(prio >= 0);
	PRECOND(fmt != NULL);

	if (sanctum->flags & SANCTUM_FLAG_DAEMONIZED) {
		vsyslog(prio, fmt, args);
	} else {
		(void)clock_gettime(CLOCK_REALTIME, &ts);
		t = gmtime(&ts.tv_sec);

		if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", t) > 0)
			printf("%s.%03ld UTC ", tbuf, ts.tv_nsec / 1000000);

		if ((proc = sanctum_process()) != NULL)
			printf("[%s]: ", proc->name);
		else
			printf("[guardian]: ");

		vprintf(fmt, args);
		printf("\n");
		fflush(stdout);
	}
}

/*
 * Update the address of the peer if it does not match with the
 * one from the packet.
 *
 * This MUST ONLY be called AFTER integrity has been verified.
 */
void
sanctum_peer_update(struct sanctum_packet *pkt)
{
	PRECOND(pkt != NULL);

	if (pkt->addr.sin_addr.s_addr != sanctum->peer_ip ||
	    pkt->addr.sin_port != sanctum->peer_port) {
		sanctum_log(LOG_NOTICE, "peer address change (new=%s:%u)",
		    inet_ntoa(pkt->addr.sin_addr), ntohs(pkt->addr.sin_port));

		sanctum_atomic_write(&sanctum->peer_ip,
		    pkt->addr.sin_addr.s_addr);
		sanctum_atomic_write(&sanctum->peer_port, pkt->addr.sin_port);
	}
}

/*
 * Erase the given sa if the key says it was erased.
 */
int
sanctum_key_erase(const char *s, struct sanctum_key *key, struct sanctum_sa *sa)
{
	int		ret;

	PRECOND(s != NULL);
	PRECOND(key != NULL);
	PRECOND(sa != NULL);

	if (!sanctum_atomic_cas_simple(&key->state,
	    SANCTUM_KEY_ERASE, SANCTUM_KEY_INSTALLING))
		return (-1);

	if (sa->spi == key->spi) {
		if (sa->cipher != NULL)
			sanctum_cipher_cleanup(sa->cipher);
		sanctum_mem_zero(sa, sizeof(*sa));

		sanctum_log(LOG_NOTICE,
		    "%s SA erased (spi=0x%08x)", s, key->spi);

		ret = 0;
		if (!sanctum_atomic_cas_simple(&key->state,
		    SANCTUM_KEY_INSTALLING, SANCTUM_KEY_EMPTY))
			fatal("failed to swap key state to empty");
	} else {
		ret = -1;
		if (!sanctum_atomic_cas_simple(&key->state,
		    SANCTUM_KEY_INSTALLING, SANCTUM_KEY_ERASE))
			fatal("failed to swap key state to erasing");
	}

	return (ret);
}

/*
 * Install the key pending under the given `key` data structure into
 * the SA context `sa`.
 */
int
sanctum_key_install(struct sanctum_key *key, struct sanctum_sa *sa)
{
	PRECOND(key != NULL);
	PRECOND(sa != NULL);

	if (sanctum_atomic_read(&key->state) != SANCTUM_KEY_PENDING)
		return (-1);

	if (!sanctum_atomic_cas_simple(&key->state,
	    SANCTUM_KEY_PENDING, SANCTUM_KEY_INSTALLING))
		fatal("failed to swap key state to installing");

	if (sa->cipher != NULL)
		sanctum_cipher_cleanup(sa->cipher);

	sa->cipher = sanctum_cipher_setup(key);
	sanctum_mem_zero(key->key, sizeof(key->key));

	sa->seqnr = 1;
	sa->pending = 1;
	sa->spi = sanctum_atomic_read(&key->spi);
	sa->salt = sanctum_atomic_read(&key->salt);
	sa->age = sanctum_atomic_read(&sanctum->uptime);

	if (!sanctum_atomic_cas_simple(&key->state,
	    SANCTUM_KEY_INSTALLING, SANCTUM_KEY_EMPTY))
		fatal("failed to swap key state to empty");

	return (0);
}

/*
 * Clear the entire given SA state, wiping its internal keys etc.
 */
void
sanctum_sa_clear(struct sanctum_sa *sa)
{
	PRECOND(sa != NULL);

	if (sa->cipher != NULL)
		sanctum_cipher_cleanup(sa->cipher);

	sanctum_mem_zero(sa, sizeof(*sa));
}

/*
 * Reset interface statistics for the given struct.
 */
void
sanctum_stat_clear(struct sanctum_ifstat *ifc)
{
	PRECOND(ifc != NULL);

	sanctum_atomic_write(&ifc->age, 0);
	sanctum_atomic_write(&ifc->spi, 0);
	sanctum_atomic_write(&ifc->pkt, 0);
	sanctum_atomic_write(&ifc->bytes, 0);
}

/*
 * Create a new UNIX socket at the given path, owned by the supplied
 * uid and gid and with 0700 permissions.
 */
int
sanctum_unix_socket(struct sanctum_sun *cfg)
{
	struct sockaddr_un	sun;
	int			fd, len, flags;

	PRECOND(cfg != NULL);

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	len = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", cfg->path);
	if (len == -1 || (size_t)len >= sizeof(sun.sun_path))
		fatal("path '%s' didnt fit into sun.sun_path", cfg->path);

	if (unlink(sun.sun_path) == -1 && errno != ENOENT)
		fatal("unlink(%s): %s", sun.sun_path, errno_s);

	if (bind(fd, (const struct sockaddr *)&sun, sizeof(sun)) == -1)
		fatal("bind(%s): %s", sun.sun_path, errno_s);

	if (chown(sun.sun_path, cfg->uid, cfg->gid) == -1)
		fatal("chown(%s): %s", sun.sun_path, errno_s);

	if (chmod(sun.sun_path, S_IRWXU) == -1)
		fatal("chmod(%s): %s", sun.sun_path, errno_s);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	return (fd);
}

/*
 * Allocate a shared memory segment with the given len as its size.
 * If key is not NULL, the shm key is written to it.
 *
 * The shared memory segment is attached automatically after allocation
 * and returned to the caller.
 *
 * Before returning the segment to the caller, it is marked for deletion
 * so that once the process exits the shared memory goes away.
 */
void *
sanctum_alloc_shared(size_t len, int *key)
{
	int		tmp;
	void		*ptr;

	tmp = shmget(IPC_PRIVATE, len, IPC_CREAT | IPC_EXCL | 0700);
	if (tmp == -1)
		fatal("%s: shmget: %s", __func__, errno_s);

	if ((ptr = shmat(tmp, NULL, 0)) == (void *)-1)
		fatal("%s: shmat: %s", __func__, errno_s);

	if (shmctl(tmp, IPC_RMID, NULL) == -1)
		fatal("%s: shmctl: %s", __func__, errno_s);

	if (key != NULL)
		*key = tmp;

	return (ptr);
}

/*
 * Detach from a shared memory segment.
 */
void
sanctum_shm_detach(void *ptr)
{
	PRECOND(ptr != NULL);

	if (shmdt(ptr) == -1)
		fatal("failed to detach from 0x%p (%s)", ptr, errno_s);
}

/*
 * Poor mans memset() that isn't optimized away on the platforms I use it on.
 *
 * If you build this on something and don't test that it actually clears the
 * contents of the data, thats on you. You probably want to do some binary
 * verification.
 */
void
sanctum_mem_zero(void *ptr, size_t len)
{
	volatile char	*p;

	PRECOND(ptr != NULL);
	PRECOND(len > 0);

	p = (volatile char *)ptr;

	while (len-- > 0)
		*(p)++ = 0x00;
}

/*
 * Helper to parse an IPv4 address into a struct sockaddr_in its sin_addr.
 */
void
sanctum_inet_addr(void *saddr, const char *ip)
{
	struct sockaddr_in	*sin;

	PRECOND(saddr != NULL);
	PRECOND(ip != NULL);

	sin = saddr;
	sin->sin_family = AF_INET;

#if !defined(__linux__)
	sin->sin_len = sizeof(*sin);
#endif

	if (inet_pton(AF_INET, ip, &sin->sin_addr) == -1)
		fatal("'%s' not a valid IPv4 address", ip);
}

