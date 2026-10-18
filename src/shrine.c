/*
 * Copyright (c) 2023-2026 Joris Vink <joris@sanctorum.se>
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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "sanctum.h"
#include "libnyfe.h"

/* The half-time window in which offers are valid. */
#define SHRINE_OFFER_VALID		150

/* The key state we save for our shrine. */
struct relic {
	u_int32_t	spi;
	u_int64_t	timestamp;
	u_int8_t	reserved[20];
} __attribute__((packed));

static void	shrine_relic_load(void);
static int	shrine_relic_save(struct relic *);

static void	shrine_drop_access(void);
static void	shrine_offer_decrypt(struct sanctum_packet *, u_int64_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* Last received verified offer its SPI and timestamp. */
static struct relic		last_relic;

/*
 * Shrine - A keying process that only receives offers from a pilgrim.
 * This process is used when the sanctum mode is set to "shrine".
 *
 * In this mode, sanctum is only capable of receiving data and will
 * thus only attempt to verify and decrypt key offers and install
 * them as its RX keys.
 */
void
sanctum_shrine(struct sanctum_proc *proc)
{
	u_int64_t		now;
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	sanctum_random_init();

	io = proc->arg;
	shrine_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	shrine_relic_load();
	sanctum_platform_sandbox(proc);
	sanctum_proc_started(proc);

	running = 1;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		sanctum_proc_suspend(-1);
		now = sanctum_atomic_read(&shared->uptime);

		while ((pkt = sanctum_packet_dequeue(io->chapel)) != NULL) {
			shrine_offer_decrypt(pkt, now);
			sanctum_packet_release(pkt);
		}
	}

	sanctum_config_release();
	sanctum_log(LOG_NOTICE, "exiting");

	nyfe_zeroize_warn();
	nyfe_zeroize_all();

	exit(0);
}

/*
 * Drop access to queues that shrine does not need.
 */
static void
shrine_drop_access(void)
{
	(void)close(io->nat);
	(void)close(io->clear);
	(void)close(io->crypto);

	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->confess);
	sanctum_shm_detach(io->purgatory);

	io->bless = NULL;
	io->heaven = NULL;
	io->confess = NULL;
	io->purgatory = NULL;
}

/*
 * Attempt to verify the given offer in pkt.
 *
 * If we can verify that it was sent by the peer and it is not
 * too old then we will install it as the RX key for it.
 */
static void
shrine_offer_decrypt(struct sanctum_packet *pkt, u_int64_t now)
{
	struct sanctum_offer		*op;
	struct relic			relic;
	struct sanctum_key		cipher;

	PRECOND(pkt != NULL);
	PRECOND(io != NULL);

	if (pkt->length != sizeof(*op))
		return;

	op = sanctum_packet_head(pkt);
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (sanctum_offer_kdf(sanctum->secret,
	    SANCTUM_SHRINE_PILGRIM_DERIVE_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed), 0, 0) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	if (sanctum_offer_decrypt(&cipher, op, SHRINE_OFFER_VALID) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	nyfe_zeroize(&cipher, sizeof(cipher));
	if (op->data.type != SANCTUM_OFFER_TYPE_KEY)
		return;

	op->hdr.spi = be32toh(op->hdr.spi);
	op->data.timestamp = be64toh(op->data.timestamp);

	if (op->hdr.spi == 0 || op->hdr.spi == last_relic.spi)
		return;

	if (op->data.timestamp <= last_relic.timestamp) {
		sanctum_log(LOG_NOTICE,
		    "old key exchange seen, someone replaying?");
		return;
	}

	memset(&relic, 0, sizeof(relic));
	relic.spi = op->hdr.spi;
	relic.timestamp = op->data.timestamp;

	if (shrine_relic_save(&relic) == -1) {
		sanctum_log(LOG_NOTICE,
		    "failed to save shrine relic, new key not accepted");
		return;
	}

	sanctum_peer_update(pkt->addr.sin_addr.s_addr, pkt->addr.sin_port);

	sanctum_offer_install(io->rx, op);
	sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);

	nyfe_memcpy(&last_relic, &relic, sizeof(relic));
}

/*
 * Load our latest relic from disk (if we have any).
 */
static void
shrine_relic_load(void)
{
	int			fd;
	struct timespec		ts;
	struct relic		relic;

	if ((fd = sanctum_file_open(sanctum->shrine_relic, NULL)) == -1) {
		if (errno != ENOENT) {
			fatal("failed to open '%s': %s",
			    sanctum->shrine_relic, errno_s);
		}
		return;
	}

	if (nyfe_file_read(fd, &relic, sizeof(relic)) != sizeof(relic))
		fatal("shrine relic is malformed, please remove it");

	(void)close(fd);

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	if (relic.timestamp > (u_int64_t)ts.tv_sec)
		sanctum_log(LOG_NOTICE, "shrine relic timestamp is ahead");

	nyfe_memcpy(&last_relic, &relic, sizeof(relic));

	sanctum_log(LOG_INFO, "shrine relic loaded");
}

/*
 * Save our latest relic to disk.
 */
static int
shrine_relic_save(struct relic *relic)
{
	int		fd, len;
	char		path[1024];

	PRECOND(relic != NULL);

	len = snprintf(path, sizeof(path), "%s.new", sanctum->shrine_relic);
	if (len < 0 || (size_t)len >= sizeof(path))
		fatal("failed to create tmp shrine relic path");

	if (unlink(path) == -1 && errno != ENOENT) {
		sanctum_log(LOG_NOTICE,
		    "failed to remove tmp file %s (%s)", path, errno_s);
		return (-1);
	}

	if ((fd = open(path,
	    O_CREAT | O_TRUNC | O_WRONLY | O_EXCL, 0400)) == -1) {
		sanctum_log(LOG_NOTICE,
		    "failed to open '%s': %s", path, errno_s);
		return (-1);
	}

	nyfe_file_write(fd, relic, sizeof(*relic));

	if (close(fd) == -1) {
		sanctum_log(LOG_NOTICE,
		    "failed to close '%s': %s", path, errno_s);
		(void)unlink(path);
		return (-1);
	}

	if (rename(path, sanctum->shrine_relic) == -1) {
		sanctum_log(LOG_NOTICE,
		    "failed to rename shrine relic: %s", errno_s);
		(void)unlink(path);
		return (-1);
	}

	sanctum_log(LOG_INFO, "shrine relic saved");

	return (0);
}
