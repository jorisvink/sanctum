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
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

/* The amount of seconds until we regenerate our shroud identity. */
#define PURGATORY_SHROUD_NEXT		300

static void	purgatory_tx_shroud_regen(void);
static void	*purgatory_tx_shroud(struct sanctum_packet *,
		    struct sockaddr_in *);

static void	purgatory_tx_drop_access(void);
static void	purgatory_tx_send_packet(struct sanctum_packet *);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The local copy of the peer shroud key. */
static struct sanctum_shroud	shroud_peer;

/* The next time we generate a new shroud id seed. */
static u_int64_t		shroud_next = 0;

/* The cathedral shroud key (if a cathedral is in use). */
static u_int8_t			shroud_cathedral[SANCTUM_KEY_LENGTH];

/* The current shroud seed and identity (for when sending to a cathedral). */
static u_int8_t			shroud_seed[SANCTUM_SHROUD_SEED_LENGTH];
static u_int8_t			shroud_identity[SANCTUM_SHROUD_ID_LENGTH];

/*
 * The process responsible for sending encrypted packets into purgatory.
 */
void
sanctum_purgatory_tx(struct sanctum_proc *proc)
{
	u_int64_t		now;
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

	io = proc->arg;
	purgatory_tx_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	if (sanctum->mode != SANCTUM_MODE_CATHEDRAL &&
	    (sanctum->flags & SANCTUM_FLAG_SHROUD) &&
	    (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE)) {
		sanctum_shroud_key(sanctum->cathedral_secret,
		    SANCTUM_KDF_PURPOSE_SHROUD_CATHEDRAL,
		    shroud_cathedral, sizeof(shroud_cathedral));
	}

	sanctum_platform_sandbox(proc);

	running = 1;
	sanctum_proc_started(proc);
	nyfe_zeroize_register(&shroud_peer, sizeof(shroud_peer));

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (sanctum_ring_pending(io->purgatory) == 0)
			sanctum_proc_suspend(-1);

		/*
		 * XXX - we should consider rotating the shroud id
		 * if we can figure out we changed networks etc so
		 * the user doesn't have to follow opsec as tightly.
		 */
		now = sanctum_atomic_read(&sanctum->uptime);
		if (now >= shroud_next) {
			purgatory_tx_shroud_regen();
			shroud_next = now + PURGATORY_SHROUD_NEXT;
		}

		if (sanctum->mode != SANCTUM_MODE_CATHEDRAL &&
		    (sanctum->flags & SANCTUM_FLAG_SHROUD)) {
			if (sanctum_shroud_copy(io->stx, &shroud_peer) != -1) {
				sanctum_log(LOG_INFO,
				    "new shroud key installed");
			}
		}

		if (sanctum->mode != SANCTUM_MODE_CATHEDRAL &&
		    sanctum->mode != SANCTUM_MODE_LITURGY) {
			while ((pkt = sanctum_ring_dequeue(io->offer)))
				purgatory_tx_send_packet(pkt);
		}

		while ((pkt = sanctum_ring_dequeue(io->purgatory)))
			purgatory_tx_send_packet(pkt);
	}

	nyfe_zeroize(&shroud_peer, sizeof(shroud_peer));

	sanctum_config_release();
	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
purgatory_tx_drop_access(void)
{
	(void)close(io->clear);

	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->rx);
	sanctum_shm_detach(io->srx);
	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->bishop);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->chapel);

	io->tx = NULL;
	io->rx = NULL;
	io->srx = NULL;
	io->bless = NULL;
	io->bishop = NULL;
	io->heaven = NULL;
	io->chapel = NULL;
}

/*
 * Send the given packet onto the purgatory interface.
 * This function will return the packet to the packet pool.
 */
static void
purgatory_tx_send_packet(struct sanctum_packet *pkt)
{
	struct sockaddr_in	peer;
	void			*data;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_PURGATORY_TX);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

	if (pkt->addr.sin_family == 0) {
		peer.sin_family = AF_INET;
		peer.sin_port = sanctum_atomic_read(&sanctum->peer_port);
		peer.sin_addr.s_addr = sanctum_atomic_read(&sanctum->peer_ip);

		if (peer.sin_addr.s_addr == 0) {
			sanctum_packet_release(pkt);
			return;
		}
	} else {
		memcpy(&peer, &pkt->addr, sizeof(pkt->addr));
	}

	for (;;) {
		if ((data = purgatory_tx_shroud(pkt, &peer)) == NULL)
			break;

		if (sendto(io->crypto, data, pkt->length, 0,
		    (struct sockaddr *)&peer, sizeof(peer)) == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (errno == EADDRNOTAVAIL) {
				/*
				 * XXX - we should act on this like we did
				 * in earlier sanctum variants.
				 */
				sanctum_log(LOG_INFO,
				    "network change detected");
				break;
			}
			if (errno == EMSGSIZE) {
				sanctum_log(LOG_INFO,
				    "packet (size=%zu) too large, "
				    "lower tunnel MTU", pkt->length);
				break;
			}
			if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
				sanctum_log(LOG_INFO,
				    "host %s unreachable (%s)",
				    inet_ntoa(peer.sin_addr), errno_s);
				break;
			}
			if (errno == ENETDOWN) {
				sanctum_log(LOG_INFO, "network is down");
				break;
			}
			if (errno == ENOBUFS) {
				sanctum_log(LOG_NOTICE, "sendto: %s", errno_s);
				break;
			}
			fatal("sendto: %s", errno_s);
		}
		break;
	}

	sanctum_packet_release(pkt);
}

/*
 * If required and applicable, shroud the packet and return a pointer to
 * where the shrouded data starts. If we are sending to the cathedral
 * we will attach our shroud id and current shroud seed, otherwise
 * we just randomize them.
 *
 * If we are a cathedral and shrouding is enabled we already have the
 * shroud applied and thus do nothing more.
 *
 * If we should shroud and we do not have a shroud key installed we
 * return NULL and the packet is not sent.
 */
static void *
purgatory_tx_shroud(struct sanctum_packet *pkt, struct sockaddr_in *peer)
{
	u_int8_t	id[SANCTUM_SHROUD_ID_LENGTH];
	u_int8_t	seed[SANCTUM_SHROUD_SEED_LENGTH];

	PRECOND(pkt != NULL);
	PRECOND(peer != NULL);

	if (!(sanctum->flags & SANCTUM_FLAG_SHROUD))
		return (sanctum_packet_head(pkt));

	if (sanctum->mode == SANCTUM_MODE_CATHEDRAL)
		return (sanctum_packet_start(pkt));

	if ((sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE) &&
	    peer->sin_addr.s_addr == sanctum->cathedral.sin_addr.s_addr) {
		sanctum_packet_shroud(pkt, shroud_identity,
		    sizeof(shroud_identity), shroud_seed, sizeof(shroud_seed),
		    shroud_cathedral, sizeof(shroud_cathedral));
	} else {
		if (shroud_peer.valid == 0) {
			sanctum_log(LOG_NOTICE,
			    "no valid shroud for peer, dropping packet");
			return (NULL);
		}

		sanctum_random_bytes(id, sizeof(id));
		sanctum_random_bytes(seed, sizeof(seed));
		sanctum_packet_shroud(pkt, id, sizeof(id), seed, sizeof(seed),
		    shroud_peer.key, sizeof(shroud_peer.key));
	}

	return (sanctum_packet_start(pkt));
}

/*
 * Regenerate our shroud ID and seed periodically.
 */
static void
purgatory_tx_shroud_regen(void)
{
	u_int8_t	base[SANCTUM_SHROUD_ID_LENGTH];

	if (!(sanctum->flags & SANCTUM_FLAG_SHROUD))
		return;

	if (sanctum->mode == SANCTUM_MODE_CATHEDRAL)
		return;

	sanctum_random_init();

	nyfe_zeroize_register(base, sizeof(base));
	sanctum_random_bytes(shroud_seed, sizeof(shroud_seed));

	sanctum_shroud_identity_base(sanctum->cathedral_flock,
	    sanctum->cathedral_flock_dst, sanctum->cathedral_id,
	    base, sizeof(base));

	sanctum_shroud_identity(base, sizeof(base), shroud_seed,
	    sizeof(shroud_seed), shroud_identity, sizeof(shroud_identity));

	nyfe_zeroize(base, sizeof(base));
}
