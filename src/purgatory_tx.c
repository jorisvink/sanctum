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
#include <netinet/in.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

static void	purgatory_tx_drop_access(void);
static void	purgatory_tx_send_packet(int, struct sanctum_packet *);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/*
 * The process responsible for sending encrypted packets into purgatory.
 */
void
sanctum_purgatory_tx(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

	io = proc->arg;
	purgatory_tx_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);

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

		if (sanctum_ring_pending(io->purgatory) == 0)
			sanctum_proc_suspend(-1);

		if (sanctum->mode != SANCTUM_MODE_CATHEDRAL) {
			if ((pkt = sanctum_ring_dequeue(io->offer)))
				purgatory_tx_send_packet(io->crypto, pkt);
		}

		while ((pkt = sanctum_ring_dequeue(io->purgatory)))
			purgatory_tx_send_packet(io->crypto, pkt);
	}

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
	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->chapel);

	io->tx = NULL;
	io->rx = NULL;
	io->bless = NULL;
	io->heaven = NULL;
	io->chapel = NULL;
}

/*
 * Send the given packet onto the purgatory interface.
 * This function will return the packet to the packet pool.
 */
static void
purgatory_tx_send_packet(int fd, struct sanctum_packet *pkt)
{
	ssize_t			ret;
	struct sockaddr_in	peer;
	u_int8_t		*data;

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
		data = sanctum_packet_head(pkt);

		if ((ret = sendto(fd, data, pkt->length, 0,
		    (struct sockaddr *)&peer, sizeof(peer))) == -1) {
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
			fatal("sendto: %s", errno_s);
		}
		break;
	}

	sanctum_packet_release(pkt);
}
