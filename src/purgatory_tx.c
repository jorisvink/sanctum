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

/*
 * The number of packets before we reset the outer layer SPI and
 * sequence number values to fake an SA rollover.
 */
#define PURGATORY_ENCAP_PKT_MAX		(1U << 24)

static void	purgatory_tx_drop_access(void);
static void	*purgatory_tx_encapsulate(struct sanctum_packet *);
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

	sanctum_platform_sandbox(proc);

	if (sanctum->flags & SANCTUM_FLAG_ENCAPSULATE) {
		sanctum_random_init();
		sanctum_log(LOG_INFO, "encapsulation active");
	}

	running = 1;
	sanctum_proc_started(proc);

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

		if (sanctum->mode != SANCTUM_MODE_CATHEDRAL &&
		    sanctum->mode != SANCTUM_MODE_LITURGY) {
			while ((pkt = sanctum_ring_dequeue(io->offer)))
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
	sanctum_shm_detach(io->bishop);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->chapel);

	io->tx = NULL;
	io->rx = NULL;
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
purgatory_tx_send_packet(int fd, struct sanctum_packet *pkt)
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
		data = purgatory_tx_encapsulate(pkt);

		if (sendto(fd, data, pkt->length, 0,
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
 * If required, encapsulate the encrypted packet its sanctum protocol header
 * with an outer ESP layer that cannot be differentiated from any other
 * IPSec implementation following RFC 4106.
 *
 * Note that no integrity is provided or checked at this layer, it is purely
 * for traffic analysis protection.
 *
 * We also don't bother with zeroizing the mask of kdf data structures
 * here as we do not consider them as sensitive.
 */
static void *
purgatory_tx_encapsulate(struct sanctum_packet *pkt)
{
	struct nyfe_kmac256		kdf;
	struct sanctum_encap_hdr	*hdr;
	size_t				idx, total;
	u_int8_t			*data, mask[SANCTUM_ENCAP_MASK_LEN];

	PRECOND(pkt != NULL);

	if (!(sanctum->flags & SANCTUM_FLAG_ENCAPSULATE))
		return (sanctum_packet_head(pkt));

	total = sizeof(*hdr) + pkt->length;
	VERIFY(total > pkt->length && total < SANCTUM_PACKET_MAX_LEN);

	hdr = sanctum_packet_start(pkt);
	data = sanctum_packet_head(pkt);

	sanctum_random_bytes(hdr->seed, sizeof(hdr->seed));

	nyfe_kmac256_init(&kdf, sanctum->tek, sizeof(sanctum->tek),
	    SANCTUM_ENCAP_LABEL, sizeof(SANCTUM_ENCAP_LABEL) - 1);
	nyfe_kmac256_update(&kdf, hdr, sizeof(*hdr));
	nyfe_kmac256_final(&kdf, mask, sizeof(mask));

	/*
	 * We do not need to check pkt length here before XOR:ing
	 * the mask onto its data. The packet buffer will have
	 * SANCTUM_ENCAP_MASK_LEN bytes available even if no data
	 * was actually written into it.
	 */
	for (idx = 0; idx < sizeof(mask); idx++)
		data[idx] ^= mask[idx];

	pkt->length += sizeof(*hdr);

	return (hdr);
}
