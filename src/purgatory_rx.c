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
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

/* The number of packets in a single run we try to read. */
#define PACKETS_PER_EVENT		64

static void	purgatory_rx_drop_access(void);
static int	purgatory_rx_recv_packets(int);
static int	purgatory_rx_packet_check(struct sanctum_packet *);

/* Temporary packet for when the packet pool is empty. */
static struct sanctum_packet	tpkt;

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/*
 * The process responsible for receiving encrypted packets from purgatory.
 */
void
sanctum_purgatory_rx(struct sanctum_proc *proc)
{
	struct pollfd		pfd;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode != SANCTUM_MODE_PILGRIM);

	io = proc->arg;
	purgatory_rx_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	running = 1;

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);

	pfd.fd = io->crypto;

	pfd.revents = 0;
	pfd.events = POLLIN;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (poll(&pfd, 1, -1) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		purgatory_rx_recv_packets(io->crypto);
	}

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
purgatory_rx_drop_access(void)
{
	(void)close(io->clear);

	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->rx);
	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->heaven);

	io->tx = NULL;
	io->rx = NULL;
	io->bless = NULL;
	io->heaven = NULL;
}

/*
 * Read up to PACKETS_PER_EVENT number of packets, queueing them up
 * for decryption via the decryption queue.
 */
static int
purgatory_rx_recv_packets(int fd)
{
	int			idx;
	ssize_t			ret;
	struct sanctum_packet	*pkt;
	u_int8_t		*data;
	u_int16_t		target;
	socklen_t		socklen;

	PRECOND(sanctum->mode != SANCTUM_MODE_PILGRIM);

	for (idx = 0; idx < PACKETS_PER_EVENT; idx++) {
		if ((pkt = sanctum_packet_get()) == NULL)
			pkt = &tpkt;

		socklen = sizeof(pkt->addr);
		data = sanctum_packet_head(pkt);

		if ((ret = recvfrom(fd, data, SANCTUM_PACKET_DATA_LEN, 0,
		    (struct sockaddr *)&pkt->addr, &socklen)) == -1) {
			if (pkt != &tpkt)
				sanctum_packet_release(pkt);
			if (errno == EINTR)
				continue;
			if (errno == EIO)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("read error: %s", errno_s);
		}

		if (ret == 0)
			fatal("eof on purgatory interface");

		if (pkt == &tpkt)
			continue;

		pkt->length = ret;
		pkt->target = SANCTUM_PROC_CONFESS;

		if (purgatory_rx_packet_check(pkt) == -1) {
			sanctum_packet_release(pkt);
			continue;
		}

		target = pkt->target;

		switch (target) {
		case SANCTUM_PROC_CONFESS:
			ret = sanctum_ring_queue(io->confess, pkt);
			break;
		case SANCTUM_PROC_CHAPEL:
		case SANCTUM_PROC_SHRINE:
		case SANCTUM_PROC_CATHEDRAL:
			ret = sanctum_ring_queue(io->chapel, pkt);
			break;
		default:
			ret = -1;
			break;
		}

		if (ret == -1)
			sanctum_packet_release(pkt);
		else
			sanctum_proc_wakeup(target);
	}

	return (idx == PACKETS_PER_EVENT);
}

/*
 * Perform initial sanity check on the incoming packet, this includes
 * a crude anti-replay check and checking if the SPI is known to the
 * decryption process.
 *
 * If these checks fail we do not move the packet forward to the
 * decryption process and instead it will get dropped.
 *
 * When running as a cathedral we always forward the packet
 * (after some early sanity checking) to the cathedral proc.
 *
 * For the anti-replay check we only check if the packet falls
 * inside of the anti-replay window here, the rest is up to
 * the decryption process. We need to account for the fact that
 * the decryption worker could have up to 1023 queued packets in
 * worst case scenario.
 */
static int
purgatory_rx_packet_check(struct sanctum_packet *pkt)
{
	struct sanctum_ipsec_hdr	*hdr;
	u_int32_t			seq, spi;
	u_int64_t			pn, last;

	PRECOND(pkt != NULL);

	if (sanctum_packet_crypto_checklen(pkt) == -1)
		return (-1);

	/* In cathedral mode, we always kick it to the cathedral. */
	if (sanctum->mode == SANCTUM_MODE_CATHEDRAL) {
		pkt->target = SANCTUM_PROC_CATHEDRAL;
		return (0);
	}

	hdr = sanctum_packet_head(pkt);
	spi = be32toh(hdr->esp.spi);
	seq = be32toh(hdr->esp.seq);
	pn = be64toh(hdr->pn);

	if (spi == 0)
		return (-1);

	/* If this has the key offer magic, kick it to the chapel. */
	if ((spi == (SANCTUM_KEY_OFFER_MAGIC >> 32)) &&
	    (seq == (SANCTUM_KEY_OFFER_MAGIC & 0xffffffff))) {
		if (sanctum->mode == SANCTUM_MODE_SHRINE)
			pkt->target = SANCTUM_PROC_SHRINE;
		else
			pkt->target = SANCTUM_PROC_CHAPEL;
		return (0);
	}

	/* If we don't know the SPI, drop the packet. */
	if (spi != sanctum_atomic_read(&sanctum->rx.spi)) {
		/* If the SPI matches the pending one, skip initial AR check. */
		if (spi == sanctum_atomic_read(&sanctum->rx_pending))
			return (0);
		return (-1);
	}

	if ((pn & 0xffffffff) != seq)
		return (-1);

	last = sanctum_atomic_read(&sanctum->last_pn);

	if (pn > last)
		return (0);

	if (pn > 0 && (SANCTUM_ARWIN_SIZE + 1023) > last - pn)
		return (0);

	sanctum_log(LOG_INFO, "dropped too old packet, seq=0x%" PRIx64, pn);

	return (-1);
}