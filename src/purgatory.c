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

/* The number of packets in a single run we try to read. */
#define PACKETS_PER_EVENT		64

static void	purgatory_drop_access(void);
static int	purgatory_recv_packets(void);
static void	purgatory_bind_address(void);
static int	purgatory_packet_check(struct sanctum_packet *);
static void	purgatory_send_packet(struct sanctum_packet *);

/* Temporary packet for when the packet pool is empty. */
static struct sanctum_packet	tpkt;

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The purgatory socket. */
static int			fd = -1;

/*
 * The process responsible for receiving packets on the purgatory side
 * and submitting them to confession.
 */
void
sanctum_purgatory(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			suspend, pending, sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	purgatory_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	purgatory_bind_address();

	running = 1;
	suspend = 0;
	sanctum_proc_privsep(proc);

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

#if !defined(SANCTUM_HIGH_PERFORMANCE)
		if (sanctum_ring_pending(io->purgatory))
			suspend = 0;
#endif
		if (sanctum->mode != SANCTUM_MODE_PILGRIM) {
			pending = purgatory_recv_packets() == 1;
			if (pending)
				suspend = 0;
		} else {
			pending = 0;
		}

		if (sanctum->mode != SANCTUM_MODE_SHRINE) {
			if ((pkt = sanctum_ring_dequeue(io->offer)))
				purgatory_send_packet(pkt);
		}

		if (sanctum->mode != SANCTUM_MODE_SHRINE &&
		    sanctum_ring_pending(io->purgatory)) {
			suspend = 0;
			while ((pkt = sanctum_ring_dequeue(io->purgatory)))
				purgatory_send_packet(pkt);
		} else if (pending == 0) {
			if (suspend < 500)
				suspend++;
		}

#if !defined(SANCTUM_HIGH_PERFORMANCE)
		if (sanctum_ring_pending(io->purgatory) == 0 && pending == 0)
			usleep(suspend * 10);
#endif
	}

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
purgatory_drop_access(void)
{
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
 * Setup the purgatory interface by creating a new socket, binding
 * it locally to the specified port and connecting it to the remote peer.
 */
static void
purgatory_bind_address(void)
{
	int	val;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("%s: socket: %s", __func__, errno_s);

	sanctum->local.sin_family = AF_INET;

	if (bind(fd, (struct sockaddr *)&sanctum->local,
	    sizeof(sanctum->local)) == -1)
		fatal("%s: connect: %s", __func__, errno_s);

	if ((val = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("%s: fcntl: %s", __func__, errno_s);

	val |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, val) == -1)
		fatal("%s: fcntl: %s", __func__, errno_s);

#if defined(__linux__)
	val = IP_PMTUDISC_DO;
	if (setsockopt(fd, IPPROTO_IP,
	    IP_MTU_DISCOVER, &val, sizeof(val)) == -1)
		fatal("%s: setsockopt: %s", __func__, errno_s);
#elif !defined(__OpenBSD__)
	val = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val)) == -1)
		fatal("%s: setsockopt: %s", __func__, errno_s);
#endif
}

/*
 * Send the given packet onto the purgatory interface.
 * This function will return the packet to the packet pool.
 */
static void
purgatory_send_packet(struct sanctum_packet *pkt)
{
	ssize_t			ret;
	struct sockaddr_in	peer;
	u_int8_t		*data;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_PURGATORY);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

	peer.sin_family = AF_INET;
	peer.sin_port = sanctum_atomic_read(&sanctum->peer_port);
	peer.sin_addr.s_addr = sanctum_atomic_read(&sanctum->peer_ip);

	if (peer.sin_addr.s_addr == 0) {
		sanctum_packet_release(pkt);
		return;
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
				sanctum_log(LOG_INFO,
				    "network change detected");
				(void)close(fd);
				purgatory_bind_address();
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
				    inet_ntoa(sanctum->peer.sin_addr), errno_s);
				break;
			}
			fatal("sendto: %s", errno_s);
		}
		break;
	}

	sanctum_packet_release(pkt);
}

/*
 * Read up to PACKETS_PER_EVENT number of packets, queueing them up
 * for decryption via the decryption queue.
 */
static int
purgatory_recv_packets(void)
{
	int			idx;
	ssize_t			ret;
	struct sanctum_packet	*pkt;
	u_int8_t		*data;
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

		if (purgatory_packet_check(pkt) == -1) {
			sanctum_packet_release(pkt);
			continue;
		}

		if (pkt->target == SANCTUM_PROC_CONFESS) {
			ret = sanctum_ring_queue(io->confess, pkt);
		} else if (pkt->target == SANCTUM_PROC_CHAPEL) {
			ret = sanctum_ring_queue(io->chapel, pkt);
		} else {
			ret = -1;
		}

		if (ret == -1)
			sanctum_packet_release(pkt);
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
 * For the anti-replay check we only check if the packet falls
 * inside of the anti-replay window here, the rest is up to
 * the decryption process. We need to account for the fact that
 * the decryption worker could have up to 1023 queued packets in
 * worst case scenario.
 */
static int
purgatory_packet_check(struct sanctum_packet *pkt)
{
	struct sanctum_ipsec_hdr	*hdr;
	u_int32_t			seq, spi;
	u_int64_t			pn, last;

	PRECOND(pkt != NULL);

	if (sanctum_packet_crypto_checklen(pkt) == -1)
		return (-1);

	hdr = sanctum_packet_head(pkt);
	spi = be32toh(hdr->esp.spi);
	seq = be32toh(hdr->esp.seq);
	pn = be64toh(hdr->pn);

	if (spi == 0)
		return (-1);

	/* If this has the key offer magic, kick it to the chapel. */
	if ((spi == (SANCTUM_KEY_OFFER_MAGIC >> 32)) &&
	    (seq == (SANCTUM_KEY_OFFER_MAGIC & 0xffffffff))) {
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
