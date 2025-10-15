/*
 * Copyright (c) 2023-2025 Joris Vink <joris@sanctorum.se>
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

static void	purgatory_rx_drop_access(void);
static void	purgatory_rx_recv_packets(int);
static int	purgatory_rx_decapsulate(struct sanctum_packet *);
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
	struct pollfd		pfd[2];
	int			sig, running, count;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode != SANCTUM_MODE_PILGRIM);

	io = proc->arg;
	purgatory_rx_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	sanctum_platform_sandbox(proc);
	sanctum_proc_started(proc);

	count = 1;
	running = 1;

	pfd[0].revents = 0;
	pfd[0].events = POLLIN;
	pfd[0].fd = io->crypto;

	if (io->nat != -1) {
		count = 2;
		pfd[1].revents = 0;
		pfd[1].fd = io->nat;
		pfd[1].events = POLLIN;
	}

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (poll(pfd, count, -1) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		if (pfd[0].revents & POLLIN)
			purgatory_rx_recv_packets(io->crypto);

		if (count == 2 && (pfd[1].revents & POLLIN))
			purgatory_rx_recv_packets(io->nat);
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
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->heaven);

	io->tx = NULL;
	io->rx = NULL;
	io->offer = NULL;
	io->bless = NULL;
	io->heaven = NULL;
}

/*
 * Read packets from the purgatory interface and queue them up for
 * processing on either confess, chapel, shrine or cathedral.
 *
 * When the recvfrom() call returns an error we break.
 */
static void
purgatory_rx_recv_packets(int fd)
{
	ssize_t			ret;
	struct sanctum_packet	*pkt;
	u_int8_t		*data;
	u_int16_t		target;
	socklen_t		socklen;
	int			wakeup[SANCTUM_PROC_MAX];

	PRECOND(sanctum->mode != SANCTUM_MODE_PILGRIM);

	wakeup[SANCTUM_PROC_CHAPEL] = 0;
	wakeup[SANCTUM_PROC_SHRINE] = 0;
	wakeup[SANCTUM_PROC_CONFESS] = 0;
	wakeup[SANCTUM_PROC_LITURGY] = 0;
	wakeup[SANCTUM_PROC_CATHEDRAL] = 0;

	for (;;) {
		if ((pkt = sanctum_packet_get()) == NULL)
			pkt = &tpkt;

		socklen = sizeof(pkt->addr);

		if (sanctum->flags & SANCTUM_FLAG_ENCAPSULATE)
			data = sanctum_packet_start(pkt);
		else
			data = sanctum_packet_head(pkt);

		if ((ret = recvfrom(fd, data, SANCTUM_PACKET_DATA_LEN,
		    MSG_DONTWAIT, (struct sockaddr *)&pkt->addr,
		    &socklen)) == -1) {
			if (pkt != &tpkt)
				sanctum_packet_release(pkt);
			if (errno == EINTR)
				break;
			if (errno == EIO)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("read error: %s", errno_s);
		}

		if (pkt == &tpkt)
			continue;

		if (ret == 0) {
			sanctum_packet_release(pkt);
			continue;
		}

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
		case SANCTUM_PROC_LITURGY:
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
			wakeup[target] = 1;
	}

	if (wakeup[SANCTUM_PROC_CHAPEL])
		sanctum_proc_wakeup(SANCTUM_PROC_CHAPEL);

	if (wakeup[SANCTUM_PROC_SHRINE])
		sanctum_proc_wakeup(SANCTUM_PROC_SHRINE);

	if (wakeup[SANCTUM_PROC_CONFESS])
		sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);

	if (wakeup[SANCTUM_PROC_CATHEDRAL])
		sanctum_proc_wakeup(SANCTUM_PROC_CATHEDRAL);

	if (wakeup[SANCTUM_PROC_LITURGY])
		sanctum_proc_wakeup(SANCTUM_PROC_LITURGY);
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
	struct sanctum_proto_hdr	*hdr;
	u_int32_t			seq, spi;
	u_int64_t			pn, last;

	PRECOND(pkt != NULL);

	if (sanctum->flags & SANCTUM_FLAG_ENCAPSULATE) {
		if (purgatory_rx_decapsulate(pkt) == -1)
			return (-1);
	}

	if (sanctum_packet_crypto_checklen(pkt) == -1)
		return (-1);

	/*
	 * In cathedral or liturgy mode we always kick it to
	 * the relevant processes.
	 */
	switch (sanctum->mode) {
	case SANCTUM_MODE_CATHEDRAL:
		pkt->target = SANCTUM_PROC_CATHEDRAL;
		return (0);
	case SANCTUM_MODE_LITURGY:
		if (sanctum_packet_from_cathedral(pkt) == -1)
			return (-1);
		pkt->target = SANCTUM_PROC_LITURGY;
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

	/*
	 * Cathedral responses go to the chapel if we're in tunnel mode
	 * and have a cathedral configured.
	 */
	if (sanctum->mode == SANCTUM_MODE_TUNNEL &&
	    (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE) &&
	    ((spi == (SANCTUM_CATHEDRAL_MAGIC >> 32)) &&
	    (seq == (SANCTUM_CATHEDRAL_MAGIC & 0xffffffff)))) {
		if (sanctum_packet_from_cathedral(pkt) == -1)
			return (-1);
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

/*
 * Remove the encapsulation layer on the outer packet. Note that no integrity
 * is provided or checked at this layer, it is purely for traffic analysis
 * protection.
 *
 * We also don't bother with zeroizing the mask of kdf data structures
 * here as we do not consider them as sensitive.
 */
static int
purgatory_rx_decapsulate(struct sanctum_packet *pkt)
{
	size_t				idx;
	struct nyfe_kmac256		kdf;
	struct sanctum_encap_hdr	*hdr;
	u_int8_t			*data, mask[SANCTUM_ENCAP_MASK_LEN];

	PRECOND(pkt != NULL);
	PRECOND(sanctum->flags & SANCTUM_FLAG_ENCAPSULATE);

	if (pkt->length < sizeof(*hdr))
		return (-1);

	hdr = sanctum_packet_start(pkt);
	data = sanctum_packet_head(pkt);

	nyfe_kmac256_init(&kdf, sanctum->tek, sizeof(sanctum->tek),
	    SANCTUM_ENCAP_LABEL, sizeof(SANCTUM_ENCAP_LABEL) - 1);
	nyfe_kmac256_update(&kdf, hdr, sizeof(*hdr));
	nyfe_kmac256_final(&kdf, mask, sizeof(mask));

	/*
	 * We do not need to check pkt length here before XOR:ing
	 * the mask onto its data. The packet buffer will have
	 * SANCTUM_ENCAP_MASK_LEN bytes available even if no data
	 * was actually read into it.
	 */
	for (idx = 0; idx < sizeof(mask); idx++)
		data[idx] ^= mask[idx];

	pkt->length -= sizeof(*hdr);

	return (0);
}
