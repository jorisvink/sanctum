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

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

/* The number of packets in a single run we try to read. */
#define PACKETS_PER_EVENT		64

static void	heaven_drop_access(void);
static void	heaven_recv_packets(int);
static void	heaven_send_packet(int, struct sanctum_packet *);

/* Temporary packet for when the packet pool is empty. */
static struct sanctum_packet	tpkt;

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/*
 * The process responsible for receiving packets on the heaven side
 * and submitting them for blessing.
 */
void
sanctum_heaven(struct sanctum_proc *proc)
{
	struct pollfd			pfd;
	struct sanctum_packet		*pkt;
	int				fd, sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	heaven_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	fd = sanctum_platform_tundev_create();
	pfd.fd = fd;
	pfd.events = POLLIN;

	running = 1;
	sanctum_proc_privsep(proc);

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			syslog(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (poll(&pfd, 1, 0) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		if (pfd.revents & POLLIN)
			heaven_recv_packets(fd);

		while ((pkt = sanctum_ring_dequeue(io->heaven)))
			heaven_send_packet(fd, pkt);

#if !defined(SANCTUM_HIGH_PERFORMANCE)
		usleep(500);
#endif
	}

	close(fd);

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
heaven_drop_access(void)
{
	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->rx);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->confess);
	sanctum_shm_detach(io->purgatory);

	io->tx = NULL;
	io->rx = NULL;
	io->offer = NULL;
	io->chapel = NULL;
	io->confess = NULL;
	io->purgatory = NULL;
}

/*
 * Send the given packet onto the heaven interface.
 * This function will return the packet to the packet pool.
 */
static void
heaven_send_packet(int fd, struct sanctum_packet *pkt)
{
	ssize_t		ret;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_HEAVEN);

	for (;;) {
		if ((ret = sanctum_platform_tundev_write(fd, pkt)) == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EIO)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("%s: write(): %s", __func__, errno_s);
		}

		sanctum_atomic_add(&sanctum->rx.pkt, 1);
		sanctum_atomic_add(&sanctum->rx.bytes, pkt->length);
		sanctum_atomic_write(&sanctum->rx.last, sanctum->uptime);

		break;
	}

	sanctum_packet_release(pkt);
}

/*
 * Read up to PACKETS_PER_EVENT number of packets, queueing them up
 * for encryption via the encryption queue.
 */
static void
heaven_recv_packets(int fd)
{
	int				idx;
	ssize_t				ret;
	struct sanctum_packet		*pkt;

	PRECOND(fd >= 0);

	for (idx = 0; idx < PACKETS_PER_EVENT; idx++) {
		if ((pkt = sanctum_packet_get()) == NULL)
			pkt = &tpkt;

		if ((ret = sanctum_platform_tundev_read(fd, pkt)) == -1) {
			if (pkt != &tpkt)
				sanctum_packet_release(pkt);
			if (errno == EINTR)
				continue;
			if (errno == EIO)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("%s: read(): %s", __func__, errno_s);
		}

		if (ret == 0)
			fatal("eof on tunnel interface");

		if (ret <= SANCTUM_PACKET_MIN_LEN) {
			if (pkt != &tpkt)
				sanctum_packet_release(pkt);
			continue;
		}

		if (pkt == &tpkt)
			continue;

		pkt->length = ret;
		pkt->target = SANCTUM_PROC_BLESS;

		if (sanctum_ring_queue(io->bless, pkt) == -1)
			sanctum_packet_release(pkt);
	}
}
