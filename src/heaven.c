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

#include <netinet/in.h>
#include <netinet/ip.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

/* The number of packets in a single run we try to read. */
#define PACKETS_PER_EVENT		64

static void	heaven_drop_access(void);
static int	heaven_recv_packets(int);
static int	heaven_is_sinner(struct sanctum_packet *);
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
	struct sanctum_packet	*pkt;
	int			suspend, pending, fd, sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	heaven_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	fd = sanctum_platform_tundev_create();
	sanctum_config_routes();

	running = 1;
	suspend = 0;

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);

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
		if (sanctum_ring_pending(io->heaven))
			suspend = 0;
#endif

		if (sanctum->mode != SANCTUM_MODE_SHRINE) {
			pending = heaven_recv_packets(fd) == 1;
			if (pending)
				suspend = 0;
		} else {
			pending = 0;
		}

		if (sanctum->mode != SANCTUM_MODE_PILGRIM &&
		    sanctum_ring_pending(io->heaven)) {
			suspend = 0;
			while ((pkt = sanctum_ring_dequeue(io->heaven)))
				heaven_send_packet(fd, pkt);
		} else if (pending == 0) {
			if (suspend < 500)
				suspend++;
		}

#if !defined(SANCTUM_HIGH_PERFORMANCE)
		if (sanctum_ring_pending(io->heaven) == 0 && pending == 0)
			usleep(suspend * 10);
#endif
	}

	close(fd);

	sanctum_log(LOG_NOTICE, "exiting");

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
	PRECOND(sanctum->mode != SANCTUM_MODE_PILGRIM);

	if (heaven_is_sinner(pkt) == -1) {
		sanctum_packet_release(pkt);
		return;
	}

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
static int
heaven_recv_packets(int fd)
{
	int				idx;
	ssize_t				ret;
	struct sanctum_packet		*pkt;

	PRECOND(fd >= 0);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

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

	return (idx == PACKETS_PER_EVENT);
}

/*
 * Check if the packet we are about to send on the heaven interface
 * actually is traffic we expect.
 */
static int
heaven_is_sinner(struct sanctum_packet *pkt)
{
	struct ip	*ip;
	in_addr_t	net, mask;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_HEAVEN);

	if (pkt->length < sizeof(*ip))
		return (-1);

	ip = sanctum_packet_data(pkt);

	if (ip->ip_v != IPVERSION)
		return (-1);

	switch (ip->ip_p) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		break;
	default:
		return (-1);
	}

	mask = sanctum->tun_mask.sin_addr.s_addr;
	net = sanctum->tun_ip.sin_addr.s_addr & mask;

	if ((ip->ip_src.s_addr & mask) != net) {
		if (sanctum_config_routable(ip->ip_src.s_addr) == -1)
			return (-1);
	}

	if ((ip->ip_dst.s_addr & mask) != net) {
		if (sanctum_config_routable(ip->ip_dst.s_addr) == -1)
			return (-1);
	}

	return (0);
}
