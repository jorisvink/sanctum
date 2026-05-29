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

#include <netinet/in.h>
#include <netinet/ip.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

static void	heaven_rx_drop_access(void);
static void	heaven_rx_recv_packets(int);
static void	heaven_rx_grace_generate(void);

/* Temporary packet for when the packet pool is empty. */
static struct sanctum_packet	tpkt;

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* If we should wakeup SANCTUM_PROC_BLESS. */
static int		bless_wakeup = 0;

/* Local timekeeping for graces. */
static u_int64_t	now = 0;
static u_int64_t	grace_next = 0;
static u_int64_t	grace_reset = 0;
static u_int64_t	grace_interval = SANCTUM_GRACE_INTERVAL;

/*
 * The process responsible for receiving packets on the heaven side
 * and enqueuing them for encryption via bless.
 *
 * We also generate grace traffic from here when required.
 */
void
sanctum_heaven_rx(struct sanctum_proc *proc)
{
	struct pollfd		pfd;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

	io = proc->arg;
	heaven_rx_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	sanctum_config_routes();
	sanctum_platform_sandbox(proc);
	sanctum_proc_started(proc);

	pfd.revents = 0;
	pfd.fd = io->clear;
	pfd.events = POLLIN;

	running = 1;
	now = sanctum_atomic_read(&sanctum->uptime);
	grace_next = now + grace_interval;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		now = sanctum_atomic_read(&sanctum->uptime);

		if (poll(&pfd, 1, grace_next - now) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		now = sanctum_atomic_read(&sanctum->uptime);

		if (sanctum_atomic_cas_simple(&sanctum->holepunch, 1, 0)) {
			grace_next = now;
			grace_interval = 1;
			grace_reset = now + SANCTUM_GRACE_INTERVAL;
		} else if (grace_reset != 0 && now >= grace_reset) {
			grace_reset = 0;
			grace_interval = SANCTUM_GRACE_INTERVAL;
		}

		if (grace_next != 0 && now >= grace_next)
			heaven_rx_grace_generate();

		heaven_rx_recv_packets(io->clear);

		if (bless_wakeup) {
			bless_wakeup = 0;
			sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
		}
	}

	sanctum_config_release();
	sanctum_log(LOG_NOTICE, "exiting");

	nyfe_zeroize_warn();
	nyfe_zeroize_all();

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
heaven_rx_drop_access(void)
{
	(void)close(io->nat);
	(void)close(io->crypto);

	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->rx);
	sanctum_shm_detach(io->stx);
	sanctum_shm_detach(io->srx);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->confess);
	sanctum_shm_detach(io->purgatory);

	io->tx = NULL;
	io->rx = NULL;
	io->stx = NULL;
	io->srx = NULL;
	io->offer = NULL;
	io->chapel = NULL;
	io->confess = NULL;
	io->purgatory = NULL;
}

/*
 * Read packets from the clear interface and queue them up for encryption
 * via the bless process. Once the read() returns an error we break.
 */
static void
heaven_rx_recv_packets(int fd)
{
	ssize_t				ret;
	struct sanctum_packet		*pkt;

	PRECOND(fd >= 0);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

	for (;;) {
		if ((pkt = sanctum_packet_get()) == NULL)
			pkt = &tpkt;

		if ((ret = sanctum_platform_tundev_read(fd, pkt)) == -1) {
			if (pkt != &tpkt)
				sanctum_packet_release(pkt);
			if (errno == EINTR)
				break;
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
		pkt->type = SANCTUM_PACKET_IP;
		pkt->target = SANCTUM_PROC_BLESS;

		if (sanctum_ring_queue(io->bless, pkt) == -1)
			sanctum_packet_release(pkt);
		else
			bless_wakeup = 1;
	}
}

/*
 * Generate a grace packet that is to be sent to our peer.
 * This ends up on the receiving side its heaven-tx process.
 */
static void
heaven_rx_grace_generate(void)
{
	struct sanctum_packet		*pkt;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	pkt->length = 0;
	pkt->target = SANCTUM_PROC_BLESS;
	pkt->next = SANCTUM_PACKET_GRACE;

	if (sanctum_ring_queue(io->bless, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		bless_wakeup = 1;

	grace_next = now + grace_interval;
}
